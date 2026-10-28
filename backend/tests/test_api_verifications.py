"""Creating and checking ownership challenges through the API, against the test database."""

import string
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.models import OwnershipVerification
from app.verification import http_token, service
from app.verification.outcome import Outcome


@pytest.fixture
def lab_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "lab_mode", True)


def make_target(
    client: TestClient, target_type: str = "url", value: str = "http://juice-shop:3000"
) -> str:
    body = {"name": "t", "target_type": target_type, "value": value, "data_types": ["general"]}
    response = client.post("/targets", json=body)
    assert response.status_code == 201, response.text
    target_id: str = response.json()["id"]
    return target_id


def challenge(client: TestClient, target_id: str, method: str) -> Any:
    return client.post(f"/targets/{target_id}/verifications", json={"method": method})


def check(client: TestClient, target_id: str, verification_id: str) -> Any:
    return client.post(f"/targets/{target_id}/verifications/{verification_id}/check")


# --- creating challenges ---------------------------------------------------------------------


def test_challenge_has_a_random_expiring_token(client: TestClient) -> None:
    target_id = make_target(client, "domain", "example.com")

    first = challenge(client, target_id, "dns_txt")
    second = challenge(client, target_id, "dns_txt")

    assert first.status_code == 201
    body = first.json()
    assert body["status"] == "pending"
    assert body["verified_at"] is None and body["used_at"] is None
    # secrets.token_urlsafe(32): 43 URL-safe characters, different every time.
    assert len(body["token"]) == 43
    assert set(body["token"]) <= set(string.ascii_letters + string.digits + "-_")
    assert body["token"] != second.json()["token"]
    expires = datetime.fromisoformat(body["expires_at"])
    assert timedelta(hours=23, minutes=59) < expires - datetime.now(UTC) <= timedelta(hours=24)
    assert body["instructions"] == (
        f"Create a DNS TXT record named _vulnscope.example.com with the value {body['token']}, "
        "then call the check endpoint. It can take a few minutes to propagate."
    )


def test_http_challenge_says_where_to_serve_the_token(client: TestClient) -> None:
    target_id = make_target(client, "url", "https://shop.example.com:8443/app")

    body = challenge(client, target_id, "http_token").json()

    assert "https://shop.example.com:8443/.well-known/vulnscope-verify.txt" in body["instructions"]


@pytest.mark.parametrize(
    ("target_type", "value", "method"),
    [
        ("ip", "203.0.113.7", "dns_txt"),  # DNS needs a name
        ("url", "http://203.0.113.7", "dns_txt"),
        ("ip", "203.0.113.7", "lab"),
        ("repo", "https://github.com/acme/app", "http_token"),  # nothing to check yet
        ("repo", "https://github.com/acme/app", "dns_txt"),
    ],
)
def test_methods_that_cannot_prove_a_target_are_rejected(
    client: TestClient, lab_mode: None, target_type: str, value: str, method: str
) -> None:
    target_id = make_target(client, target_type, value)

    assert challenge(client, target_id, method).status_code == 422


@pytest.mark.parametrize(
    "value", ["http://juice-shop.evil.com", "http://my-juice-shop", "https://dvwa.example.com"]
)
def test_lab_challenge_needs_an_exact_lab_hostname(
    client: TestClient, lab_mode: None, value: str
) -> None:
    response = challenge(client, make_target(client, "url", value), "lab")

    assert response.status_code == 422
    assert "not a lab target" in response.json()["detail"]


def test_lab_challenge_is_forbidden_when_lab_mode_is_off(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "lab_mode", False)

    response = challenge(client, make_target(client), "lab")

    assert response.status_code == 403
    assert "LAB_MODE=false" in response.json()["detail"]


def test_challenge_for_unknown_target_is_404(client: TestClient) -> None:
    assert challenge(client, str(uuid.uuid4()), "dns_txt").status_code == 404


# --- checking challenges ---------------------------------------------------------------------


def test_lab_check_verifies_juice_shop(client: TestClient, lab_mode: None) -> None:
    target_id = make_target(client)
    created = challenge(client, target_id, "lab").json()

    response = check(client, target_id, created["id"])

    assert response.status_code == 200
    assert response.json()["status"] == "verified"
    assert response.json()["verified_at"] is not None


def test_failed_check_stays_pending_and_can_be_retried(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_id = make_target(client, "domain", "example.com")
    created = challenge(client, target_id, "http_token").json()
    answers = iter([Outcome.fail("https://example.com/... answered HTTP 404"), Outcome.ok("ok")])
    urls: list[str] = []

    def fake_check(url: str, token: str) -> Outcome:
        urls.append(url)
        assert token == created["token"]
        return next(answers)

    monkeypatch.setattr(http_token, "check", fake_check)

    first = check(client, target_id, created["id"])
    assert first.status_code == 409
    assert "HTTP 404" in first.json()["detail"]

    second = check(client, target_id, created["id"])
    assert second.status_code == 200
    assert second.json()["status"] == "verified"
    assert urls == ["https://example.com/.well-known/vulnscope-verify.txt"] * 2


def test_expired_challenge_is_marked_expired(
    client: TestClient, session_factory: sessionmaker[Session]
) -> None:
    target_id = make_target(client, "domain", "example.com")
    created = challenge(client, target_id, "dns_txt").json()
    with session_factory() as db:
        verification = db.get(OwnershipVerification, uuid.UUID(created["id"]))
        assert verification is not None
        verification.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()

    response = check(client, target_id, created["id"])

    assert response.status_code == 409
    assert "expired" in response.json()["detail"]
    with session_factory() as db:
        stored = db.get(OwnershipVerification, uuid.UUID(created["id"]))
        assert stored is not None and stored.status.value == "expired"


def test_used_challenge_cannot_be_checked_again(
    client: TestClient, session_factory: sessionmaker[Session], lab_mode: None
) -> None:
    target_id = make_target(client)
    created = challenge(client, target_id, "lab").json()
    check(client, target_id, created["id"])
    with session_factory() as db:
        verification = db.get(OwnershipVerification, uuid.UUID(created["id"]))
        assert verification is not None
        verification.used_at = datetime.now(UTC)
        db.commit()

    response = check(client, target_id, created["id"])

    assert response.status_code == 409
    assert "already used" in response.json()["detail"]


def test_lab_check_fails_if_lab_mode_was_turned_off(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "lab_mode", True)
    target_id = make_target(client)
    created = challenge(client, target_id, "lab").json()
    monkeypatch.setattr(get_settings(), "lab_mode", False)

    response = check(client, target_id, created["id"])

    assert response.status_code == 409
    assert "LAB_MODE=false" in response.json()["detail"]


def test_checking_another_targets_challenge_is_404(client: TestClient, lab_mode: None) -> None:
    mine = make_target(client)
    created = challenge(client, mine, "lab").json()
    other = make_target(client, "domain", "example.com")

    assert check(client, other, created["id"]).status_code == 404
    assert check(client, mine, str(uuid.uuid4())).status_code == 404


def test_service_token_ttl_is_24_hours() -> None:
    assert timedelta(hours=24) == service.TOKEN_TTL


def test_lab_mode_is_off_unless_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    # `make test` exports .env (LAB_MODE=true for development), so check the bare code default.
    monkeypatch.delenv("LAB_MODE", raising=False)

    assert Settings(_env_file=None).lab_mode is False
