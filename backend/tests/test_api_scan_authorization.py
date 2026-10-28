"""Authorization first: POST /scans refuses any target without an unused, verified verification."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models import OwnershipVerification, Scan, Target
from app.models.enums import DataType, TargetType, VerificationMethod, VerificationStatus
from app.verification import service
from app.workers import queue as pipeline_queue
from tests.api_helpers import create_target, start_scan, verify_target


def scans_of(factory: sessionmaker[Session], target_id: str) -> int:
    with factory() as db:
        count = db.scalar(
            select(func.count()).select_from(Scan).where(Scan.target_id == uuid.UUID(target_id))
        )
        return count or 0


def forbidden(response: Any) -> bool:
    return bool(
        response.status_code == 403 and "ownership is not verified" in response.json()["detail"]
    )


def test_unverified_target_is_forbidden_and_no_scan_is_created(
    client: TestClient, session_factory: sessionmaker[Session]
) -> None:
    target = create_target(client)

    response = start_scan(client, target["id"])

    assert forbidden(response)
    assert f"/targets/{target['id']}/verifications" in response.json()["detail"]
    assert scans_of(session_factory, target["id"]) == 0


def test_pending_verification_is_not_enough(client: TestClient, lab_mode: None) -> None:
    target = create_target(client)
    created = client.post(f"/targets/{target['id']}/verifications", json={"method": "lab"})
    assert created.json()["status"] == "pending"  # created but never checked

    assert forbidden(start_scan(client, target["id"]))


def test_verified_target_is_scanned_once_per_verification(
    client: TestClient, session_factory: sessionmaker[Session], lab_mode: None
) -> None:
    target = create_target(client)
    verification = verify_target(client, target["id"])

    first = start_scan(client, target["id"])
    second = start_scan(client, target["id"])

    assert first.status_code == 202
    assert forbidden(second)  # single use: the verification was spent on the first scan
    assert scans_of(session_factory, target["id"]) == 1
    with session_factory() as db:
        stored = db.get(OwnershipVerification, uuid.UUID(verification["id"]))
        assert stored is not None and stored.used_at is not None


def test_each_verification_authorizes_exactly_one_scan(
    client: TestClient, session_factory: sessionmaker[Session], lab_mode: None
) -> None:
    target = create_target(client)
    verify_target(client, target["id"])
    verify_target(client, target["id"])

    statuses = [start_scan(client, target["id"]).status_code for _ in range(3)]

    assert statuses == [202, 202, 403]
    assert scans_of(session_factory, target["id"]) == 2


def test_expired_verification_is_forbidden(
    client: TestClient, session_factory: sessionmaker[Session], lab_mode: None
) -> None:
    target = create_target(client)
    verification = verify_target(client, target["id"])
    with session_factory() as db:
        stored = db.get(OwnershipVerification, uuid.UUID(verification["id"]))
        assert stored is not None
        stored.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()

    assert forbidden(start_scan(client, target["id"]))


def test_lab_verification_stops_counting_when_lab_mode_is_turned_off(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guide's check: juice-shop works in lab mode and fails with LAB_MODE=false."""
    monkeypatch.setattr(get_settings(), "lab_mode", True)
    target = create_target(client)
    verify_target(client, target["id"])

    monkeypatch.setattr(get_settings(), "lab_mode", False)
    assert forbidden(start_scan(client, target["id"]))

    monkeypatch.setattr(get_settings(), "lab_mode", True)
    assert start_scan(client, target["id"]).status_code == 202  # still unused, so still valid


def test_another_targets_verification_does_not_count(client: TestClient, lab_mode: None) -> None:
    verified = create_target(client)
    verify_target(client, verified["id"])
    other = create_target(client)

    assert forbidden(start_scan(client, other["id"]))
    assert start_scan(client, verified["id"]).status_code == 202


def test_queue_down_gives_the_verification_back(
    client: TestClient,
    session_factory: sessionmaker[Session],
    lab_mode: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnreachableQueue:
        def enqueue(self, *args: object, **kwargs: object) -> None:
            raise RedisConnectionError("Error 111 connecting to redis:6379. Connection refused.")

    target = create_target(client)
    verification = verify_target(client, target["id"])
    monkeypatch.setattr(pipeline_queue, "get_queue", UnreachableQueue)

    assert start_scan(client, target["id"]).status_code == 503

    # No scan ran, so the verification is unused again and the user can simply retry.
    with session_factory() as db:
        stored = db.get(OwnershipVerification, uuid.UUID(verification["id"]))
        assert stored is not None and stored.used_at is None


def test_concurrent_requests_cannot_spend_the_same_verification(engine: Engine) -> None:
    """Two real connections: while one request holds the only verification (not yet committed),
    another must not get it. SKIP LOCKED makes the second find nothing, so it would answer 403."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as setup:
        target = Target(
            name="race",
            target_type=TargetType.URL,
            value="http://juice-shop:3000",
            data_types=[DataType.GENERAL],
        )
        setup.add(target)
        setup.add(
            OwnershipVerification(
                target=target,
                method=VerificationMethod.HTTP_TOKEN,
                token=service.new_token(),
                status=VerificationStatus.VERIFIED,
                verified_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        setup.commit()
        target_id = target.id
    try:
        with factory() as first, factory() as second:
            first_target = first.get(Target, target_id)
            second_target = second.get(Target, target_id)
            assert first_target is not None and second_target is not None

            claimed = service.claim_for_scan(first, first_target)
            assert claimed is not None  # locked by the first request, not yet committed
            assert service.claim_for_scan(second, second_target) is None

            first.commit()
            second.rollback()
            # After the first commits, the verification is spent for everyone.
            assert service.claim_for_scan(second, second_target) is None
    finally:
        with factory() as cleanup:
            stored = cleanup.get(Target, target_id)
            if stored is not None:
                cleanup.delete(stored)
                cleanup.commit()
