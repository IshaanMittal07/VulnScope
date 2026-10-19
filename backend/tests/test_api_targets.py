"""POST /targets against the real app and test database."""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.models import Target
from tests.api_helpers import TARGET, create_target


def test_create_target(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    body = create_target(client)

    assert {key: body[key] for key in TARGET} == TARGET
    with session_factory() as db:
        stored = db.get(Target, uuid.UUID(body["id"]))
        assert stored is not None
        # Stored as the lowercase values the CHECK constraint allows, not enum names.
        assert stored.data_types == ["personal", "payment_card"]


@pytest.mark.parametrize(
    "bad",
    [{"data_types": []}, {"target_type": "ftp"}, {"country": "ca"}, {"name": ""}],
)
def test_create_target_rejects_invalid_input(client: TestClient, bad: dict[str, Any]) -> None:
    assert client.post("/targets", json=TARGET | bad).status_code == 422
