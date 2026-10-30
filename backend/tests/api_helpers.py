"""Shared request helpers and sample payloads for the API tests."""

from typing import Any

from fastapi.testclient import TestClient

TARGET = {
    "name": "Juice Shop (lab)",
    "target_type": "url",
    "value": "http://juice-shop:3000",
    "data_types": ["personal", "payment_card"],
    "country": "CA",
}


def create_target(client: TestClient) -> dict[str, Any]:
    response = client.post("/targets", json=TARGET)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def start_scan(client: TestClient, target_id: str) -> Any:
    return client.post("/scans", json={"target_id": target_id})


def verify_target(client: TestClient, target_id: str) -> dict[str, Any]:
    """Pass a lab verification for a lab target (the test needs the lab_mode fixture)."""
    created = client.post(f"/targets/{target_id}/verifications", json={"method": "lab"})
    assert created.status_code == 201, created.text
    checked = client.post(f"/targets/{target_id}/verifications/{created.json()['id']}/check")
    assert checked.status_code == 200, checked.text
    body: dict[str, Any] = checked.json()
    return body


def create_verified_target(client: TestClient) -> dict[str, Any]:
    target = create_target(client)
    verify_target(client, target["id"])
    return target
