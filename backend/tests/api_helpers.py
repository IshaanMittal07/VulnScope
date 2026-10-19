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
