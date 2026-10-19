"""POST /scans and GET /scans/{id}: real routes and test database, jobs run synchronously."""

import uuid

import fakeredis
import pytest
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError
from rq import Queue
from sqlalchemy.orm import Session, sessionmaker

from app.models import Scan
from app.models.enums import PipelineState
from app.workers import queue as pipeline_queue
from app.workers import recovery, tasks
from tests.api_helpers import create_target, start_scan


def test_scan_runs_the_whole_pipeline(client: TestClient) -> None:
    target = create_target(client)

    response = start_scan(client, target["id"])

    assert response.status_code == 202
    scan = response.json()
    assert response.headers["location"] == f"/scans/{scan['id']}"
    assert scan["target_id"] == target["id"]
    # Synchronous mode ran every stage inside the request; a real worker runs them later.
    polled = client.get(f"/scans/{scan['id']}").json()
    assert polled["state"] == "complete"
    assert polled["error_message"] is None
    assert polled["started_at"] is not None
    assert polled["finished_at"] is not None


def test_polling_shows_every_state(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase 3's "done when": polling GET /scans/{id} shows the scan advancing to complete."""
    seen: list[str] = []

    def poll_during_stage(scan: Scan) -> None:
        seen.append(client.get(f"/scans/{scan.id}").json()["state"])

    monkeypatch.setattr(tasks, "placeholder_work", poll_during_stage)
    scan = start_scan(client, create_target(client)["id"]).json()
    seen.append(client.get(f"/scans/{scan['id']}").json()["state"])

    assert seen == ["scanning", "analyzing", "planning", "auditing", "reporting", "complete"]


def test_failed_stage_is_visible_through_the_api(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_audit(scan: Scan) -> None:
        if scan.state is PipelineState.AUDITING:
            raise RuntimeError("semgrep crashed")

    monkeypatch.setattr(tasks, "placeholder_work", broken_audit)
    scan = start_scan(client, create_target(client)["id"]).json()

    polled = client.get(f"/scans/{scan['id']}").json()
    assert polled["state"] == "failed"
    assert polled["error_message"] == "auditing stage failed: RuntimeError: semgrep crashed"
    assert polled["finished_at"] is not None


def test_scan_for_unknown_target_is_404(client: TestClient) -> None:
    assert start_scan(client, str(uuid.uuid4())).status_code == 404


def test_scan_when_queue_is_down_is_503_and_marked_failed(
    client: TestClient, session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    class UnreachableQueue:
        def enqueue(self, *args: object, **kwargs: object) -> None:
            raise RedisConnectionError("Error 111 connecting to redis:6379. Connection refused.")

    monkeypatch.setattr(pipeline_queue, "get_queue", UnreachableQueue)
    target = create_target(client)

    response = start_scan(client, target["id"])

    assert response.status_code == 503
    with session_factory() as db:
        scans = db.query(Scan).filter_by(target_id=uuid.UUID(target["id"])).all()
    assert len(scans) == 1  # created, then marked failed: never stuck in "queued"
    assert scans[0].state is PipelineState.FAILED
    assert scans[0].error_message is not None
    assert scans[0].error_message.startswith("could not queue the pipeline: ConnectionError:")
    assert str(scans[0].id) in response.json()["detail"]


def test_get_unknown_scan_is_404(client: TestClient) -> None:
    assert client.get(f"/scans/{uuid.uuid4()}").status_code == 404


def test_get_scan_with_malformed_id_is_422(client: TestClient) -> None:
    assert client.get("/scans/not-a-uuid").status_code == 422


def test_first_stage_job_carries_the_recovery_callback(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /scans queues run_scan through enqueue_stage, so a lost first job is recovered too."""
    stored = Queue("pipeline", connection=fakeredis.FakeRedis())  # async: the job waits in Redis
    monkeypatch.setattr(pipeline_queue, "get_queue", lambda: stored)

    scan = start_scan(client, create_target(client)["id"]).json()

    assert scan["state"] == "queued"
    (job,) = stored.get_jobs()
    assert job.func_name == "app.workers.tasks.run_scan"
    assert job.args == (scan["id"],)
    assert job.failure_callback is recovery.on_stage_failure
