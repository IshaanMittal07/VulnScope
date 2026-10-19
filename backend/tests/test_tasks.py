"""Integration tests: pipeline jobs run through RQ's synchronous mode against the test database."""

import uuid

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from rq import Queue
from sqlalchemy.orm import Session, sessionmaker

from app.models import Scan
from app.models.enums import PipelineState
from app.workers import queue as pipeline_queue
from app.workers import tasks
from app.workers.pipeline import InvalidTransitionError
from tests.factories import make_target


def create_scan(factory: sessionmaker[Session], state: PipelineState | None = None) -> str:
    with factory() as db:
        scan = Scan(target=make_target(db))
        if state is not None:
            scan.state = state
        db.add(scan)
        db.commit()
        return str(scan.id)


def load_scan(factory: sessionmaker[Session], scan_id: str) -> Scan:
    with factory() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        assert scan is not None
        return scan


def record_states(
    monkeypatch: pytest.MonkeyPatch, fail_in: PipelineState | None = None
) -> list[PipelineState]:
    """Swap the stub work for one that records each stage's state (and can raise in one)."""
    seen: list[PipelineState] = []

    def work(scan: Scan) -> None:
        seen.append(scan.state)
        if scan.state is fail_in:
            raise RuntimeError("boom")

    monkeypatch.setattr(tasks, "placeholder_work", work)
    return seen


def test_pipeline_runs_every_stage_to_complete(
    session_factory: sessionmaker[Session], sync_queue: Queue, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = record_states(monkeypatch)
    scan_id = create_scan(session_factory)

    sync_queue.enqueue(tasks.run_scan, scan_id)

    assert seen == [
        PipelineState.SCANNING,
        PipelineState.ANALYZING,
        PipelineState.PLANNING,
        PipelineState.AUDITING,
        PipelineState.REPORTING,
    ]
    scan = load_scan(session_factory, scan_id)
    assert scan.state is PipelineState.COMPLETE
    assert scan.error_message is None
    assert scan.started_at is not None
    assert scan.finished_at is not None
    assert scan.started_at <= scan.finished_at


def test_failing_stage_marks_scan_failed_and_stops(
    session_factory: sessionmaker[Session], sync_queue: Queue, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = record_states(monkeypatch, fail_in=PipelineState.PLANNING)
    scan_id = create_scan(session_factory)

    sync_queue.enqueue(tasks.run_scan, scan_id)

    # Stages after planning never ran.
    assert seen == [PipelineState.SCANNING, PipelineState.ANALYZING, PipelineState.PLANNING]
    scan = load_scan(session_factory, scan_id)
    assert scan.state is PipelineState.FAILED
    assert scan.error_message == "planning stage failed: RuntimeError: boom"
    assert scan.finished_at is not None
    # RQ also records the job itself as failed.
    assert sync_queue.failed_job_registry.count == 1


def test_lost_redis_between_stages_marks_scan_failed(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    record_states(monkeypatch)

    class UnreachableQueue:
        def enqueue(self, *args: object) -> None:
            raise RedisConnectionError("Error 111 connecting to redis:6379. Connection refused.")

    monkeypatch.setattr(pipeline_queue, "get_queue", UnreachableQueue)
    scan_id = create_scan(session_factory)

    with pytest.raises(RedisConnectionError):
        tasks.run_scan(scan_id)

    # The scan isn't left looking busy in "scanning" forever.
    scan = load_scan(session_factory, scan_id)
    assert scan.state is PipelineState.FAILED
    assert scan.error_message is not None
    assert scan.error_message.startswith("scanning stage failed: ConnectionError:")


@pytest.mark.parametrize("state", [PipelineState.COMPLETE, PipelineState.FAILED])
def test_stale_job_leaves_finished_scan_untouched(
    session_factory: sessionmaker[Session],
    sync_queue: Queue,
    monkeypatch: pytest.MonkeyPatch,
    state: PipelineState,
) -> None:
    seen = record_states(monkeypatch)
    scan_id = create_scan(session_factory, state=state)

    with pytest.raises(InvalidTransitionError):
        tasks.run_analysis(scan_id)

    assert seen == []
    scan = load_scan(session_factory, scan_id)
    assert scan.state is state
    assert scan.error_message is None


def test_duplicate_job_does_not_fail_a_running_scan(
    session_factory: sessionmaker[Session], sync_queue: Queue, monkeypatch: pytest.MonkeyPatch
) -> None:
    record_states(monkeypatch)
    scan_id = create_scan(session_factory, state=PipelineState.SCANNING)

    with pytest.raises(InvalidTransitionError):
        tasks.run_scan(scan_id)

    assert load_scan(session_factory, scan_id).state is PipelineState.SCANNING


def test_unknown_scan_id_fails_the_job(
    session_factory: sessionmaker[Session], sync_queue: Queue
) -> None:
    with pytest.raises(LookupError):
        tasks.run_scan(str(uuid.uuid4()))
