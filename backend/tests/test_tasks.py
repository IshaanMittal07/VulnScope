"""Integration tests: pipeline jobs run through RQ's synchronous mode against the test database."""

import logging
import threading
import uuid

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from rq import Queue
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.db import session as db_session
from app.models import Scan, Target
from app.models.enums import PipelineState
from app.workers import pipeline, tasks
from app.workers import queue as pipeline_queue
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
        def enqueue(self, *args: object, **kwargs: object) -> None:
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


def test_failed_commit_still_marks_scan_failed(
    session_factory: sessionmaker[Session], sync_queue: Queue, monkeypatch: pytest.MonkeyPatch
) -> None:
    record_states(monkeypatch)
    scan_id = create_scan(session_factory)
    real_commit = Session.commit
    commits = 0

    def commit_that_fails_once(self: Session) -> None:
        nonlocal commits
        commits += 1
        if commits == 1:
            raise OperationalError("COMMIT", {}, Exception("server closed the connection"))
        real_commit(self)

    monkeypatch.setattr(Session, "commit", commit_that_fails_once)

    with pytest.raises(OperationalError):
        tasks.run_scan(scan_id)

    scan = load_scan(session_factory, scan_id)
    assert scan.state is PipelineState.FAILED
    assert scan.error_message is not None
    assert scan.error_message.startswith("scanning stage failed: OperationalError:")


def test_error_while_recording_failure_keeps_original_exception(
    session_factory: sessionmaker[Session],
    sync_queue: Queue,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    record_states(monkeypatch, fail_in=PipelineState.SCANNING)

    def fail_that_breaks(scan: Scan, message: str) -> None:
        raise ValueError("database went away")

    monkeypatch.setattr(pipeline, "fail", fail_that_breaks)
    scan_id = create_scan(session_factory)

    # RQ must see the stage's own error ("boom"), not the secondary one.
    with (
        caplog.at_level(logging.ERROR, logger="app.workers.tasks"),
        pytest.raises(RuntimeError, match="boom"),
    ):
        tasks.run_scan(scan_id)
    assert f"could not mark scan {scan_id} failed" in caplog.text


def test_concurrent_duplicate_job_waits_for_row_lock_then_is_rejected(
    engine: Engine, sync_queue: Queue, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two workers running the same job: the second must wait for the first, then back off.

    Uses real, committed rows and two connections, because a row lock only blocks *another*
    connection. Without FOR UPDATE the duplicate would read the old state and advance it again.
    """
    record_states(monkeypatch)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(db_session, "SessionLocal", factory)
    with factory() as setup:
        scan = Scan(target=make_target(setup))
        setup.add(scan)
        setup.commit()
        scan_id, target_id = scan.id, scan.target_id
    try:
        errors: list[Exception] = []

        def duplicate_job() -> None:
            try:
                tasks.run_scan(str(scan_id))
            except Exception as exc:
                errors.append(exc)

        with engine.connect() as first_job:
            tx = first_job.begin()
            # The first job is mid-transition: it holds the row and has moved it to scanning.
            first_job.execute(
                text("UPDATE scans SET state = 'scanning' WHERE id = :id"), {"id": scan_id}
            )
            worker = threading.Thread(target=duplicate_job)
            worker.start()
            worker.join(timeout=1.0)
            assert worker.is_alive(), "the duplicate job should be waiting on the row lock"
            tx.commit()
            worker.join(timeout=10.0)
            assert not worker.is_alive()

        assert len(errors) == 1
        assert isinstance(errors[0], InvalidTransitionError)
        with factory() as db:
            stored = db.get(Scan, scan_id)
            assert stored is not None
            assert stored.state is PipelineState.SCANNING
    finally:
        with factory() as cleanup:
            target = cleanup.get(Target, target_id)
            if target is not None:
                cleanup.delete(target)
                cleanup.commit()
