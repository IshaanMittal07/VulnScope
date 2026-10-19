"""A stage job that dies without recording anything still ends with its scan marked failed."""

import os
import signal
import uuid

import fakeredis
import pytest
from rq import Queue
from rq.exceptions import AbandonedJobError
from rq.job import Job
from sqlalchemy.orm import Session, sessionmaker

from app.models import Scan
from app.models.enums import PipelineState
from app.workers import queue as pipeline_queue
from app.workers import recovery, tasks
from tests.factories import make_target


def scan_in(factory: sessionmaker[Session], state: PipelineState) -> str:
    with factory() as db:
        scan = Scan(target=make_target(db), state=state)
        db.add(scan)
        db.commit()
        return str(scan.id)


def state_of(factory: sessionmaker[Session], scan_id: str) -> Scan:
    with factory() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        assert scan is not None
        return scan


def lost_job(queue: Queue, scan_id: str) -> Job:
    """The run_scan job as RQ stores it, as the parent worker sees it after the job died."""
    return Job.create(
        tasks.run_scan, args=[scan_id], connection=queue.connection, origin="pipeline"
    )


def owned_lost_job(factory: sessionmaker[Session], queue: Queue, scan_id: str) -> Job:
    """A lost run_scan job that had moved the scan into "scanning", so it owns the stage."""
    job = lost_job(queue, scan_id)
    with factory() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        assert scan is not None
        scan.stage_job_id = job.id
        db.commit()
    return job


def test_abandoned_job_marks_scan_failed(
    session_factory: sessionmaker[Session], sync_queue: Queue
) -> None:
    scan_id = scan_in(session_factory, PipelineState.SCANNING)
    job = owned_lost_job(session_factory, sync_queue, scan_id)

    recovery.on_stage_failure(job, sync_queue.connection, AbandonedJobError, None, None)

    scan = state_of(session_factory, scan_id)
    assert scan.state is PipelineState.FAILED
    assert scan.error_message == (
        "scanning stage failed: the worker stopped before the job finished"
    )


def test_killed_job_process_marks_scan_failed(
    session_factory: sessionmaker[Session], sync_queue: Queue
) -> None:
    scan_id = scan_in(session_factory, PipelineState.SCANNING)
    job = owned_lost_job(session_factory, sync_queue, scan_id)
    killed_by_sigkill = signal.SIGKILL  # waitpid status of a process killed by a signal

    recovery.on_work_horse_killed(job, 1234, killed_by_sigkill, None)

    scan = state_of(session_factory, scan_id)
    assert scan.state is PipelineState.FAILED
    assert scan.error_message == (
        "scanning stage failed: the job's process died unexpectedly (killed by signal 9)"
    )


def test_job_process_with_nonzero_exit_reports_its_code(
    session_factory: sessionmaker[Session], sync_queue: Queue
) -> None:
    scan_id = scan_in(session_factory, PipelineState.SCANNING)
    job = owned_lost_job(session_factory, sync_queue, scan_id)
    exited_with_3 = 3 << 8  # waitpid encodes a normal exit code in the high byte

    recovery.on_work_horse_killed(job, 1234, exited_with_3, None)

    assert state_of(session_factory, scan_id).error_message == (
        "scanning stage failed: the job's process died unexpectedly (exit code 3)"
    )


def test_ordinary_stage_errors_are_left_to_the_stage(
    session_factory: sessionmaker[Session], sync_queue: Queue
) -> None:
    # Includes InvalidTransitionError from a duplicate job: that must never fail a live scan.
    scan_id = scan_in(session_factory, PipelineState.SCANNING)

    recovery.on_stage_failure(
        lost_job(sync_queue, scan_id), sync_queue.connection, RuntimeError, None, None
    )

    assert state_of(session_factory, scan_id).state is PipelineState.SCANNING


def test_job_lost_before_it_moved_the_scan_on_still_fails_it(
    session_factory: sessionmaker[Session], sync_queue: Queue
) -> None:
    # Killed right after starting: run_scan never committed "scanning", so the scan is "queued".
    scan_id = scan_in(session_factory, PipelineState.QUEUED)

    recovery.on_work_horse_killed(lost_job(sync_queue, scan_id), 1234, signal.SIGKILL, None)

    scan = state_of(session_factory, scan_id)
    assert scan.state is PipelineState.FAILED
    assert scan.error_message is not None
    assert scan.error_message.startswith("scanning stage failed:")


def test_duplicate_job_dying_leaves_the_owners_scan_alone(
    session_factory: sessionmaker[Session], sync_queue: Queue
) -> None:
    # The real run_scan owns "scanning" and is still working; a duplicate copy of it dies.
    scan_id = scan_in(session_factory, PipelineState.SCANNING)
    owned_lost_job(session_factory, sync_queue, scan_id)
    duplicate = lost_job(sync_queue, scan_id)

    recovery.on_work_horse_killed(duplicate, 1234, signal.SIGKILL, None)

    scan = state_of(session_factory, scan_id)
    assert scan.state is PipelineState.SCANNING
    assert scan.error_message is None


def test_each_stage_records_the_job_that_owns_it(
    session_factory: sessionmaker[Session], sync_queue: Queue, monkeypatch: pytest.MonkeyPatch
) -> None:
    owners: list[str | None] = []
    monkeypatch.setattr(tasks, "placeholder_work", lambda scan: owners.append(scan.stage_job_id))
    scan_id = scan_in(session_factory, PipelineState.QUEUED)

    first = tasks.enqueue_stage(sync_queue, tasks.run_scan, scan_id)

    assert owners[0] == first.id
    assert len(owners) == 5
    assert None not in owners
    assert len(set(owners)) == 5  # every stage was moved on by its own job


@pytest.mark.parametrize(
    "state", [PipelineState.ANALYZING, PipelineState.COMPLETE, PipelineState.FAILED]
)
def test_recovery_leaves_a_scan_that_moved_on(
    session_factory: sessionmaker[Session], sync_queue: Queue, state: PipelineState
) -> None:
    scan_id = scan_in(session_factory, state)

    recovery.on_stage_failure(
        lost_job(sync_queue, scan_id), sync_queue.connection, AbandonedJobError, None, None
    )

    scan = state_of(session_factory, scan_id)
    assert scan.state is state
    assert scan.error_message is None


def test_stage_jobs_carry_the_recovery_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    stored = Queue("pipeline", connection=fakeredis.FakeRedis())  # async: jobs wait in Redis
    monkeypatch.setattr(pipeline_queue, "get_queue", lambda: stored)

    job = tasks.enqueue_stage(stored, tasks.run_analysis, str(uuid.uuid4()))

    fetched = Job.fetch(job.id, connection=stored.connection)
    assert fetched.failure_callback is recovery.on_stage_failure


def test_every_stage_job_has_a_known_state() -> None:
    stages = [tasks.run_scan, tasks.run_analysis, tasks.run_plan, tasks.run_audit, tasks.run_report]
    assert set(tasks.STAGE_STATES) == {f"app.workers.tasks.{s.__name__}" for s in stages}
    assert os.waitstatus_to_exitcode(signal.SIGKILL) == -9  # what the handler relies on
