"""Pipeline job functions: run_scan, run_analysis, run_plan, run_audit, run_report.

Each one is an RQ job for one stage. It moves the scan into its state, does the stage's work,
commits, and queues the next stage. Any error sets state=failed with an error message, and the
remaining stages never run. The scanning stage runs the real scanners (app/workers/scanning.py);
the other stages are still stubs that only sleep until later phases fill them in.
"""

import logging
import time
import uuid
from collections.abc import Callable

from rq import Queue, get_current_job
from rq.job import Callback, Job
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import session
from app.models import Scan
from app.models.enums import PipelineState
from app.workers import pipeline, queue, recovery, scanning

logger = logging.getLogger(__name__)

Stage = Callable[[str], None]


def placeholder_work(scan: Scan) -> None:
    """Stand-in for a stage's real work: wait a moment so the state change can be seen."""
    time.sleep(get_settings().pipeline_step_delay_seconds)


def stage_work(scan: Scan) -> None:
    """The work of the scan's current stage. Only scanning is real so far (Phase 5)."""
    if scan.state is PipelineState.SCANNING:
        scanning.run_scanners(scan)
    else:
        placeholder_work(scan)


def enqueue_stage(job_queue: Queue, stage: Stage, scan_id: str) -> Job:
    """Queue a stage job with the hook that recovers its scan if RQ abandons the job.

    RQ kills a job after 180 s by default, far too short for real scanners, so the scanning
    stage gets its own, longer timeout.
    """
    timeout = get_settings().scan_stage_timeout_seconds if stage is run_scan else None
    return job_queue.enqueue(
        stage,
        scan_id,
        job_timeout=timeout,
        on_failure=Callback(recovery.on_stage_failure),
    )


def _run_stage(scan_id: str, state: PipelineState, next_stage: Stage | None) -> None:
    with session.SessionLocal() as db:
        # SELECT ... FOR UPDATE: if two copies of the same job run at once (two workers), the
        # second waits here until the first commits, then sees the new state and is rejected.
        scan = db.get(Scan, uuid.UUID(scan_id), with_for_update=True)
        if scan is None:
            raise LookupError(f"scan {scan_id} does not exist")
        # A stale or duplicate job must not touch the scan, so this check sits outside the
        # try block: InvalidTransitionError fails the job but leaves the scan as it was.
        pipeline.advance(scan, state)
        current_job = get_current_job()  # None when a stage is called directly (tests)
        scan.stage_job_id = current_job.id if current_job is not None else None
        try:
            db.commit()
            stage_work(scan)
            if next_stage is None:
                pipeline.advance(scan, PipelineState.COMPLETE)
            db.commit()
            # Queue the next stage only after this one is committed, so the next job (possibly
            # on another worker) reads the updated row.
            if next_stage is not None:
                enqueue_stage(queue.get_queue(), next_stage, scan_id)
        except Exception as exc:
            _record_failure(db, scan_id, f"{state} stage failed: {type(exc).__name__}: {exc}")
            raise  # RQ records the job as failed, with the original traceback.


def _record_failure(db: Session, scan_id: str, message: str) -> None:
    """Mark the scan failed. Best effort: if this goes wrong too (say the database is down),
    log it rather than raise, so the stage's original exception is the one RQ reports."""
    try:
        db.rollback()
        scan = db.get(Scan, uuid.UUID(scan_id), with_for_update=True)
        if scan is not None and scan.state not in pipeline.FINAL_STATES:
            pipeline.fail(scan, message)
            db.commit()
    except Exception:
        logger.exception("could not mark scan %s failed", scan_id)


def run_scan(scan_id: str) -> None:
    _run_stage(scan_id, PipelineState.SCANNING, run_analysis)


def run_analysis(scan_id: str) -> None:
    _run_stage(scan_id, PipelineState.ANALYZING, run_plan)


def run_plan(scan_id: str) -> None:
    _run_stage(scan_id, PipelineState.PLANNING, run_audit)


def run_audit(scan_id: str) -> None:
    _run_stage(scan_id, PipelineState.AUDITING, run_report)


def run_report(scan_id: str) -> None:
    """Last stage: builds the report (Phase 12), then marks the scan complete."""
    _run_stage(scan_id, PipelineState.REPORTING, None)


# Which state each stage job is responsible for, keyed by RQ's job.func_name.
STAGE_STATES: dict[str, PipelineState] = {
    f"{__name__}.{stage.__name__}": state
    for stage, state in (
        (run_scan, PipelineState.SCANNING),
        (run_analysis, PipelineState.ANALYZING),
        (run_plan, PipelineState.PLANNING),
        (run_audit, PipelineState.AUDITING),
        (run_report, PipelineState.REPORTING),
    )
}


def fail_lost_stage(stage_job: str, scan_id: str, reason: str, job_id: str | None = None) -> None:
    """Recovery job queued by app.workers.recovery: a stage job died without recording anything.

    Fails the scan when the lost job owned it: the scan is in that job's stage and its
    stage_job_id is the lost job's id, or the scan is still in the stage before (the job died
    before it could move the scan on; each stage job is queued only after the previous stage
    finished, so nothing else will move it). A duplicate job that dies while the real one is
    working doesn't own the stage, so it leaves the scan alone, as does any scan that moved on.
    """
    state = STAGE_STATES.get(stage_job)
    if state is None:
        return
    previous = pipeline.STAGE_ORDER[pipeline.STAGE_ORDER.index(state) - 1]
    with session.SessionLocal() as db:
        scan = db.get(Scan, uuid.UUID(scan_id), with_for_update=True)
        if scan is None:
            return
        owned_stage = scan.state is state and job_id is not None and scan.stage_job_id == job_id
        if not (owned_stage or scan.state is previous):
            return
        pipeline.fail(scan, f"{state} stage failed: {reason}")
        db.commit()
