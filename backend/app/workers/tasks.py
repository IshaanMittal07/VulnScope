"""Pipeline job functions: run_scan, run_analysis, run_plan, run_audit, run_report.

Each one is an RQ job for one stage. It moves the scan into its state, does the stage's work,
commits, and queues the next stage. Any error sets state=failed with an error message, and the
remaining stages never run. In Phase 3 the work is a stub that only sleeps; later phases replace
it (real scanners arrive in Phase 5).
"""

import logging
import time
import uuid
from collections.abc import Callable

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import session
from app.models import Scan
from app.models.enums import PipelineState
from app.workers import pipeline, queue

logger = logging.getLogger(__name__)

Stage = Callable[[str], None]


def placeholder_work(scan: Scan) -> None:
    """Stand-in for a stage's real work: wait a moment so the state change can be seen."""
    time.sleep(get_settings().pipeline_step_delay_seconds)


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
        try:
            db.commit()
            placeholder_work(scan)
            if next_stage is None:
                pipeline.advance(scan, PipelineState.COMPLETE)
            db.commit()
            # Queue the next stage only after this one is committed, so the next job (possibly
            # on another worker) reads the updated row.
            if next_stage is not None:
                queue.get_queue().enqueue(next_stage, scan_id)
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
