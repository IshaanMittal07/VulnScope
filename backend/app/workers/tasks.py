"""Pipeline job functions: run_scan, run_analysis, run_plan, run_audit, run_report.

Each one is an RQ job for one stage. It moves the scan into its state, does the stage's work,
commits, and queues the next stage. Any error sets state=failed with an error message, and the
remaining stages never run. In Phase 3 the work is a stub that only sleeps; later phases replace
it (real scanners arrive in Phase 5).
"""

import time
import uuid
from collections.abc import Callable

from app.config import get_settings
from app.db import session
from app.models import Scan
from app.models.enums import PipelineState
from app.workers import pipeline, queue

Stage = Callable[[str], None]


def placeholder_work(scan: Scan) -> None:
    """Stand-in for a stage's real work: wait a moment so the state change can be seen."""
    time.sleep(get_settings().pipeline_step_delay_seconds)


def _run_stage(scan_id: str, state: PipelineState, next_stage: Stage | None) -> None:
    with session.SessionLocal() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            raise LookupError(f"scan {scan_id} does not exist")
        # A stale or duplicate job must not touch the scan, so this check sits outside the
        # try block: InvalidTransitionError fails the job but leaves the scan as it was.
        pipeline.advance(scan, state)
        db.commit()
        try:
            placeholder_work(scan)
            if next_stage is None:
                pipeline.advance(scan, PipelineState.COMPLETE)
            db.commit()
            # Queue the next stage only after this one is committed, so the next job (possibly
            # on another worker) reads the updated row.
            if next_stage is not None:
                queue.get_queue().enqueue(next_stage, scan_id)
        except Exception as exc:
            db.rollback()
            scan = db.get(Scan, uuid.UUID(scan_id))
            if scan is not None and scan.state not in pipeline.FINAL_STATES:
                pipeline.fail(scan, f"{state} stage failed: {type(exc).__name__}: {exc}")
                db.commit()
            raise  # RQ records the job as failed, with the traceback.


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
