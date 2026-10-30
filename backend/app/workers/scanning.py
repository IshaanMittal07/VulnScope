"""The scanning stage: run every scanner that applies to the target and store what each found.

Each scanner becomes a ScanJob row (queued -> running -> succeeded / failed / timed_out) holding
its raw findings. One scanner failing doesn't stop the others; the stage only fails if every
scanner that applies failed, because then the scan learned nothing.
"""

import logging
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session, object_session

from app import scanners  # noqa: F401  (imports every adapter, which registers itself)
from app.models import Scan, ScanJob
from app.models.enums import JobStatus
from app.scanners import registry
from app.scanners.base import ScanTarget, ScanTimeoutError

logger = logging.getLogger(__name__)

MAX_ERROR_LENGTH = 2000


class AllScannersFailedError(Exception):
    """Every scanner that applies to the target failed or timed out."""


def run_scanners(scan: Scan) -> None:
    db = object_session(scan)
    if db is None:
        raise RuntimeError("scan is not attached to a session")
    target = ScanTarget.from_target(scan.target)
    attempted: list[str] = []
    succeeded = 0
    for scanner in registry.all_scanners():
        try:
            applies = scanner.applies_to(target)
        except Exception as exc:  # one faulty adapter must not stop the others
            logger.exception("scanner %s failed to check target %s", scanner.name, target.value)
            _record(db, ScanJob(scan=scan, scanner=scanner.name), JobStatus.FAILED, exc)
            attempted.append(scanner.name)
            continue
        if not applies:
            continue
        attempted.append(scanner.name)
        job = ScanJob(scan=scan, scanner=scanner.name, status=JobStatus.RUNNING)
        job.started_at = datetime.now(UTC)
        db.add(job)
        db.commit()  # visible while it runs, so GET /scans/{id}/jobs shows progress
        try:
            with tempfile.TemporaryDirectory(prefix=f"vulnscope-{scanner.name}-") as workdir:
                outcome = scanner.run(target, Path(workdir))
        except ScanTimeoutError as exc:
            job.status, job.error_message = JobStatus.TIMED_OUT, str(exc)
        except Exception as exc:
            logger.exception("scanner %s failed on scan %s", scanner.name, scan.id)
            job.status = JobStatus.FAILED
            job.error_message = f"{type(exc).__name__}: {exc}"[:MAX_ERROR_LENGTH]
        else:
            job.exit_code = outcome.exit_code
            job.raw_output = outcome.raw_output()
            if outcome.ok:
                job.status = JobStatus.SUCCEEDED
                succeeded += 1
            else:  # the tool stopped with an error: its partial output can't be trusted
                last_line = outcome.output_excerpt.strip().rsplit("\n", 1)[-1]
                job.status = JobStatus.FAILED
                job.error_message = (
                    f"{scanner.name} exited with code {outcome.exit_code}: {last_line}"
                )[:MAX_ERROR_LENGTH]
        job.finished_at = datetime.now(UTC)
        db.commit()

    if not attempted:
        logger.warning("no scanner applies to %s target %s", target.target_type, target.value)
    elif succeeded == 0:
        raise AllScannersFailedError(f"every scanner failed ({', '.join(attempted)})")


def _record(db: Session, job: ScanJob, status: JobStatus, exc: Exception) -> None:
    now = datetime.now(UTC)
    job.status, job.started_at, job.finished_at = status, now, now
    job.error_message = f"{type(exc).__name__}: {exc}"[:MAX_ERROR_LENGTH]
    db.add(job)
    db.commit()
