"""Start a pipeline run for a target, and poll its state."""

import uuid

from fastapi import APIRouter, HTTPException, Response, status
from redis.exceptions import RedisError

from app.api.deps import DbSession, PipelineQueue
from app.models import Scan, Target
from app.schemas import ScanCreate, ScanJobRead, ScanRead
from app.verification import service
from app.workers import pipeline, tasks

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    body: ScanCreate, db: DbSession, queue: PipelineQueue, response: Response
) -> ScanRead:
    """Create a scan and queue its pipeline. 202: the work happens in the background.

    Authorization first: the target's ownership must be verified. Each verification authorizes
    exactly one scan; without an unused one this is 403 and no scan is created.
    """
    target = db.get(Target, body.target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    verification = service.claim_for_scan(db, target)
    if verification is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Target ownership is not verified. Create and pass a verification first "
            f"(POST /targets/{target.id}/verifications); each one authorizes a single scan.",
        )

    scan = Scan(target_id=target.id)
    db.add(scan)
    db.commit()  # Spends the verification and creates the scan together, before any job runs.
    try:
        tasks.enqueue_stage(queue, tasks.run_scan, str(scan.id))
    except RedisError as exc:
        # Don't leave a scan sitting in "queued" that no worker will ever pick up. No scan ran,
        # so give the verification back.
        pipeline.fail(scan, f"could not queue the pipeline: {type(exc).__name__}: {exc}")
        verification.used_at = None
        db.commit()
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"Job queue unavailable; scan {scan.id} was marked failed. Try again later.",
        ) from exc

    db.refresh(scan)
    response.headers["Location"] = f"/scans/{scan.id}"
    return ScanRead.model_validate(scan)


@router.get("/{scan_id}")
def get_scan(scan_id: uuid.UUID, db: DbSession) -> ScanRead:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return ScanRead.model_validate(scan)


@router.get("/{scan_id}/jobs")
def list_scan_jobs(scan_id: uuid.UUID, db: DbSession) -> list[ScanJobRead]:
    """One entry per scanner run: its status, exit code, error, and how many findings it stored."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    jobs = sorted(scan.jobs, key=lambda job: (job.started_at is None, job.started_at))
    return [ScanJobRead.model_validate(job) for job in jobs]
