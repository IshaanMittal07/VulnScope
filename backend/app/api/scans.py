"""Start a pipeline run for a target, and poll its state."""

import uuid

from fastapi import APIRouter, HTTPException, Response, status
from redis.exceptions import RedisError

from app.api.deps import DbSession, PipelineQueue
from app.models import Scan, Target
from app.schemas import ScanCreate, ScanRead
from app.workers import pipeline, tasks

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    body: ScanCreate, db: DbSession, queue: PipelineQueue, response: Response
) -> ScanRead:
    """Create a scan and queue its pipeline. 202: the work happens in the background.

    TODO(Phase 4, #6): return 403 unless the target's ownership is verified. Until then every
    stage is a stub that never contacts the target.
    """
    if db.get(Target, body.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")

    scan = Scan(target_id=body.target_id)
    db.add(scan)
    db.commit()  # The worker must be able to read the scan before its first job runs.
    try:
        tasks.enqueue_stage(queue, tasks.run_scan, str(scan.id))
    except RedisError as exc:
        # Don't leave a scan sitting in "queued" that no worker will ever pick up.
        pipeline.fail(scan, f"could not queue the pipeline: {type(exc).__name__}: {exc}")
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
