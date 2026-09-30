"""Schemas for scans and scanner jobs."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.enums import JobStatus, PipelineState
from app.schemas.base import ORMSchema


class ScanCreate(BaseModel):
    target_id: uuid.UUID


class ScanRead(ORMSchema):
    id: uuid.UUID
    target_id: uuid.UUID
    state: PipelineState
    error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ScanJobRead(ORMSchema):
    """Raw scanner output is deliberately left out; it can be large and is internal."""

    id: uuid.UUID
    scan_id: uuid.UUID
    scanner: str
    status: JobStatus
    exit_code: int | None
    error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
