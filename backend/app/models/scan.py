"""A pipeline run against one target, and the individual scanner jobs within it."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, Timestamps, UUIDPrimaryKey, enum_column
from app.models.enums import JobStatus, PipelineState

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.plan import ProtectionPlan
    from app.models.target import Target


class Scan(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "scans"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    state: Mapped[PipelineState] = mapped_column(
        enum_column(PipelineState), default=PipelineState.QUEUED
    )
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]

    target: Mapped[Target] = relationship(back_populates="scans")
    jobs: Mapped[list[ScanJob]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    plan: Mapped[ProtectionPlan | None] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )


class ScanJob(UUIDPrimaryKey, Base):
    """One scanner run (e.g. Nmap) within a scan. Keeps the scanner's raw output."""

    __tablename__ = "scan_jobs"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    scanner: Mapped[str] = mapped_column(String(32))
    status: Mapped[JobStatus] = mapped_column(enum_column(JobStatus), default=JobStatus.QUEUED)
    exit_code: Mapped[int | None]
    raw_output: Mapped[dict[str, Any] | None]
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]

    scan: Mapped[Scan] = relationship(back_populates="jobs")
