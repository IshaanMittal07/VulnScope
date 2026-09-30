"""The protection plan for a scan: a PlanSpec plus the code rendered from it."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, Timestamps, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.audit import AuditRun, PatchLog
    from app.models.scan import Scan


class ProtectionPlan(UUIDPrimaryKey, Timestamps, Base):
    """Holds the current spec; its history lives in PatchLog and per-iteration AuditRuns."""

    __tablename__ = "protection_plans"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), unique=True
    )
    spec: Mapped[dict[str, Any]]
    # Filename -> rendered source code.
    rendered_files: Mapped[dict[str, Any]] = mapped_column(default=dict)

    scan: Mapped[Scan] = relationship(back_populates="plan")
    audit_runs: Mapped[list[AuditRun]] = relationship(
        back_populates="plan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="AuditRun.iteration",
    )
    patches: Mapped[list[PatchLog]] = relationship(
        back_populates="plan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="PatchLog.created_at",
    )
