"""Test-and-fix loop records: one AuditRun per iteration, its findings, and every patch applied."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKey, enum_column
from app.models.enums import AuditCheck, AuditFindingStatus, Severity

if TYPE_CHECKING:
    from app.models.plan import ProtectionPlan

MAX_AUDIT_ITERATIONS = 5


class AuditRun(UUIDPrimaryKey, Base):
    __tablename__ = "audit_runs"
    __table_args__ = (
        UniqueConstraint("plan_id", "iteration"),
        # The loop is capped at 5 iterations (CLAUDE.md); the database enforces it too.
        CheckConstraint(f"iteration BETWEEN 1 AND {MAX_AUDIT_ITERATIONS}", name="iteration_range"),
    )

    plan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("protection_plans.id", ondelete="CASCADE"), index=True
    )
    iteration: Mapped[int]
    passed: Mapped[bool] = mapped_column(default=False)
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    started_at: Mapped[datetime] = mapped_column(server_default=func.now())
    finished_at: Mapped[datetime | None]

    plan: Mapped[ProtectionPlan] = relationship(back_populates="audit_runs")
    findings: Mapped[list[AuditFinding]] = relationship(
        back_populates="audit_run", cascade="all, delete-orphan", passive_deletes=True
    )


class AuditFinding(UUIDPrimaryKey, Base):
    """One issue reported by a check (Semgrep, Wycheproof, LLM review, ...) in one iteration."""

    __tablename__ = "audit_findings"

    audit_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"), index=True
    )
    check: Mapped[AuditCheck] = mapped_column(enum_column(AuditCheck))
    rule_id: Mapped[str] = mapped_column(String(200))
    severity: Mapped[Severity] = mapped_column(enum_column(Severity))
    message: Mapped[str] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[AuditFindingStatus] = mapped_column(
        enum_column(AuditFindingStatus), default=AuditFindingStatus.OPEN
    )

    audit_run: Mapped[AuditRun] = relationship(back_populates="findings")


class PatchLog(UUIDPrimaryKey, Base):
    """Every spec change the fixer makes, with before/after snapshots."""

    __tablename__ = "patch_logs"

    plan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("protection_plans.id", ondelete="CASCADE"), index=True
    )
    audit_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"), index=True
    )
    audit_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("audit_findings.id", ondelete="SET NULL")
    )
    description: Mapped[str] = mapped_column(Text)
    spec_before: Mapped[dict[str, Any]]
    spec_after: Mapped[dict[str, Any]]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    plan: Mapped[ProtectionPlan] = relationship(back_populates="patches")
    audit_run: Mapped[AuditRun] = relationship()
    audit_finding: Mapped[AuditFinding | None] = relationship()
