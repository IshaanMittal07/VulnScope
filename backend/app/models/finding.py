"""Normalized, deduplicated findings, their policy mappings, and the NVD response cache."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from sqlalchemy import ARRAY, ForeignKey, Numeric, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, Timestamps, UUIDPrimaryKey, enum_column
from app.models.enums import Framework, Severity

if TYPE_CHECKING:
    from app.models.scan import Scan


class Finding(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "findings"
    # The fingerprint identifies "the same issue" across scanners; one row per issue per scan.
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str | None] = mapped_column(Text)
    affected_asset: Mapped[str] = mapped_column(String(2048))
    source_scanners: Mapped[list[str]] = mapped_column(ARRAY(String(32)))
    severity: Mapped[Severity] = mapped_column(enum_column(Severity))
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    cve_ids: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    cwe_ids: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list)
    # Filled in by the LLM layer (Phase 8).
    explanation: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[int | None]

    scan: Mapped[Scan] = relationship(back_populates="findings")
    policy_mappings: Mapped[list[PolicyMapping]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", passive_deletes=True
    )


class PolicyMapping(UUIDPrimaryKey, Base):
    """Links a finding to one control in one framework (e.g. OWASP A02, NIST SC-13)."""

    __tablename__ = "policy_mappings"
    __table_args__ = (UniqueConstraint("finding_id", "framework", "control_id"),)

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    framework: Mapped[Framework] = mapped_column(enum_column(Framework))
    control_id: Mapped[str] = mapped_column(String(64))
    control_title: Mapped[str] = mapped_column(String(300))

    finding: Mapped[Finding] = relationship(back_populates="policy_mappings")


class CveCache(Base):
    """Cached NVD API responses, keyed by CVE ID, so repeat scans don't re-query NVD."""

    __tablename__ = "cve_cache"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    data: Mapped[dict[str, Any]]
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    fetched_at: Mapped[datetime] = mapped_column(server_default=func.now())
