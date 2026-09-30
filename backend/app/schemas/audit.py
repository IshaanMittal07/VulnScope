"""Schemas for audit iterations, audit findings, and the patch log."""

import uuid
from datetime import datetime
from typing import Any

from app.models.enums import AuditCheck, AuditFindingStatus, Severity
from app.schemas.base import ORMSchema


class AuditFindingRead(ORMSchema):
    id: uuid.UUID
    audit_run_id: uuid.UUID
    check: AuditCheck
    rule_id: str
    severity: Severity
    message: str
    location: str | None
    status: AuditFindingStatus


class AuditRunRead(ORMSchema):
    id: uuid.UUID
    plan_id: uuid.UUID
    iteration: int
    passed: bool
    summary: dict[str, Any]
    started_at: datetime
    finished_at: datetime | None
    findings: list[AuditFindingRead] = []


class PatchLogRead(ORMSchema):
    id: uuid.UUID
    plan_id: uuid.UUID
    audit_run_id: uuid.UUID
    audit_finding_id: uuid.UUID | None
    description: str
    spec_before: dict[str, Any]
    spec_after: dict[str, Any]
    created_at: datetime
