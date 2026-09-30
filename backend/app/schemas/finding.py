"""Schemas for findings, policy mappings, and cached CVE data."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from app.models.enums import Framework, Severity
from app.schemas.base import ORMSchema


class PolicyMappingRead(ORMSchema):
    id: uuid.UUID
    finding_id: uuid.UUID
    framework: Framework
    control_id: str
    control_title: str


class FindingRead(ORMSchema):
    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    description: str
    evidence: str | None
    affected_asset: str
    source_scanners: list[str]
    severity: Severity
    cvss_score: Decimal | None
    cvss_vector: str | None
    cve_ids: list[str]
    cwe_ids: list[str]
    explanation: str | None
    priority: int | None
    policy_mappings: list[PolicyMappingRead] = []


class CveCacheRead(ORMSchema):
    cve_id: str
    data: dict[str, Any]
    cvss_score: Decimal | None
    fetched_at: datetime
