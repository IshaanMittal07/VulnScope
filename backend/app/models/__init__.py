"""SQLAlchemy ORM models. Importing this package registers every table on Base.metadata."""

from app.models.audit import AuditFinding, AuditRun, PatchLog
from app.models.finding import CveCache, Finding, PolicyMapping
from app.models.plan import ProtectionPlan
from app.models.scan import Scan, ScanJob
from app.models.target import OwnershipVerification, Target

__all__ = [
    "AuditFinding",
    "AuditRun",
    "CveCache",
    "Finding",
    "OwnershipVerification",
    "PatchLog",
    "PolicyMapping",
    "ProtectionPlan",
    "Scan",
    "ScanJob",
    "Target",
]
