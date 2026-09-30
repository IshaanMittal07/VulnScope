"""Helpers that insert a realistic chain of rows (target -> scan -> plan -> audit run)."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models import AuditRun, ProtectionPlan, Scan, Target
from app.models.enums import DataType, TargetType


def make_target(db: Session, **overrides: object) -> Target:
    fields: dict[str, object] = {
        "name": "Juice Shop (lab)",
        "target_type": TargetType.URL,
        "value": "http://juice-shop:3000",
        "data_types": [DataType.PERSONAL, DataType.PAYMENT_CARD],
        "country": "CA",
    }
    fields.update(overrides)
    target = Target(**fields)
    db.add(target)
    db.flush()
    return target


def make_scan(db: Session, target: Target | None = None) -> Scan:
    scan = Scan(target=target or make_target(db), started_at=datetime.now(UTC))
    db.add(scan)
    db.flush()
    return scan


def make_plan(db: Session, scan: Scan | None = None) -> ProtectionPlan:
    plan = ProtectionPlan(
        scan=scan or make_scan(db),
        spec={"aead": "aes-256-gcm", "password_hash": "argon2id", "tls_min_version": "1.3"},
    )
    db.add(plan)
    db.flush()
    return plan


def make_audit_run(db: Session, plan: ProtectionPlan | None = None, iteration: int = 1) -> AuditRun:
    run = AuditRun(plan=plan or make_plan(db), iteration=iteration)
    db.add(run)
    db.flush()
    return run


def in_24h() -> datetime:
    return datetime.now(UTC) + timedelta(hours=24)
