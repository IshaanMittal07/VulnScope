"""Pydantic schemas: validation of API input, and building responses from ORM objects."""

from decimal import Decimal

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.models import AuditFinding, Finding, PolicyMapping
from app.models.enums import AuditCheck, DataType, Framework, PipelineState, Severity
from app.schemas import AuditRunRead, FindingRead, ScanRead, TargetCreate, TargetRead
from tests.factories import make_audit_run, make_scan, make_target


def test_target_create_accepts_valid_input() -> None:
    target = TargetCreate.model_validate(
        {
            "name": "Juice Shop",
            "target_type": "url",
            "value": "http://juice-shop:3000",
            "data_types": ["personal"],
            "country": "CA",
        }
    )
    assert target.data_types == [DataType.PERSONAL]


@pytest.mark.parametrize(
    "bad",
    [
        {"data_types": []},  # must say what data the service handles
        {"data_types": ["banana"]},
        {"country": "ca"},  # ISO codes are uppercase
        {"target_type": "ftp"},
        {"name": ""},
    ],
)
def test_target_create_rejects_invalid_input(bad: dict[str, object]) -> None:
    payload = {"name": "t", "target_type": "url", "value": "http://x", "data_types": ["general"]}
    with pytest.raises(ValidationError):
        TargetCreate.model_validate(payload | bad)


def test_read_schemas_from_orm(db: Session) -> None:
    target = make_target(db)
    scan = make_scan(db, target)
    db.add(
        Finding(
            scan=scan,
            fingerprint="f1",
            title="Missing HSTS header",
            affected_asset="juice-shop:3000",
            source_scanners=["zap"],
            severity=Severity.MEDIUM,
            cvss_score=Decimal("5.3"),
            policy_mappings=[
                PolicyMapping(
                    framework=Framework.OWASP_ASVS,
                    control_id="V14.4.5",
                    control_title="HSTS header present",
                )
            ],
        )
    )
    db.flush()

    assert TargetRead.model_validate(target).data_types == [
        DataType.PERSONAL,
        DataType.PAYMENT_CARD,
    ]
    assert ScanRead.model_validate(scan).state is PipelineState.QUEUED
    finding = FindingRead.model_validate(scan.findings[0])
    assert finding.policy_mappings[0].control_id == "V14.4.5"


def test_audit_run_read_nests_findings(db: Session) -> None:
    run = make_audit_run(db)
    db.add(
        AuditFinding(
            audit_run=run,
            check=AuditCheck.WYCHEPROOF,
            rule_id="aes-gcm-tag-tamper",
            severity=Severity.HIGH,
            message="Tampered tag accepted",
        )
    )
    db.flush()
    db.refresh(run)

    read = AuditRunRead.model_validate(run)
    assert read.iteration == 1
    assert read.findings[0].check is AuditCheck.WYCHEPROOF
