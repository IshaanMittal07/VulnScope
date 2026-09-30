"""Create and query every model against real Postgres, and check the DB enforces its rules."""

from decimal import Decimal

import pytest
from alembic import command
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    AuditFinding,
    CveCache,
    Finding,
    OwnershipVerification,
    PatchLog,
    PolicyMapping,
    ProtectionPlan,
    Scan,
    ScanJob,
    Target,
)
from app.models.enums import (
    AuditCheck,
    AuditFindingStatus,
    Framework,
    JobStatus,
    PipelineState,
    Severity,
    VerificationMethod,
    VerificationStatus,
)
from tests.conftest import alembic_config
from tests.factories import in_24h, make_audit_run, make_plan, make_scan, make_target

# --- Create and query each model -------------------------------------------------------------


def test_target(db: Session) -> None:
    target = make_target(db)
    db.expire_all()  # force a real read from Postgres, not the session's cached object

    loaded = db.get_one(Target, target.id)
    assert loaded.name == "Juice Shop (lab)"
    assert loaded.data_types == ["personal", "payment_card"]
    assert loaded.country == "CA"
    assert loaded.created_at.tzinfo is not None


def test_ownership_verification(db: Session) -> None:
    target = make_target(db)
    db.add(
        OwnershipVerification(
            target=target, method=VerificationMethod.LAB, token="tok-abc", expires_at=in_24h()
        )
    )
    db.flush()
    db.expire_all()

    (verification,) = db.get_one(Target, target.id).verifications
    assert verification.status is VerificationStatus.PENDING  # default
    assert verification.used_at is None


def test_scan_defaults_to_queued(db: Session) -> None:
    scan = make_scan(db)
    db.expire_all()

    loaded = db.get_one(Scan, scan.id)
    assert loaded.state is PipelineState.QUEUED
    assert loaded.target.name == "Juice Shop (lab)"


def test_scan_job_keeps_raw_output(db: Session) -> None:
    scan = make_scan(db)
    raw = {"host": "juice-shop", "ports": [{"port": 3000, "service": "http"}]}
    db.add(ScanJob(scan=scan, scanner="nmap", status=JobStatus.SUCCEEDED, raw_output=raw))
    db.flush()
    db.expire_all()

    (job,) = db.get_one(Scan, scan.id).jobs
    assert job.raw_output == raw  # JSONB round-trips nested data


def test_finding_with_policy_mappings(db: Session) -> None:
    scan = make_scan(db)
    finding = Finding(
        scan=scan,
        fingerprint="tls-weak-cipher:juice-shop:3000",
        title="Weak TLS cipher suites enabled",
        affected_asset="juice-shop:3000",
        source_scanners=["testssl", "nuclei"],
        severity=Severity.HIGH,
        cvss_score=Decimal("7.5"),
        cve_ids=["CVE-2016-2183"],
        cwe_ids=["CWE-327"],
        policy_mappings=[
            PolicyMapping(
                framework=Framework.OWASP_TOP10,
                control_id="A02:2021",
                control_title="Cryptographic Failures",
            ),
            PolicyMapping(
                framework=Framework.PCI_DSS,
                control_id="4.2.1",
                control_title="Strong cryptography for cardholder data in transit",
            ),
        ],
    )
    db.add(finding)
    db.flush()
    db.expire_all()

    (loaded,) = db.get_one(Scan, scan.id).findings
    assert loaded.cvss_score == Decimal("7.5")
    assert loaded.source_scanners == ["testssl", "nuclei"]
    assert {m.framework for m in loaded.policy_mappings} == {
        Framework.OWASP_TOP10,
        Framework.PCI_DSS,
    }


def test_cve_cache(db: Session) -> None:
    db.add(
        CveCache(cve_id="CVE-2016-2183", data={"id": "CVE-2016-2183"}, cvss_score=Decimal("7.5"))
    )
    db.flush()
    db.expire_all()

    cached = db.get_one(CveCache, "CVE-2016-2183")
    assert cached.data["id"] == "CVE-2016-2183"
    assert cached.fetched_at is not None


def test_protection_plan(db: Session) -> None:
    plan = make_plan(db)
    db.expire_all()

    loaded = db.get_one(ProtectionPlan, plan.id)
    assert loaded.spec["aead"] == "aes-256-gcm"
    assert loaded.scan.plan is loaded  # one-to-one both ways
    assert loaded.rendered_files == {}


def test_audit_run_findings_and_patch_log(db: Session) -> None:
    plan = make_plan(db)
    run = make_audit_run(db, plan)
    issue = AuditFinding(
        audit_run=run,
        check=AuditCheck.SEMGREP,
        rule_id="crypto.hardcoded-key",
        severity=Severity.CRITICAL,
        message="Encryption key is hardcoded in source",
        location="crypto_impl.py:12",
    )
    db.add(issue)
    db.flush()
    db.add(
        PatchLog(
            plan=plan,
            audit_run=run,
            audit_finding=issue,
            description="Load key from OpenBao instead of source code",
            spec_before={"key_source": "inline"},
            spec_after={"key_source": "openbao"},
        )
    )
    issue.status = AuditFindingStatus.FIXED
    db.flush()
    db.expire_all()

    loaded = db.get_one(ProtectionPlan, plan.id)
    assert [r.iteration for r in loaded.audit_runs] == [1]
    assert loaded.audit_runs[0].findings[0].status is AuditFindingStatus.FIXED
    (patch,) = loaded.patches
    assert patch.audit_finding is not None
    assert patch.audit_finding.rule_id == "crypto.hardcoded-key"
    assert patch.spec_after == {"key_source": "openbao"}


# --- Rules the database enforces -------------------------------------------------------------


@pytest.mark.parametrize("iteration", [0, 6])
def test_audit_iteration_must_be_1_to_5(db: Session, iteration: int) -> None:
    with pytest.raises(IntegrityError, match="ck_audit_runs_iteration_range"):
        make_audit_run(db, iteration=iteration)


def test_audit_iteration_unique_per_plan(db: Session) -> None:
    plan = make_plan(db)
    make_audit_run(db, plan, iteration=1)
    with pytest.raises(IntegrityError, match="uq_audit_runs_plan_id_iteration"):
        make_audit_run(db, plan, iteration=1)


def test_one_plan_per_scan(db: Session) -> None:
    scan = make_scan(db)
    make_plan(db, scan)
    db.expire_all()  # drop scan.plan from memory so the ORM doesn't just replace it
    db.add(ProtectionPlan(scan_id=scan.id, spec={}))
    with pytest.raises(IntegrityError, match="uq_protection_plans_scan_id"):
        db.flush()


def test_duplicate_finding_fingerprint_rejected(db: Session) -> None:
    scan = make_scan(db)
    for _ in range(2):
        db.add(
            Finding(
                scan=scan,
                fingerprint="same-issue",
                title="x",
                affected_asset="juice-shop",
                source_scanners=["nmap"],
                severity=Severity.LOW,
            )
        )
    with pytest.raises(IntegrityError, match="uq_findings_scan_id_fingerprint"):
        db.flush()


def test_invalid_enum_value_rejected(db: Session) -> None:
    scan = make_scan(db)
    with pytest.raises(IntegrityError, match="ck_scans_pipelinestate"):
        db.execute(text("UPDATE scans SET state = 'hacked' WHERE id = :id"), {"id": scan.id})


def test_invalid_data_type_rejected(db: Session) -> None:
    with pytest.raises(IntegrityError, match="ck_targets_data_types_valid"):
        make_target(db, data_types=["personal", "banana"])


def test_deleting_target_cascades_to_everything(db: Session) -> None:
    plan = make_plan(db)
    run = make_audit_run(db, plan)
    db.add(ScanJob(scan=plan.scan, scanner="nmap"))
    db.add(
        AuditFinding(
            audit_run=run,
            check=AuditCheck.BANDIT,
            rule_id="B303",
            severity=Severity.MEDIUM,
            message="weak hash",
        )
    )
    db.flush()

    # Raw SQL, so this proves the database's ON DELETE CASCADE, not ORM behaviour.
    db.execute(text("DELETE FROM targets"))
    db.expunge_all()

    for model in (Scan, ScanJob, ProtectionPlan, AuditFinding, PatchLog, OwnershipVerification):
        assert db.scalar(select(func.count()).select_from(model)) == 0, model.__name__


# --- Migration matches models ----------------------------------------------------------------


def test_migration_matches_models(engine: object, db_url: str) -> None:
    """Fails if a model changed without a new migration (`make revision m=...`)."""
    command.check(alembic_config(db_url))
