"""Insert a realistic sample pipeline run into the dev database, for browsing with psql or a GUI.

Run with `make seed`. Safe to re-run: the previous seed target (and, via ON DELETE CASCADE,
everything under it) is deleted first. Refuses to run when APP_ENV=production.
"""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import SessionLocal
from app.models import (
    AuditFinding,
    AuditRun,
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
    DataType,
    Framework,
    JobStatus,
    PipelineState,
    Severity,
    TargetType,
    VerificationMethod,
    VerificationStatus,
)

SEED_TARGET_NAME = "Juice Shop (seed data)"


def seed(db: Session) -> Target:
    now = datetime.now(UTC)
    db.execute(delete(Target).where(Target.name == SEED_TARGET_NAME))
    db.execute(delete(CveCache).where(CveCache.cve_id == "CVE-2016-2183"))

    target = Target(
        name=SEED_TARGET_NAME,
        target_type=TargetType.URL,
        value="http://juice-shop:3000",
        data_types=[DataType.PERSONAL, DataType.PAYMENT_CARD],
        country="CA",
        verifications=[
            OwnershipVerification(
                method=VerificationMethod.LAB,
                token="lab-seed-token",  # noqa: S106 (sample data, not a secret)
                status=VerificationStatus.VERIFIED,
                expires_at=now + timedelta(hours=24),
                verified_at=now - timedelta(minutes=30),
                used_at=now - timedelta(minutes=29),
            )
        ],
    )
    scan = Scan(
        target=target,
        state=PipelineState.COMPLETE,
        started_at=now - timedelta(minutes=29),
        finished_at=now - timedelta(minutes=2),
        jobs=[
            ScanJob(
                scanner="nmap",
                status=JobStatus.SUCCEEDED,
                exit_code=0,
                raw_output={"host": "juice-shop", "ports": [{"port": 3000, "service": "http"}]},
            ),
            ScanJob(
                scanner="testssl",
                status=JobStatus.SUCCEEDED,
                exit_code=0,
                raw_output={"id": "cipherlist_3DES", "severity": "HIGH"},
            ),
            ScanJob(
                scanner="nuclei",
                status=JobStatus.TIMED_OUT,
                error_message="Scanner exceeded 600s timeout",
            ),
        ],
        findings=[
            Finding(
                fingerprint="tls-3des:juice-shop:3000",
                title="3DES cipher suites enabled",
                description="The server accepts 64-bit block ciphers vulnerable to SWEET32.",
                affected_asset="juice-shop:3000",
                source_scanners=["testssl", "nuclei"],
                severity=Severity.HIGH,
                cvss_score=Decimal("7.5"),
                cve_ids=["CVE-2016-2183"],
                cwe_ids=["CWE-327"],
                priority=1,
                policy_mappings=[
                    PolicyMapping(
                        framework=Framework.OWASP_TOP10,
                        control_id="A02:2021",
                        control_title="Cryptographic Failures",
                    ),
                    PolicyMapping(
                        framework=Framework.PCI_DSS,
                        control_id="4.2.1",
                        control_title="Strong cryptography for data in transit",
                    ),
                ],
            ),
            Finding(
                fingerprint="missing-hsts:juice-shop:3000",
                title="Strict-Transport-Security header missing",
                affected_asset="http://juice-shop:3000/",
                source_scanners=["zap"],
                severity=Severity.MEDIUM,
                cvss_score=Decimal("5.3"),
                cwe_ids=["CWE-319"],
                priority=2,
                policy_mappings=[
                    PolicyMapping(
                        framework=Framework.OWASP_ASVS,
                        control_id="V14.4.5",
                        control_title="HSTS header on all responses",
                    ),
                    PolicyMapping(
                        framework=Framework.PIPEDA,
                        control_id="4.7",
                        control_title="Safeguards for personal information",
                    ),
                ],
            ),
            Finding(
                fingerprint="open-port:juice-shop:3000",
                title="HTTP service exposed on port 3000",
                affected_asset="juice-shop:3000",
                source_scanners=["nmap"],
                severity=Severity.INFO,
                priority=3,
            ),
        ],
    )
    plan = ProtectionPlan(
        scan=scan,
        spec={
            "aead": "aes-256-gcm",
            "password_hash": "argon2id",
            "tls_min_version": "1.3",
            "key_source": "openbao",
        },
        rendered_files={"crypto_impl.py": "# rendered in Phase 9"},
    )
    run1 = AuditRun(
        plan=plan,
        iteration=1,
        passed=False,
        summary={"semgrep": 1, "wycheproof": 0, "property": 0, "llm_review": 0},
        started_at=now - timedelta(minutes=6),
        finished_at=now - timedelta(minutes=5),
    )
    run2 = AuditRun(
        plan=plan,
        iteration=2,
        passed=True,
        summary={"semgrep": 0, "wycheproof": 0, "property": 0, "llm_review": 0},
        started_at=now - timedelta(minutes=4),
        finished_at=now - timedelta(minutes=3),
    )
    issue = AuditFinding(
        audit_run=run1,
        check=AuditCheck.SEMGREP,
        rule_id="crypto.hardcoded-key",
        severity=Severity.CRITICAL,
        message="Encryption key is hardcoded in source",
        location="crypto_impl.py:12",
        status=AuditFindingStatus.FIXED,
    )
    db.add_all([target, plan, run2, issue])
    db.flush()
    db.add(
        PatchLog(
            plan=plan,
            audit_run=run1,
            audit_finding=issue,
            description="Load the key from OpenBao instead of source code",
            spec_before={"key_source": "inline"},
            spec_after={"key_source": "openbao"},
        )
    )
    db.add(
        CveCache(
            cve_id="CVE-2016-2183",
            data={"id": "CVE-2016-2183", "summary": "SWEET32 birthday attack on 64-bit ciphers"},
            cvss_score=Decimal("7.5"),
        )
    )
    return target


def main() -> None:
    if get_settings().app_env == "production":
        raise SystemExit("Refusing to seed: APP_ENV=production")
    with SessionLocal.begin() as db:
        target = seed(db)
        print(f"Seeded '{target.name}' (target id {target.id})")


if __name__ == "__main__":
    main()
