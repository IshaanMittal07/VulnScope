"""Enumerations shared by models and schemas. Values are what gets stored in the database."""

from enum import StrEnum


class PipelineState(StrEnum):
    """Where a scan is in the pipeline. Ownership is verified per target before a scan exists."""

    QUEUED = "queued"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    PLANNING = "planning"
    AUDITING = "auditing"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


class TargetType(StrEnum):
    URL = "url"
    IP = "ip"
    DOMAIN = "domain"
    REPO = "repo"


class DataType(StrEnum):
    """Kind of data the target handles; drives which policy frameworks apply."""

    GENERAL = "general"
    PERSONAL = "personal"
    PAYMENT_CARD = "payment_card"
    HEALTH = "health"
    CREDENTIALS = "credentials"


class VerificationMethod(StrEnum):
    DNS_TXT = "dns_txt"
    HTTP_TOKEN = "http_token"  # noqa: S105 (method name, not a secret)
    LAB = "lab"


class VerificationStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    EXPIRED = "expired"
    FAILED = "failed"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Framework(StrEnum):
    OWASP_TOP10 = "owasp_top10"
    OWASP_ASVS = "owasp_asvs"
    NIST_800_53 = "nist_800_53"
    NIST_CSF = "nist_csf"
    CIS = "cis"
    PCI_DSS = "pci_dss"
    PIPEDA = "pipeda"


class AuditCheck(StrEnum):
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    WYCHEPROOF = "wycheproof"
    PROPERTY = "property"
    LLM_REVIEW = "llm_review"


class AuditFindingStatus(StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
