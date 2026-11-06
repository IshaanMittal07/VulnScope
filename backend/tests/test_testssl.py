"""testssl.sh adapter: parsing real output (saved fixtures) and building the command line.

The fixtures were produced by running this adapter in the worker: against Juice Shop (plain
HTTP) and against a throwaway local TLS server with a self-signed certificate. These tests need
no network, no DNS, and no testssl.sh binary.
"""

import json
from collections import Counter
from pathlib import Path

import pytest

from app.models.enums import TargetType
from app.scanners import testssl
from app.scanners.base import ScanTarget, UnsafeArgumentError
from app.scanners.testssl import TLSScanner, parse_json

FIXTURES = Path(__file__).parent / "fixtures" / "testssl"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def target(target_type: TargetType, host: str | None, port: int | None = None) -> ScanTarget:
    return ScanTarget(target_type, host or "", host, port, None)


# --- parsing the fixtures ---------------------------------------------------------------------


def test_a_service_without_tls_becomes_one_finding() -> None:
    findings = parse_json(fixture("juice-shop.json"), "juice-shop:3000")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner == "testssl"
    assert finding.title == "Service does not offer TLS"
    assert finding.severity == "medium"
    assert finding.location == "juice-shop:3000"
    assert finding.evidence is not None and testssl.NO_TLS_MARKER in finding.evidence
    assert finding.data == {"id": "optimal_proto", "testssl_severity": "WARN"}


def test_a_tls_service_keeps_only_real_problems() -> None:
    findings = parse_json(fixture("local-tls.json"), "127.0.0.1:8443")

    assert len(findings) == 26
    assert Counter(f.severity for f in findings) == {
        "low": 18,
        "medium": 1,
        "high": 5,
        "critical": 2,
    }
    assert all(f.location == "127.0.0.1:8443" for f in findings)
    # "OK", "INFO" and "DEBUG" entries, and notes about testssl.sh itself, are dropped.
    ids = {f.data["id"] for f in findings}
    assert not ids & {"engine_problem", "scanTime", "SSLv2", "heartbleed"}


def test_the_self_signed_certificate_problems_are_found() -> None:
    findings = parse_json(fixture("local-tls.json"), "127.0.0.1:8443")

    serious = {f.data["id"]: f for f in findings if f.severity in {"high", "critical"}}
    assert set(serious) == {
        "cert_chain_of_trust",
        "cert_expirationStatus",
        "cert_notAfter",
        "cert_revocation",
        "cert_subjectAltName",
        "cert_trust",
        "overall_grade",
    }
    chain = serious["cert_chain_of_trust"]
    assert chain.severity == "critical"
    assert chain.title.startswith("cert_chain_of_trust: failed (self signed)")


# --- parsing edge cases -----------------------------------------------------------------------


def test_cve_and_cwe_identifiers_are_picked_out() -> None:
    entry = {
        "id": "BREACH",
        "ip": "example.com/203.0.113.7",
        "port": "443",
        "severity": "MEDIUM",
        "cve": "CVE-2013-3587 not-a-cve",
        "cwe": "CWE-310",
        "finding": "potentially VULNERABLE, gzip HTTP compression detected",
    }

    (finding,) = parse_json(json.dumps([entry]), "example.com:443")

    assert finding.cve_ids == ("CVE-2013-3587",)
    assert finding.cwe_ids == ("CWE-310",)
    assert finding.title == "BREACH: potentially VULNERABLE, gzip HTTP compression detected"
    assert finding.data == {"id": "BREACH", "ip": "example.com/203.0.113.7", "port": "443"}


def test_long_titles_are_cut_to_300_characters() -> None:
    entry = {"id": "x", "severity": "LOW", "finding": "y" * 1000}

    (finding,) = parse_json(json.dumps([entry]), "example.com:443")

    assert len(finding.title) == 300
    assert finding.description == "y" * 1000  # the full text is kept


def test_an_empty_report_has_no_findings() -> None:
    assert parse_json("[]", "example.com:443") == []


# --- which targets, and on which port ---------------------------------------------------------


@pytest.mark.parametrize(
    ("scan_target", "applies"),
    [
        (target(TargetType.URL, "juice-shop", 3000), True),
        (target(TargetType.DOMAIN, "example.com"), True),
        (target(TargetType.IP, "203.0.113.7"), False),  # no web address to check
        (target(TargetType.REPO, None), False),
    ],
)
def test_applies_to_web_targets_only(scan_target: ScanTarget, applies: bool) -> None:
    assert TLSScanner().applies_to(scan_target) is applies


@pytest.mark.parametrize(
    ("scan_target", "endpoint"),
    [
        (target(TargetType.URL, "juice-shop", 3000), "juice-shop:3000"),
        (target(TargetType.DOMAIN, "example.com"), "example.com:443"),  # domains use 443
        (target(TargetType.URL, "2001:db8::1", 8443), "[2001:db8::1]:8443"),
    ],
)
def test_endpoint(scan_target: ScanTarget, endpoint: str) -> None:
    assert TLSScanner().endpoint(scan_target) == endpoint


def test_endpoint_needs_a_host() -> None:
    with pytest.raises(ValueError, match="needs a host"):
        TLSScanner().endpoint(target(TargetType.REPO, None))


# --- the command line -------------------------------------------------------------------------


def test_command_passes_the_resolved_address_and_the_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # testssl.sh can't resolve Docker service names itself, so the adapter does it.
    monkeypatch.setattr(testssl, "resolve", lambda host: "172.20.0.2")

    argv = TLSScanner().command(target(TargetType.URL, "juice-shop", 3000), tmp_path)

    assert argv == [
        "testssl",
        "--jsonfile",
        str(tmp_path / "testssl.json"),
        "--warnings",
        "off",
        "--quiet",
        "--color",
        "0",
        "--ip",
        "172.20.0.2",
        "juice-shop:3000",
    ]


def test_command_refuses_a_value_testssl_would_read_as_an_option(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(testssl, "resolve", lambda host: host)

    with pytest.raises(UnsafeArgumentError):
        TLSScanner().command(target(TargetType.DOMAIN, "--openssl=/tmp/evil"), tmp_path)


def test_parse_reads_the_report_from_the_workdir(tmp_path: Path) -> None:
    (tmp_path / "testssl.json").write_text(fixture("juice-shop.json"))

    findings = TLSScanner().parse(target(TargetType.URL, "juice-shop", 3000), tmp_path)

    assert [f.title for f in findings] == ["Service does not offer TLS"]


# --- exit codes -------------------------------------------------------------------------------


@pytest.mark.parametrize("code", [0, 1, 11, 241])
def test_completed_scans_are_accepted(code: int) -> None:
    assert code in TLSScanner.ok_exit_codes


@pytest.mark.parametrize("code", [242, 246, 247, 254, 255])
def test_testssl_errors_are_rejected(code: int) -> None:
    # 242-255 are testssl.sh's own errors (ERR_CHILD ... ERR_BASH), e.g. 247 = DNS lookup failed
    assert code not in TLSScanner.ok_exit_codes
