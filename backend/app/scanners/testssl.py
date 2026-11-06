"""testssl.sh adapter: TLS configuration checks, parses JSON output into raw findings.

testssl.sh resolves names with its own DNS tools (dig/host), which can't see Docker's service
names (juice-shop, dvwa), so the adapter resolves the host itself and passes the address with
--ip, keeping the name for SNI and the Host header.
"""

import json
import socket
from pathlib import Path
from typing import Any

from app.models.enums import TargetType
from app.scanners.base import RawFinding, Scanner, ScanTarget, safe_argument
from app.scanners.registry import register

# testssl.sh's own failures are 242-255 (ERR_CHILD .. ERR_BASH); 0-241 means the scan ran,
# and the number counts the issues it found.
_COMPLETED = frozenset(range(0, 242))
# Entries that describe the scan or say "fine", rather than a problem with the target.
_NOT_PROBLEMS = frozenset({"OK", "INFO", "DEBUG"})
# Entries about testssl.sh's own environment, not the target.
_ENVIRONMENT_IDS = frozenset({"engine_problem", "scanTime"})
NO_TLS_MARKER = "doesn't seem to be a TLS/SSL enabled server"


def resolve(host: str) -> str:
    """The first address of a host (a literal address is returned as is)."""
    return str(socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0])


@register
class TLSScanner(Scanner):
    name = "testssl"
    timeout_seconds = 900
    ok_exit_codes = _COMPLETED

    def applies_to(self, target: ScanTarget) -> bool:
        # Web services: a url (on its own port, http or https) or a domain (port 443).
        return target.host is not None and target.target_type in {
            TargetType.URL,
            TargetType.DOMAIN,
        }

    def endpoint(self, target: ScanTarget) -> str:
        if target.host is None:
            raise ValueError("testssl needs a host")
        port = target.port or 443
        host = f"[{target.host}]" if ":" in target.host else target.host
        return f"{host}:{port}"

    def command(self, target: ScanTarget, workdir: Path) -> list[str]:
        endpoint = self.endpoint(target)
        address = resolve(target.host or "")
        return [
            "testssl",
            "--jsonfile",
            str(workdir / "testssl.json"),
            "--warnings",
            "off",  # never wait for a key press
            "--quiet",
            "--color",
            "0",
            "--ip",
            safe_argument(address),
            safe_argument(endpoint),
        ]

    def parse(self, target: ScanTarget, workdir: Path) -> list[RawFinding]:
        return parse_json((workdir / "testssl.json").read_text(), self.endpoint(target))


def parse_json(text: str, endpoint: str) -> list[RawFinding]:
    entries: list[dict[str, Any]] = json.loads(text)
    no_tls = next((e for e in entries if NO_TLS_MARKER in str(e.get("finding", ""))), None)
    if no_tls is not None:
        # Every other entry is a check that couldn't connect; one finding says it all.
        return [
            RawFinding(
                scanner="testssl",
                title="Service does not offer TLS",
                severity="medium",
                location=endpoint,
                description=(
                    "testssl.sh found no TLS/SSL on this port, so traffic to it (including "
                    "any credentials or session cookies) travels unencrypted."
                ),
                evidence=str(no_tls.get("finding")),
                data={"id": no_tls.get("id"), "testssl_severity": no_tls.get("severity")},
            )
        ]
    findings = []
    for entry in entries:
        severity = str(entry.get("severity", "")).upper()
        if severity in _NOT_PROBLEMS or entry.get("id") in _ENVIRONMENT_IDS:
            continue
        findings.append(_finding(entry, severity, endpoint))
    return findings


def _finding(entry: dict[str, Any], severity: str, endpoint: str) -> RawFinding:
    check = str(entry.get("id", "unknown"))
    text = str(entry.get("finding", ""))
    cves = tuple(c for c in str(entry.get("cve", "")).split() if c.startswith("CVE-"))
    cwes = tuple(c for c in str(entry.get("cwe", "")).split() if c.startswith("CWE-"))
    return RawFinding(
        scanner="testssl",
        title=f"{check}: {text}"[:300],
        severity=severity.lower(),  # testssl.sh's own scale: low/medium/high/critical/warn
        location=endpoint,
        description=text,
        evidence=text or None,
        cve_ids=cves,
        cwe_ids=cwes,
        data={key: entry[key] for key in ("id", "ip", "port", "hint") if key in entry},
    )
