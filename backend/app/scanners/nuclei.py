"""Nuclei adapter: template-based vulnerability checks, parses JSONL output.

Runs the pinned template set baked into the worker image (Dockerfile.worker), and only templates
that look rather than attack: anything tagged dos, intrusive, fuzz, or bruteforce is excluded,
as are templates that need outside services (oast, osint) or a browser (headless). Interactsh is
off, so nothing is sent to ProjectDiscovery's public callback servers, and templates are never
updated during a scan.

Only low-to-critical templates run: the info-level ones (mostly technology fingerprints) more than
double the requests, overlap with ZAP's passive checks, and pushed Juice Shop, which keeps memory
for every request it serves, past its heap limit. Requests are paced for the same reason.
"""

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.models.enums import TargetType
from app.scanners.base import RawFinding, Scanner, ScanTarget, safe_argument
from app.scanners.registry import register

TEMPLATES = "/opt/nuclei-templates"
EXCLUDED_TAGS = ("dos", "intrusive", "fuzz", "bruteforce", "oast", "osint", "headless")


@register
class Nuclei(Scanner):
    name = "nuclei"
    timeout_seconds = 1800  # about 9 minutes against Juice Shop on this machine

    def applies_to(self, target: ScanTarget) -> bool:
        return target.url is not None and target.target_type in {
            TargetType.URL,
            TargetType.DOMAIN,
        }

    def command(self, target: ScanTarget, workdir: Path) -> list[str]:
        if target.url is None:
            raise ValueError("nuclei needs a web address")
        return [
            "nuclei",
            "-u",
            safe_argument(target.url),
            "-t",
            TEMPLATES,
            "-type",
            "http",
            "-severity",
            "low,medium,high,critical",
            "-etags",
            ",".join(EXCLUDED_TAGS),
            "-ni",  # no interactsh: never contact outside callback servers
            "-duc",  # never check for or download updates
            "-nc",  # no colour codes (not -silent: its log says when it gives up on a host)
            "-jsonl",
            "-omit-raw",  # keep full requests/responses out of the stored output
            "-o",
            str(workdir / "nuclei.jsonl"),
            "-rl",
            "30",  # at most 30 requests per second
            "-c",
            "5",
            "-timeout",
            "10",
            "-retries",
            "1",
        ]

    def parse(self, target: ScanTarget, workdir: Path) -> list[RawFinding]:
        # Nuclei still exits 0 when it gives up on an unreachable or crashed host, which would
        # look like a clean scan. Its log says so; treat that as a failed run.
        log = (workdir / "stderr.txt").read_text(errors="replace")
        gave_up = gave_up_reason(log, endpoint(target.url or ""))
        if gave_up is not None:
            raise TargetUnresponsiveError(f"nuclei gave up on the target: {gave_up}")
        report = workdir / "nuclei.jsonl"
        # Nuclei only creates the file once it has a result.
        return parse_jsonl(report.read_text()) if report.exists() else []


class TargetUnresponsiveError(Exception):
    """Nuclei stopped scanning the target part-way, so its results are incomplete."""


def endpoint(url: str) -> str:
    """host:port of a URL, the way Nuclei names a target in its log (juice-shop:3000)."""
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.hostname}:{port}"


def gave_up_reason(log: str, target_endpoint: str) -> str | None:
    """The cause Nuclei logged when it dropped *this* target as unresponsive, if it did.

    Some templates probe other ports (e.g. Spark on :4040); Nuclei logs those as skipped too,
    which says nothing about the target itself, so only lines naming the target's own
    host:port count.
    """
    for line in log.splitlines():
        if "found unresponsive" not in line or "Skipped " not in line:
            continue
        skipped = line.split("Skipped ", 1)[1].split(" ", 1)[0]
        if skipped != target_endpoint:
            continue
        cause = line.split('cause="', 1)[1].split('"', 1)[0] if 'cause="' in line else ""
        return cause or "found unresponsive"
    return None


def parse_jsonl(text: str) -> list[RawFinding]:
    return [_finding(json.loads(line)) for line in text.splitlines() if line.strip()]


def _ids(value: Any) -> tuple[str, ...]:
    """Nuclei gives CVE/CWE ids as a list, a single string, or null."""
    if not value:
        return ()
    values = [value] if isinstance(value, str) else list(value)
    return tuple(str(item).upper() for item in values if item)


def _finding(result: dict[str, Any]) -> RawFinding:
    info = result.get("info", {})
    classification = info.get("classification") or {}
    name = str(info.get("name", result.get("template-id", "unknown")))
    matcher = result.get("matcher-name")
    extracted = result.get("extracted-results") or []
    data = {
        "template_id": result.get("template-id"),
        "matcher_name": matcher,
        "type": result.get("type"),
        "tags": info.get("tags", []),
        "references": info.get("reference") or [],
        "cvss_score": classification.get("cvss-score"),
        "cvss_metrics": classification.get("cvss-metrics"),
        "extracted": extracted,
    }
    return RawFinding(
        scanner="nuclei",
        title=f"{name}: {matcher}" if matcher else name,
        severity=str(info.get("severity", "unknown")).lower(),
        location=str(result.get("matched-at", result.get("host", ""))),
        description=str(info.get("description", "")).strip(),
        evidence=", ".join(str(item) for item in extracted) or None,
        cve_ids=_ids(classification.get("cve-id")),
        cwe_ids=_ids(classification.get("cwe-id")),
        data={key: value for key, value in data.items() if value not in (None, [], "")},
    )
