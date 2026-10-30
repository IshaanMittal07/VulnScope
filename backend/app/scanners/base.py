"""Scanner base class: build argument list (never a shell string), enforce timeout, parse output.

Every adapter wraps one open-source tool installed in the worker image (Dockerfile.worker). The
tool always runs as an argument list, never through a shell, in its own process group so a
timeout kills it and every child it started. Parsing turns the tool's output into RawFindings,
which are stored as-is on the ScanJob; Phase 6 normalizes and deduplicates them.
"""

import os
import signal
import subprocess
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit

from app.models import Target
from app.models.enums import TargetType
from app.verification.hosts import target_host

# Output kept from a tool's stdout/stderr for debugging; the parsed findings are what matter.
MAX_OUTPUT_EXCERPT = 4000


class ScanTimeoutError(Exception):
    """The tool ran longer than its timeout and was killed (with all its child processes)."""


class UnsafeArgumentError(ValueError):
    """A value from the target would be read by the tool as an option (it starts with '-')."""


@dataclass(frozen=True)
class ScanTarget:
    """What a scanner needs to know about a target, derived from a validated Target."""

    target_type: TargetType
    value: str
    host: str | None
    port: int | None  # explicit or scheme default for url targets; None otherwise
    url: str | None  # the web address for url and domain targets

    @classmethod
    def from_target(cls, target: Target) -> "ScanTarget":
        host = target_host(target.target_type, target.value)
        port = None
        url = None
        if target.target_type is TargetType.URL:
            parts = urlsplit(target.value)
            port = parts.port or (443 if parts.scheme == "https" else 80)
            url = target.value
        elif target.target_type is TargetType.DOMAIN:
            url = f"https://{host}"
        return cls(target.target_type, target.value, host, port, url)


@dataclass(frozen=True)
class RawFinding:
    """One thing a scanner reported, in the scanner's own terms (normalized in Phase 6)."""

    scanner: str
    title: str
    severity: str  # the tool's own label, lowercased (e.g. "high", "info", "unknown")
    location: str  # where: host:port, a URL, or a package
    description: str = ""
    evidence: str | None = None
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    data: dict[str, Any] = field(default_factory=dict)  # tool-specific details

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["cve_ids"] = list(self.cve_ids)
        result["cwe_ids"] = list(self.cwe_ids)
        return result


@dataclass(frozen=True)
class ScanOutcome:
    exit_code: int
    findings: list[RawFinding]
    output_excerpt: str  # the end of stdout/stderr, for debugging a failed or odd run

    def raw_output(self) -> dict[str, Any]:
        """What is stored in ScanJob.raw_output (JSONB)."""
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "finding_count": len(self.findings),
            "output_excerpt": self.output_excerpt,
        }


def safe_argument(value: str) -> str:
    """Refuse a target-derived value that a tool would parse as an option ("-oN /etc/x").

    Target values are already validated (hosts.py), so this is defence in depth.
    """
    if value.startswith("-"):
        raise UnsafeArgumentError(f"refusing to pass {value!r} to a scanner")
    return value


def run_command(argv: list[str], timeout: float, cwd: Path) -> tuple[int, str, str]:
    """Run a tool as an argument list (no shell), killing its whole process group on timeout."""
    process = subprocess.Popen(  # noqa: S603 (argument list built by an adapter, no shell)
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        start_new_session=True,  # its own process group, so children die with it
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise ScanTimeoutError(f"{argv[0]} exceeded its {timeout:.0f}s timeout") from None
    return process.returncode, stdout, stderr


class Scanner(ABC):
    """One tool. Subclasses say which targets they apply to, how to call the tool, and how to
    read its output."""

    name: ClassVar[str]
    timeout_seconds: ClassVar[int]

    @abstractmethod
    def applies_to(self, target: ScanTarget) -> bool: ...

    @abstractmethod
    def command(self, target: ScanTarget, workdir: Path) -> list[str]:
        """The argument list to run. Use safe_argument() on every value from the target."""

    @abstractmethod
    def parse(self, target: ScanTarget, workdir: Path, stdout: str) -> list[RawFinding]:
        """Turn the tool's output (files in workdir, or stdout) into RawFindings."""

    def run(self, target: ScanTarget, workdir: Path) -> ScanOutcome:
        exit_code, stdout, stderr = run_command(
            self.command(target, workdir), self.timeout_seconds, workdir
        )
        findings = self.parse(target, workdir, stdout)
        excerpt = (stdout + stderr)[-MAX_OUTPUT_EXCERPT:]
        return ScanOutcome(exit_code=exit_code, findings=findings, output_excerpt=excerpt)
