"""Scanner base class: build argument list (never a shell string), enforce timeout, parse output.

Every adapter wraps one open-source tool installed in the worker image (Dockerfile.worker). The
tool always runs as an argument list, never through a shell, in its own process group so a
timeout kills it and every child it started. Its stdout and stderr go to files in the scan's
work folder, never into memory, and the kernel caps the size of every file it writes. Parsing
turns the tool's output into RawFindings, stored as-is on the ScanJob; Phase 6 normalizes them.
"""

import os
import resource
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

# The end of a tool's stdout/stderr kept for debugging; the parsed findings are what matter.
MAX_OUTPUT_EXCERPT = 4000
# Largest file a tool may write (its stdout, stderr, or report). The kernel enforces it
# (RLIMIT_FSIZE): a tool that tries to write more is stopped, and its job fails.
MAX_FILE_BYTES = 64 * 1024 * 1024


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
    ok: bool  # the exit code is one the adapter accepts as a completed run
    findings: list[RawFinding]
    output_excerpt: str  # the end of stdout/stderr, for debugging a failed or odd run

    def raw_output(self) -> dict[str, Any]:
        """What is stored in ScanJob.raw_output (JSONB)."""
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "finding_count": len(self.findings),
            "output_excerpt": self.output_excerpt,
        }


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: Path
    stderr: Path


def safe_argument(value: str) -> str:
    """Refuse a target-derived value that a tool would parse as an option ("-oN /etc/x").

    Target values are already validated (hosts.py), so this is defence in depth.
    """
    if value.startswith("-"):
        raise UnsafeArgumentError(f"refusing to pass {value!r} to a scanner")
    return value


def _limit_file_size() -> None:
    """Runs in the tool's process just before it starts: cap every file it writes."""
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))


def run_command(argv: list[str], timeout: float, cwd: Path) -> CommandResult:
    """Run a tool as an argument list (no shell), killing its whole process group on timeout.

    stdout and stderr are written to files in `cwd`, so a noisy tool can't fill the worker's
    memory, and the kernel stops it if any file it writes grows past MAX_FILE_BYTES.
    """
    stdout_path, stderr_path = cwd / "stdout.txt", cwd / "stderr.txt"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(  # noqa: S603 (argument list built by an adapter, no shell)
            argv,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # its own process group, so children die with it
            preexec_fn=_limit_file_size,  # the worker runs one job per process: no threads
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise ScanTimeoutError(f"{argv[0]} exceeded its {timeout:.0f}s timeout") from None
    return CommandResult(process.returncode, stdout_path, stderr_path)


def tail(path: Path, limit: int = MAX_OUTPUT_EXCERPT) -> str:
    """The last `limit` bytes of a file, without reading the rest of it."""
    with path.open("rb") as handle:
        handle.seek(max(path.stat().st_size - limit, 0))
        return handle.read().decode("utf-8", "replace")


class Scanner(ABC):
    """One tool. Subclasses say which targets they apply to, how to call the tool, and how to
    read its output."""

    name: ClassVar[str]
    timeout_seconds: ClassVar[int]
    # Exit codes meaning "the tool ran to completion". Anything else fails the job.
    ok_exit_codes: ClassVar[frozenset[int]] = frozenset({0})

    @abstractmethod
    def applies_to(self, target: ScanTarget) -> bool: ...

    @abstractmethod
    def command(self, target: ScanTarget, workdir: Path) -> list[str]:
        """The argument list to run. Use safe_argument() on every value from the target."""

    @abstractmethod
    def parse(self, target: ScanTarget, workdir: Path) -> list[RawFinding]:
        """Read the tool's output files in workdir (stdout is workdir/"stdout.txt")."""

    def run(self, target: ScanTarget, workdir: Path) -> ScanOutcome:
        result = run_command(self.command(target, workdir), self.timeout_seconds, workdir)
        ok = result.exit_code in self.ok_exit_codes
        findings = self.parse(target, workdir) if ok else []
        excerpt = tail(result.stdout, MAX_OUTPUT_EXCERPT // 2) + tail(
            result.stderr, MAX_OUTPUT_EXCERPT // 2
        )
        return ScanOutcome(result.exit_code, ok, findings, excerpt)
