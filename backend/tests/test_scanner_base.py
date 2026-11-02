"""The Scanner base: tools run as argument lists, time out cleanly, and get safe arguments."""

import os
import signal
import time
from pathlib import Path

import pytest

from app.models import Target
from app.models.enums import DataType, TargetType
from app.scanners import base
from app.scanners.base import (
    RawFinding,
    ScanTarget,
    ScanTimeoutError,
    UnsafeArgumentError,
    run_command,
    safe_argument,
    tail,
)


def test_arguments_never_go_through_a_shell(tmp_path: Path) -> None:
    # In a shell, ";" would end the command and "$(...)" would run another one.
    result = run_command(["echo", "a; touch pwned", "$(id)"], 5, tmp_path)

    assert result.exit_code == 0
    assert result.stdout.read_text() == "a; touch pwned $(id)\n"
    assert not (tmp_path / "pwned").exists()


def test_tool_output_goes_to_files_capped_by_the_kernel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tool printing forever must not fill the worker's memory or disk."""
    monkeypatch.setattr(base, "MAX_FILE_BYTES", 1024 * 1024)

    result = run_command(["yes", "flood"], 30, tmp_path)  # "yes" never stops by itself

    assert result.exit_code == -signal.SIGXFSZ  # stopped by the file-size limit
    assert result.stdout.stat().st_size <= 1024 * 1024
    assert "flood" in tail(result.stdout, 12)  # the end of the file, read without loading it


def test_timeout_kills_the_tool_and_every_child_it_started(tmp_path: Path) -> None:
    # The "tool" starts a background child, records its pid, and then waits forever.
    script = "sleep 300 & echo $! > child.pid; wait"

    started = time.monotonic()
    with pytest.raises(ScanTimeoutError, match="exceeded its 1s timeout"):
        run_command(["sh", "-c", script], 1, tmp_path)

    assert time.monotonic() - started < 10
    child = int((tmp_path / "child.pid").read_text())
    for _ in range(50):  # give the kernel a moment to reap it
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail(f"child process {child} survived the timeout")


@pytest.mark.parametrize("value", ["-oN/etc/passwd", "--script=evil", "-"])
def test_values_that_look_like_options_are_refused(value: str) -> None:
    with pytest.raises(UnsafeArgumentError):
        safe_argument(value)


def test_ordinary_values_pass_through() -> None:
    assert safe_argument("juice-shop") == "juice-shop"
    assert safe_argument("http://juice-shop:3000") == "http://juice-shop:3000"


@pytest.mark.parametrize(
    ("target_type", "value", "host", "port", "url"),
    [
        (TargetType.URL, "http://juice-shop:3000", "juice-shop", 3000, "http://juice-shop:3000"),
        (TargetType.URL, "https://example.com/app", "example.com", 443, "https://example.com/app"),
        (TargetType.URL, "http://example.com", "example.com", 80, "http://example.com"),
        (TargetType.DOMAIN, "Example.com", "example.com", None, "https://example.com"),
        (TargetType.IP, "203.0.113.7", "203.0.113.7", None, None),
        (TargetType.REPO, "https://github.com/acme/app", None, None, None),
    ],
)
def test_scan_target_from_target(
    target_type: TargetType, value: str, host: str | None, port: int | None, url: str | None
) -> None:
    target = Target(name="t", target_type=target_type, value=value, data_types=[DataType.GENERAL])

    scan_target = ScanTarget.from_target(target)

    assert (scan_target.host, scan_target.port, scan_target.url) == (host, port, url)


def test_raw_finding_serializes_to_json_friendly_dict() -> None:
    finding = RawFinding(
        scanner="nmap",
        title="Open port 3000/tcp",
        severity="info",
        location="juice-shop:3000",
        cve_ids=("CVE-2024-0001",),
        data={"service": "http"},
    )

    assert finding.to_dict() == {
        "scanner": "nmap",
        "title": "Open port 3000/tcp",
        "severity": "info",
        "location": "juice-shop:3000",
        "description": "",
        "evidence": None,
        "cve_ids": ["CVE-2024-0001"],
        "cwe_ids": [],
        "data": {"service": "http"},
    }
