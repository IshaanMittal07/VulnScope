"""Nuclei adapter: parsing real output (saved fixtures), spotting a target Nuclei gave up on, and
building a safe command line. No network and no nuclei binary needed.

Fixtures: juice-shop.jsonl is a complete run against the lab's Juice Shop with the adapter's
settings; the .stderr.txt files are Nuclei's own logs from a run where Juice Shop crashed
(unresponsive) and from a healthy run where only an unrelated port was skipped.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from app.models.enums import TargetType
from app.scanners.base import ScanTarget, UnsafeArgumentError
from app.scanners.nuclei import (
    EXCLUDED_TAGS,
    Nuclei,
    TargetUnresponsiveError,
    endpoint,
    gave_up_reason,
    parse_jsonl,
)

FIXTURES = Path(__file__).parent / "fixtures" / "nuclei"
JUICE_SHOP = "http://juice-shop:3000"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def web_target(
    url: str | None = JUICE_SHOP, target_type: TargetType = TargetType.URL
) -> ScanTarget:
    return ScanTarget(target_type, url or "", "juice-shop", 3000, url)


def result(**overrides: Any) -> str:
    """One line of Nuclei JSONL output, with sensible defaults."""
    line: dict[str, Any] = {
        "template-id": "example-template",
        "info": {"name": "Example Check", "severity": "high", "tags": ["cve"]},
        "type": "http",
        "matched-at": "https://example.com/admin",
    }
    line.update(overrides)
    return json.dumps(line)


# --- parsing the real fixture -----------------------------------------------------------------


def test_parses_the_juice_shop_run() -> None:
    (finding,) = parse_jsonl(fixture("juice-shop.jsonl"))

    assert finding.scanner == "nuclei"
    assert finding.title == "Prometheus Metrics - Detect"
    assert finding.severity == "medium"
    assert finding.location == "http://juice-shop:3000/metrics"
    assert finding.data["template_id"] == "prometheus-metrics"
    assert finding.data["type"] == "http"
    assert "description" not in finding.data  # it's in the finding's own description field


# --- parsing details --------------------------------------------------------------------------


def test_cve_cwe_and_cvss_come_from_the_classification() -> None:
    classification = {
        "cve-id": ["cve-2021-44228"],
        "cwe-id": "cwe-502",  # Nuclei sometimes gives a single string
        "cvss-score": 10.0,
        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    }
    line = result(
        info={"name": "Log4Shell", "severity": "critical", "classification": classification}
    )

    (finding,) = parse_jsonl(line)

    assert finding.cve_ids == ("CVE-2021-44228",)
    assert finding.cwe_ids == ("CWE-502",)
    assert finding.severity == "critical"
    assert finding.data["cvss_score"] == 10.0
    assert finding.data["cvss_metrics"].startswith("CVSS:3.1/")


def test_missing_or_null_classification_gives_no_ids() -> None:
    line = result(info={"name": "x", "severity": "low", "classification": {"cve-id": None}})

    (finding,) = parse_jsonl(line)

    assert finding.cve_ids == ()
    assert finding.cwe_ids == ()


def test_matcher_name_and_extracted_results_are_kept() -> None:
    line = result(**{"matcher-name": "x-frame-options", "extracted-results": ["nginx", "1.25"]})

    (finding,) = parse_jsonl(line)

    assert finding.title == "Example Check: x-frame-options"
    assert finding.evidence == "nginx, 1.25"
    assert finding.data["extracted"] == ["nginx", "1.25"]


def test_empty_values_are_left_out_of_the_data() -> None:
    (finding,) = parse_jsonl(result())

    assert finding.data == {"template_id": "example-template", "type": "http", "tags": ["cve"]}


def test_blank_lines_are_ignored_and_an_empty_report_has_no_findings() -> None:
    assert parse_jsonl("") == []
    assert len(parse_jsonl(f"\n{result()}\n\n{result()}\n")) == 2


def test_location_falls_back_to_the_host() -> None:
    line = json.loads(result())
    del line["matched-at"]
    line["host"] = "https://example.com"

    (finding,) = parse_jsonl(json.dumps(line))

    assert finding.location == "https://example.com"


# --- a target Nuclei gave up on ----------------------------------------------------------------


def test_spots_that_nuclei_gave_up_on_the_target() -> None:
    log = fixture("unresponsive.stderr.txt")  # Juice Shop crashed during this run

    assert gave_up_reason(log, "juice-shop:3000") == "no address found for host"


def test_an_unrelated_port_being_skipped_is_not_a_failure() -> None:
    # A healthy run: one template probed Spark on :4040, which is closed, and Nuclei logged it.
    log = fixture("other-port-skipped.stderr.txt")

    assert "Skipped juice-shop:4040" in log
    assert gave_up_reason(log, "juice-shop:3000") is None


def test_a_line_without_a_cause_still_counts() -> None:
    log = "[INF] Skipped example.com:443 from target list as found unresponsive permanently"

    assert gave_up_reason(log, "example.com:443") == "found unresponsive"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://juice-shop:3000", "juice-shop:3000"),
        ("https://example.com/login", "example.com:443"),
        ("http://example.com", "example.com:80"),
    ],
)
def test_endpoint_matches_how_nuclei_names_targets(url: str, expected: str) -> None:
    assert endpoint(url) == expected


def test_parse_fails_the_run_when_nuclei_gave_up(tmp_path: Path) -> None:
    # Nuclei exits 0 even then, so without this the scan would look clean.
    (tmp_path / "stderr.txt").write_text(fixture("unresponsive.stderr.txt"))

    with pytest.raises(TargetUnresponsiveError, match="no address found for host"):
        Nuclei().parse(web_target(), tmp_path)


def test_parse_reads_the_report_when_the_run_was_healthy(tmp_path: Path) -> None:
    (tmp_path / "stderr.txt").write_text(fixture("other-port-skipped.stderr.txt"))
    (tmp_path / "nuclei.jsonl").write_text(fixture("juice-shop.jsonl"))

    findings = Nuclei().parse(web_target(), tmp_path)

    assert [f.title for f in findings] == ["Prometheus Metrics - Detect"]


def test_no_report_file_means_no_findings(tmp_path: Path) -> None:
    # Nuclei only creates the report once it has a result.
    (tmp_path / "stderr.txt").write_text("")

    assert Nuclei().parse(web_target(), tmp_path) == []


# --- targets and command line ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scan_target", "applies"),
    [
        (web_target(), True),
        (web_target("https://example.com", TargetType.DOMAIN), True),
        (ScanTarget(TargetType.IP, "203.0.113.7", "203.0.113.7", None, None), False),
        (ScanTarget(TargetType.REPO, "https://x/y.git", None, None, None), False),
    ],
)
def test_applies_to_web_targets_only(scan_target: ScanTarget, applies: bool) -> None:
    assert Nuclei().applies_to(scan_target) is applies


def test_command_runs_only_non_intrusive_pinned_templates(tmp_path: Path) -> None:
    argv = Nuclei().command(web_target(), tmp_path)

    def value(flag: str) -> str:
        return argv[argv.index(flag) + 1]

    assert argv[0] == "nuclei"
    assert value("-u") == JUICE_SHOP
    assert value("-t") == "/opt/nuclei-templates"
    assert value("-severity") == "low,medium,high,critical"
    assert set(value("-etags").split(",")) == set(EXCLUDED_TAGS)
    assert {"dos", "intrusive", "fuzz", "bruteforce", "oast"} <= set(EXCLUDED_TAGS)
    assert "-ni" in argv  # no interactsh callbacks to outside servers
    assert "-duc" in argv  # no update checks or downloads
    assert "-silent" not in argv  # its log is how a crashed target is detected
    assert value("-o") == str(tmp_path / "nuclei.jsonl")
    assert value("-rl") == "30"


def test_command_refuses_a_url_nuclei_would_read_as_an_option(tmp_path: Path) -> None:
    with pytest.raises(UnsafeArgumentError):
        Nuclei().command(web_target("-config=/tmp/evil.yaml"), tmp_path)


def test_command_needs_a_web_address(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="needs a web address"):
        Nuclei().command(web_target(None), tmp_path)
