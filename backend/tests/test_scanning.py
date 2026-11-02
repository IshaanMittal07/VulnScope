"""The scanning stage runs every applicable scanner, records a ScanJob for each, and only fails
the scan when every scanner failed. Fake scanners stand in for the real tools."""

import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from rq import Queue
from sqlalchemy.orm import Session, sessionmaker

from app.models import Scan, ScanJob
from app.models.enums import JobStatus
from app.scanners import registry
from app.scanners.base import RawFinding, Scanner, ScanOutcome, ScanTarget, ScanTimeoutError
from app.workers import tasks
from tests.api_helpers import create_verified_target, start_scan


class FakeScanner(Scanner):
    timeout_seconds = 5
    behaviour = "succeed"

    def applies_to(self, target: ScanTarget) -> bool:
        return target.host is not None

    def command(self, target: ScanTarget, workdir: Path) -> list[str]:
        if self.behaviour == "exit3":
            return ["sh", "-c", "echo 'could not reach target' >&2; exit 3"]
        return ["true"]

    def parse(self, target: ScanTarget, workdir: Path) -> list[RawFinding]:
        return [RawFinding(self.name, "Open port", "info", f"{target.host}:{target.port}")]

    def run(self, target: ScanTarget, workdir: Path) -> ScanOutcome:
        if self.behaviour == "fail":
            raise RuntimeError("tool crashed")
        if self.behaviour == "timeout":
            raise ScanTimeoutError(f"{self.name} exceeded its 5s timeout")
        return super().run(target, workdir)


def make(name: str, behaviour: str) -> type[Scanner]:
    return type(name, (FakeScanner,), {"name": name, "behaviour": behaviour})


@pytest.fixture
def scanners(monkeypatch: pytest.MonkeyPatch) -> dict[str, type[Scanner]]:
    """An empty registry for this test, so real adapters don't run."""
    fresh: dict[str, type[Scanner]] = {}
    monkeypatch.setattr(registry, "_SCANNERS", fresh)
    return fresh


def jobs_of(factory: sessionmaker[Session], scan_id: str) -> dict[str, ScanJob]:
    with factory() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        assert scan is not None
        return {job.scanner: job for job in scan.jobs}


pytestmark = pytest.mark.usefixtures("lab_mode")


def test_each_scanner_gets_a_job_and_one_failure_does_not_stop_the_others(
    client: TestClient, session_factory: sessionmaker[Session], scanners: dict[str, type[Scanner]]
) -> None:
    for name, behaviour in [("good", "succeed"), ("broken", "fail"), ("slow", "timeout")]:
        registry.register(make(name, behaviour))

    scan = start_scan(client, create_verified_target(client)["id"]).json()

    assert client.get(f"/scans/{scan['id']}").json()["state"] == "complete"
    jobs = jobs_of(session_factory, scan["id"])
    assert jobs["good"].status is JobStatus.SUCCEEDED
    assert jobs["good"].exit_code == 0
    assert jobs["good"].raw_output is not None
    assert jobs["good"].raw_output["findings"][0]["location"] == "juice-shop:3000"
    assert jobs["broken"].status is JobStatus.FAILED
    assert jobs["broken"].error_message == "RuntimeError: tool crashed"
    assert jobs["slow"].status is JobStatus.TIMED_OUT
    assert all(job.started_at and job.finished_at for job in jobs.values())


def test_a_tool_exiting_with_an_error_fails_its_job(
    client: TestClient, session_factory: sessionmaker[Session], scanners: dict[str, type[Scanner]]
) -> None:
    registry.register(make("good", "succeed"))
    registry.register(make("erroring", "exit3"))

    scan = start_scan(client, create_verified_target(client)["id"]).json()

    jobs = jobs_of(session_factory, scan["id"])
    assert jobs["erroring"].status is JobStatus.FAILED
    assert jobs["erroring"].exit_code == 3
    assert jobs["erroring"].error_message == "erroring exited with code 3: could not reach target"
    assert jobs["erroring"].raw_output is not None
    assert jobs["erroring"].raw_output["findings"] == []  # partial output isn't trusted


def test_only_erroring_tools_means_the_scan_fails(
    client: TestClient, scanners: dict[str, type[Scanner]]
) -> None:
    registry.register(make("erroring", "exit3"))

    scan = start_scan(client, create_verified_target(client)["id"]).json()

    assert client.get(f"/scans/{scan['id']}").json()["state"] == "failed"


def test_an_adapter_that_crashes_deciding_does_not_stop_the_others(
    client: TestClient, session_factory: sessionmaker[Session], scanners: dict[str, type[Scanner]]
) -> None:
    class Faulty(FakeScanner):
        name = "faulty"

        def applies_to(self, target: ScanTarget) -> bool:
            raise KeyError("port")

    registry.register(Faulty)
    registry.register(make("good", "succeed"))

    scan = start_scan(client, create_verified_target(client)["id"]).json()

    assert client.get(f"/scans/{scan['id']}").json()["state"] == "complete"
    jobs = jobs_of(session_factory, scan["id"])
    assert jobs["good"].status is JobStatus.SUCCEEDED
    assert jobs["faulty"].status is JobStatus.FAILED
    assert jobs["faulty"].error_message == "KeyError: 'port'"


def test_the_scan_fails_when_every_scanner_fails(
    client: TestClient, scanners: dict[str, type[Scanner]]
) -> None:
    registry.register(make("broken", "fail"))
    registry.register(make("slow", "timeout"))

    scan = start_scan(client, create_verified_target(client)["id"]).json()

    polled = client.get(f"/scans/{scan['id']}").json()
    assert polled["state"] == "failed"
    assert polled["error_message"] == (
        "scanning stage failed: AllScannersFailedError: every scanner failed (broken, slow)"
    )


def test_no_applicable_scanner_is_not_an_error(
    client: TestClient, session_factory: sessionmaker[Session], scanners: dict[str, type[Scanner]]
) -> None:
    class RepoOnly(FakeScanner):
        name = "repo-only"

        def applies_to(self, target: ScanTarget) -> bool:
            return target.host is None

    registry.register(RepoOnly)

    scan = start_scan(client, create_verified_target(client)["id"]).json()

    assert client.get(f"/scans/{scan['id']}").json()["state"] == "complete"
    assert jobs_of(session_factory, scan["id"]) == {}


def test_jobs_endpoint_lists_each_scanner_run(
    client: TestClient, scanners: dict[str, type[Scanner]]
) -> None:
    registry.register(make("good", "succeed"))
    registry.register(make("broken", "fail"))
    scan = start_scan(client, create_verified_target(client)["id"]).json()

    jobs = client.get(f"/scans/{scan['id']}/jobs").json()

    assert [(j["scanner"], j["status"], j["finding_count"]) for j in jobs] == [
        ("good", "succeeded", 1),
        ("broken", "failed", None),
    ]
    assert "raw_output" not in jobs[0]  # internal; can be large
    assert client.get(f"/scans/{uuid.uuid4()}/jobs").status_code == 404


def test_registering_a_name_twice_is_refused(scanners: dict[str, type[Scanner]]) -> None:
    registry.register(make("dup", "succeed"))
    with pytest.raises(ValueError, match="already registered"):
        registry.register(make("dup", "succeed"))


def test_the_scanning_job_may_run_every_scanner_back_to_back(
    sync_queue: Queue, scanners: dict[str, type[Scanner]]
) -> None:
    registry.register(type("a", (FakeScanner,), {"name": "a", "timeout_seconds": 900}))
    registry.register(type("b", (FakeScanner,), {"name": "b", "timeout_seconds": 1200}))
    stored = Queue("pipeline", connection=sync_queue.connection)  # async: jobs wait in Redis

    scan_job = tasks.enqueue_stage(stored, tasks.run_scan, str(uuid.uuid4()))
    other_job = tasks.enqueue_stage(stored, tasks.run_analysis, str(uuid.uuid4()))

    assert scan_job.timeout == 900 + 1200 + registry.STAGE_OVERHEAD_SECONDS
    assert other_job.timeout == 180  # RQ's default for the stub stages
