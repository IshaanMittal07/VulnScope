"""Recover scans whose stage job died without recording anything.

These hooks run in RQ's *parent* worker process: the on_failure callback when RQ finds a job
abandoned (its worker stopped mid-job), and the handler for a job process that died (killed by
the OOM killer, `kill -9`, ...). They must stay light: no database access and no job code, or
every job forked afterwards would inherit them (shared DB connections, stale code). So they only
queue `fail_lost_stage`, which runs in a fresh job process like any other job.
"""

import os
from types import TracebackType
from typing import Any

from redis import Redis
from rq.exceptions import AbandonedJobError
from rq.job import Job

from app.workers import queue

FAIL_LOST_STAGE = "app.workers.tasks.fail_lost_stage"


def _queue_recovery(job: Job, reason: str) -> None:
    if job.args:
        queue.get_queue().enqueue(FAIL_LOST_STAGE, job.func_name, str(job.args[0]), reason)


def on_stage_failure(
    job: Job,
    connection: Redis,
    exc_type: type[BaseException] | None,
    exc_value: BaseException | None,
    tb: TracebackType | Any,
) -> None:
    """on_failure callback for stage jobs.

    Errors raised by a stage are already recorded by tasks._run_stage, and a stale or duplicate
    job must not touch the scan, so this only acts on jobs RQ gave up on as abandoned.
    """
    if exc_type is not None and issubclass(exc_type, AbandonedJobError):
        _queue_recovery(job, "the worker stopped before the job finished")


def on_work_horse_killed(job: Job, retpid: int, ret_val: int, rusage: Any) -> None:
    """Worker hook: the process running a stage job exited without finishing it."""
    code = os.waitstatus_to_exitcode(ret_val)
    detail = f"killed by signal {-code}" if code < 0 else f"exit code {code}"
    _queue_recovery(job, f"the job's process died unexpectedly ({detail})")
