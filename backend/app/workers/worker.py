"""Entry point for the worker container: `python -m app.workers.worker`.

Runs an RQ worker on the pipeline queue. RQ forks a fresh process for every job, and only that
child imports the job code and opens database connections, so none are shared across a fork.
If a job's process dies, app.workers.recovery queues a job that marks its scan failed.
"""

from rq import Worker

from app.workers.queue import get_queue, get_redis
from app.workers.recovery import on_work_horse_killed


def main() -> None:
    Worker(
        [get_queue()], connection=get_redis(), work_horse_killed_handler=on_work_horse_killed
    ).work()


if __name__ == "__main__":
    main()
