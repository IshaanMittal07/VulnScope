"""Entry point for the worker container: `python -m app.workers.worker`.

Runs an RQ worker on the pipeline queue. RQ forks a fresh process for every job, and only that
child imports the job code and opens database connections, so none are shared across a fork.
"""

from rq import Worker

from app.workers.queue import get_queue, get_redis


def main() -> None:
    Worker([get_queue()], connection=get_redis()).work()


if __name__ == "__main__":
    main()
