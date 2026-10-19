"""The Redis connection and the RQ queue that pipeline stages run on."""

from functools import lru_cache

from redis import Redis
from rq import Queue

from app.config import get_settings


@lru_cache
def get_redis() -> Redis:
    return Redis.from_url(get_settings().redis_url)


def get_queue() -> Queue:
    """The pipeline queue. Tests replace this with a synchronous queue (RQ's is_async=False)."""
    return Queue(get_settings().pipeline_queue, connection=get_redis())
