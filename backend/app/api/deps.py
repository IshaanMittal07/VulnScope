"""Shared FastAPI dependencies: a database session and the pipeline queue, per request."""

from typing import Annotated

from fastapi import Depends
from rq import Queue
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.workers import queue


def pipeline_queue() -> Queue:
    return queue.get_queue()


DbSession = Annotated[Session, Depends(get_db)]
PipelineQueue = Annotated[Queue, Depends(pipeline_queue)]
