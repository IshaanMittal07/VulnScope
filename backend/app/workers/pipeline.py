"""The pipeline state machine: which state may follow which. Every scan state change goes here.

queued -> scanning -> analyzing -> planning -> auditing -> reporting -> complete
   any non-final state --------------------------------------------> failed
"""

from datetime import UTC, datetime
from itertools import pairwise

from app.models import Scan
from app.models.enums import PipelineState

# The happy path, in order. Each state may only move to the next one (or to FAILED).
STAGE_ORDER: tuple[PipelineState, ...] = (
    PipelineState.QUEUED,
    PipelineState.SCANNING,
    PipelineState.ANALYZING,
    PipelineState.PLANNING,
    PipelineState.AUDITING,
    PipelineState.REPORTING,
    PipelineState.COMPLETE,
)
FINAL_STATES = frozenset({PipelineState.COMPLETE, PipelineState.FAILED})

TRANSITIONS: dict[PipelineState, frozenset[PipelineState]] = {
    current: frozenset({following, PipelineState.FAILED})
    for current, following in pairwise(STAGE_ORDER)
}
TRANSITIONS.update({state: frozenset() for state in FINAL_STATES})

# error_message is TEXT; keep it readable rather than storing a whole traceback.
MAX_ERROR_LENGTH = 2000


class InvalidTransitionError(Exception):
    """Raised when a scan is asked to move to a state that can't follow its current one."""


def advance(scan: Scan, to: PipelineState) -> None:
    """Move a scan to the next state, stamping started_at and finished_at along the way."""
    if to not in TRANSITIONS[scan.state]:
        raise InvalidTransitionError(f"scan {scan.id} cannot move from {scan.state} to {to}")
    now = datetime.now(UTC)
    if scan.state is PipelineState.QUEUED and to is PipelineState.SCANNING:
        scan.started_at = now
    if to in FINAL_STATES:
        scan.finished_at = now
    scan.state = to


def fail(scan: Scan, message: str) -> None:
    """Mark a scan failed with a reason. A scan that already finished can't fail afterwards."""
    advance(scan, PipelineState.FAILED)
    scan.error_message = message[:MAX_ERROR_LENGTH]
