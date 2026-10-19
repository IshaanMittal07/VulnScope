"""The pipeline state machine allows exactly the happy path, plus failing from any live state."""

import pytest
from sqlalchemy.orm import Session

from app.models import Scan
from app.models.enums import PipelineState
from app.workers.pipeline import (
    FINAL_STATES,
    MAX_ERROR_LENGTH,
    STAGE_ORDER,
    TRANSITIONS,
    InvalidTransitionError,
    advance,
    fail,
)
from tests.factories import make_target


def new_scan(db: Session) -> Scan:
    scan = Scan(target=make_target(db))
    db.add(scan)
    db.flush()
    return scan


def test_every_state_has_transition_rules() -> None:
    assert set(TRANSITIONS) == set(PipelineState)


def test_happy_path_stamps_start_and_finish(db: Session) -> None:
    scan = new_scan(db)
    assert scan.state is PipelineState.QUEUED
    assert scan.started_at is None

    for state in STAGE_ORDER[1:]:
        advance(scan, state)
        assert scan.state is state
        assert scan.started_at is not None
        assert (scan.finished_at is not None) == (state is PipelineState.COMPLETE)


@pytest.mark.parametrize(
    ("start", "to"),
    [
        (PipelineState.QUEUED, PipelineState.ANALYZING),  # skips scanning
        (PipelineState.QUEUED, PipelineState.COMPLETE),
        (PipelineState.PLANNING, PipelineState.SCANNING),  # goes backwards
        (PipelineState.SCANNING, PipelineState.SCANNING),  # a duplicate job
        (PipelineState.COMPLETE, PipelineState.FAILED),  # final states never change
        (PipelineState.FAILED, PipelineState.SCANNING),
    ],
)
def test_illegal_transitions_are_rejected(
    db: Session, start: PipelineState, to: PipelineState
) -> None:
    scan = new_scan(db)
    scan.state = start

    with pytest.raises(InvalidTransitionError):
        advance(scan, to)
    assert scan.state is start


@pytest.mark.parametrize("state", [s for s in STAGE_ORDER if s not in FINAL_STATES])
def test_any_live_state_can_fail(db: Session, state: PipelineState) -> None:
    scan = new_scan(db)
    scan.state = state

    fail(scan, "nmap timed out")

    assert scan.state is PipelineState.FAILED
    assert scan.error_message == "nmap timed out"
    assert scan.finished_at is not None


def test_fail_truncates_long_messages(db: Session) -> None:
    scan = new_scan(db)

    fail(scan, "x" * (MAX_ERROR_LENGTH + 500))

    assert scan.error_message is not None
    assert len(scan.error_message) == MAX_ERROR_LENGTH


def test_finished_scan_cannot_fail(db: Session) -> None:
    scan = new_scan(db)
    scan.state = PipelineState.COMPLETE

    with pytest.raises(InvalidTransitionError):
        fail(scan, "late error")
    assert scan.error_message is None
