"""Prove ownership of a target: create a challenge, then check it."""

import uuid

from fastapi import APIRouter, HTTPException, status

from app.api.deps import DbSession
from app.models import OwnershipVerification, Target
from app.schemas import OwnershipVerificationRead, VerificationChallenge, VerificationCreate
from app.verification import service

router = APIRouter(prefix="/targets/{target_id}/verifications", tags=["verification"])


def _target(db: DbSession, target_id: uuid.UUID) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    return target


@router.post("", status_code=status.HTTP_201_CREATED)
def create_verification(
    target_id: uuid.UUID, body: VerificationCreate, db: DbSession
) -> VerificationChallenge:
    """Start proving ownership: returns a token and where to publish it (valid for 24 hours)."""
    target = _target(db, target_id)
    try:
        verification = service.create_challenge(target, body.method)
    except service.LabModeOffError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except service.NotApplicableError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    db.add(verification)
    db.commit()
    read = OwnershipVerificationRead.model_validate(verification)
    return VerificationChallenge(
        **read.model_dump(), instructions=service.instructions(verification, target)
    )


@router.post("/{verification_id}/check")
def check_verification(
    target_id: uuid.UUID, verification_id: uuid.UUID, db: DbSession
) -> OwnershipVerificationRead:
    """Run the check. 200 once verified; 409 with the reason if not (retry until it expires)."""
    target = _target(db, target_id)
    verification = db.get(OwnershipVerification, verification_id)
    if verification is None or verification.target_id != target.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Verification not found")
    outcome = service.check_challenge(db, verification, target)
    db.commit()  # keep a status change (verified or expired) even when answering 409
    if not outcome.verified:
        raise HTTPException(status.HTTP_409_CONFLICT, outcome.reason)
    return OwnershipVerificationRead.model_validate(verification)
