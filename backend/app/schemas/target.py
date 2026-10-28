"""Schemas for targets and ownership verifications."""

import uuid
from datetime import datetime
from typing import Self

from pydantic import BaseModel, Field, model_validator

from app.models.enums import DataType, TargetType, VerificationMethod, VerificationStatus
from app.schemas.base import ORMSchema
from app.verification.hosts import value_error


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_type: TargetType
    value: str = Field(min_length=1, max_length=2048)
    data_types: list[DataType] = Field(min_length=1)
    country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")

    @model_validator(mode="after")
    def value_matches_type(self) -> Self:
        # Ownership verification works on the target's host, so the value must really be one.
        error = value_error(self.target_type, self.value)
        if error is not None:
            raise ValueError(error)
        return self


class TargetRead(ORMSchema):
    id: uuid.UUID
    name: str
    target_type: TargetType
    value: str
    data_types: list[DataType]
    country: str | None
    created_at: datetime
    updated_at: datetime


class OwnershipVerificationRead(ORMSchema):
    id: uuid.UUID
    target_id: uuid.UUID
    method: VerificationMethod
    token: str
    status: VerificationStatus
    expires_at: datetime
    verified_at: datetime | None
    used_at: datetime | None
    created_at: datetime


class VerificationCreate(BaseModel):
    method: VerificationMethod


class VerificationChallenge(OwnershipVerificationRead):
    """A new challenge: the verification, plus what the user must do to pass it."""

    instructions: str
