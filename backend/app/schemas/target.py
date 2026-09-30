"""Schemas for targets and ownership verifications."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import DataType, TargetType, VerificationMethod, VerificationStatus
from app.schemas.base import ORMSchema


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_type: TargetType
    value: str = Field(min_length=1, max_length=2048)
    data_types: list[DataType] = Field(min_length=1)
    country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")


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
