"""Targets the user wants assessed, and the ownership checks that authorize scanning them."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ARRAY, CheckConstraint, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, Timestamps, UUIDPrimaryKey, enum_column
from app.models.enums import DataType, TargetType, VerificationMethod, VerificationStatus

if TYPE_CHECKING:
    from app.models.scan import Scan

_DATA_TYPE_VALUES = ", ".join(f"'{d.value}'" for d in DataType)


class Target(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "targets"
    __table_args__ = (
        # Every element of data_types must be a known DataType value.
        CheckConstraint(
            f"data_types <@ ARRAY[{_DATA_TYPE_VALUES}]::varchar[]", name="data_types_valid"
        ),
    )

    name: Mapped[str] = mapped_column(String(200))
    target_type: Mapped[TargetType] = mapped_column(enum_column(TargetType))
    value: Mapped[str] = mapped_column(String(2048))
    data_types: Mapped[list[str]] = mapped_column(ARRAY(String(32)))
    # ISO 3166-1 alpha-2; lets policy selection add e.g. PIPEDA for Canadian personal data.
    country: Mapped[str | None] = mapped_column(String(2))

    verifications: Mapped[list[OwnershipVerification]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    scans: Mapped[list[Scan]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )


class OwnershipVerification(UUIDPrimaryKey, Base):
    """A single-use, expiring token proving the user controls a target.

    The token is published in DNS or over HTTP, so it isn't secret; knowing it proves nothing.
    """

    __tablename__ = "ownership_verifications"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    method: Mapped[VerificationMethod] = mapped_column(enum_column(VerificationMethod))
    token: Mapped[str] = mapped_column(String(128), unique=True)
    status: Mapped[VerificationStatus] = mapped_column(
        enum_column(VerificationStatus), default=VerificationStatus.PENDING
    )
    expires_at: Mapped[datetime]
    verified_at: Mapped[datetime | None]
    used_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    target: Mapped[Target] = relationship(back_populates="verifications")
