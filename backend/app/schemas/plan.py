"""Schemas for protection plans."""

import uuid
from datetime import datetime
from typing import Any

from app.schemas.base import ORMSchema


class ProtectionPlanRead(ORMSchema):
    id: uuid.UUID
    scan_id: uuid.UUID
    spec: dict[str, Any]
    rendered_files: dict[str, Any]
    created_at: datetime
    updated_at: datetime
