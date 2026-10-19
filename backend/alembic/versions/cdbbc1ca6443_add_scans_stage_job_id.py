"""add scans.stage_job_id

Revision ID: cdbbc1ca6443
Revises: ce5bd7a4c160
Create Date: 2026-10-19 14:11:35.716469

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "cdbbc1ca6443"
down_revision: str | Sequence[str] | None = "ce5bd7a4c160"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("scans", sa.Column("stage_job_id", sa.String(length=64), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scans", "stage_job_id")
