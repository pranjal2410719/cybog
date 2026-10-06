"""Add password_hash to users (T1: UID + password authentication)

Revision ID: d4e81a2c7f3b
Revises: bf36aa3b7fca
Create Date: 2026-10-06

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e81a2c7f3b'
down_revision: Union[str, Sequence[str], None] = 'bf36aa3b7fca'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Nullable: pre-existing users have no password until one is assigned.
    # NULL password_hash users cannot log in (verify rejects None).
    op.add_column('users', sa.Column('password_hash', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'password_hash')
