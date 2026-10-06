"""Align targets ownership with ORM + remove ANALYST role (T2)

Revision ID: f7c92d4a1e5b
Revises: d4e81a2c7f3b
Create Date: 2026-10-06

Two independent drift fixes:

1. ``targets.owner_uid`` (FK -> users.uid, from bf36aa3b7fca) never matched
   the ORM model, which uses ``owner_id`` (FK -> users.id) everywhere
   (target_routes.py, create_assessment). Alembic-created databases were
   therefore unusable by the API. Rename the column and re-point the FK.
2. ``ANALYST`` existed in the Python Role enum but in no migration SQL
   enum; the canonical product has three roles. Any rows carrying it
   (possible on create_all-created SQLite DBs) become VALIDATOR.

Downgrade restores the old column name/FK; the ANALYST->VALIDATOR data
move is intentionally one-way (the old value no longer exists).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f7c92d4a1e5b'
down_revision: Union[str, Sequence[str], None] = 'd4e81a2c7f3b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("UPDATE users SET role='VALIDATOR' WHERE role='ANALYST'")

    with op.batch_alter_table("targets", recreate="always") as batch_op:
        batch_op.alter_column(
            "owner_uid",
            new_column_name="owner_id",
            existing_type=sa.String(),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_targets_owner_id_users", "users", ["owner_id"], ["id"]
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("targets", recreate="always") as batch_op:
        batch_op.alter_column(
            "owner_id",
            new_column_name="owner_uid",
            existing_type=sa.String(),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_targets_owner_uid_users", "users", ["owner_uid"], ["uid"]
        )
