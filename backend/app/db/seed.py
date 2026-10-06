"""
Seed default users (T1: UID + password authentication).

- In development (``CYBOG_RUNTIME=development``, the default), the seeded
  demo accounts get known deterministic passwords of the form
  ``cybog-dev-<uid>`` so ``./scripts/tunnel-dev.sh`` keeps working out of
  the box. These must never be used outside a local dev environment.
- In any other runtime, accounts are created with ``password_hash=None``
  and **cannot log in** until a password is assigned with::

      python -m app.db.seed --password <uid> <new-password>

  (requires host access to the backend — that is the bootstrap authority).
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from app.config import get_settings
from app.db.session import async_session_maker
from app.db.models import DBUser
from app.models.auth import Role
from app.services.passwords import hash_password

SEEDS = [
    ("op_0001", "Ada Lovelace", Role.OPERATOR),
    ("val_0024", "Grace Hopper", Role.VALIDATOR),
    ("mg_0099", "Katherine Johnson", Role.MANAGEMENT),
    ("USR-0001", "Ada Lovelace", Role.OPERATOR),
    ("USR-0024", "Grace Hopper", Role.VALIDATOR),
    ("USR-0099", "Katherine Johnson", Role.MANAGEMENT),
]

DEV_PASSWORD_PREFIX = "cybog-dev-"


def dev_password_for(uid: str) -> str:
    """Deterministic development-only password for a seeded UID."""
    return f"{DEV_PASSWORD_PREFIX}{uid}"


async def seed() -> None:
    from sqlalchemy.future import select

    settings = get_settings()
    development = settings.CYBOG_RUNTIME == "development"

    async with async_session_maker() as session:
        for uid, name, role in SEEDS:
            result = await session.execute(select(DBUser).where(DBUser.uid == uid))
            if not result.scalar_one_or_none():
                user = DBUser(uid=uid, name=name, role=role)
                if development:
                    user.password_hash = hash_password(dev_password_for(uid))
                session.add(user)

        await session.commit()

    if development:
        print("Database seeded successfully (development passwords set: 'cybog-dev-<uid>').")
    else:
        print(
            "Database seeded successfully. No passwords assigned "
            "(non-development runtime): use 'python -m app.db.seed --password <uid> <pw>' "
            "to enable logins."
        )


async def set_password(uid: str, password: str) -> bool:
    """Assign (or rotate) a user's password. Returns False if UID unknown."""
    from sqlalchemy.future import select

    if len(password) < 12:
        print("error: password must be at least 12 characters", file=sys.stderr)
        return False
    async with async_session_maker() as session:
        result = await session.execute(select(DBUser).where(DBUser.uid == uid))
        db_user = result.scalar_one_or_none()
        if not db_user:
            print(f"error: unknown uid {uid!r}", file=sys.stderr)
            return False
        db_user.password_hash = hash_password(password)
        await session.commit()
        print(f"Password set for {uid}.")
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed Cybog users / assign passwords.")
    parser.add_argument("--password", nargs=2, metavar=("UID", "PASSWORD"),
                        help="Set a user's password and exit.")
    args = parser.parse_args()
    if args.password:
        uid, password = args.password
        ok = asyncio.run(set_password(uid, password))
        sys.exit(0 if ok else 1)
    asyncio.run(seed())
