"""
Authentication and audit service for the Cybog backend (PRD §6, §9, §50, §60).

Provides:
- :class:`UserStore` — in-memory user registry keyed by ``uid``, seeded on
  startup with a small set of known users.
- :class:`AuditLog` — append-only audit trail persisted to
  ``backend/app/data/audit_log.json`` under a lock.
- :func:`get_current_user` — resolves a ``Bearer <uid>`` token or ``?uid=``
  query parameter into a real :class:`User` (or ``None``).
- :func:`require_role` — enforces the RBAC matrix, raising ``HTTPException(403)``
  when the caller's role is not permitted.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import List, Optional, Set

from fastapi import HTTPException

from app.models.auth import AuditEvent, Role, User

#: Path to the persisted audit log, resolved relative to this file so it is
#: stable regardless of the process working directory.
AUDIT_LOG_PATH = Path(__file__).resolve().parents[1] / "data" / "audit_log.json"


def _uid_for(index: int, role: Role) -> str:
    """Build a zero-padded ``USR-XXXX`` uid from a 1-based index."""
    return f"USR-{index:04d}"


class UserStore:
    """In-memory registry of users keyed by ``uid``.

    Seeded with a small, stable set of users so the backend can run without an
    external identity provider. The seed data is intentionally deterministic.
    """

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._seed()

    def _seed(self) -> None:
        """Populate the store with the default operator/analyst/management users."""
        seeds = [
            (_uid_for(1, Role.OPERATOR), "Ada Lovelace", Role.OPERATOR),
            (_uid_for(24, Role.ANALYST), "Grace Hopper", Role.ANALYST),
            (_uid_for(99, Role.MANAGEMENT), "Katherine Johnson", Role.MANAGEMENT),
        ]
        for uid, name, role in seeds:
            self._users[uid] = User(uid=uid, name=name, role=role)

    def get(self, uid: str) -> Optional[User]:
        """Return the user for ``uid`` or ``None`` if unknown."""
        return self._users.get(uid)

    def list_all(self) -> List[User]:
        """Return every registered user."""
        return list(self._users.values())

    def create(self, uid: str, name: str, role: Role) -> User:
        """Register a new user, raising ``ValueError`` on a duplicate uid."""
        if uid in self._users:
            raise ValueError(f"User {uid} already exists")
        user = User(uid=uid, name=name, role=role)
        self._users[uid] = user
        return user


class AuditLog:
    """Append-only audit trail persisted to a JSON file.

    All writes are serialized through an in-process lock so concurrent requests
    cannot interleave partial records. The file is created (with its parent
    directory) on the first append.
    """

    def __init__(self, path: Path = AUDIT_LOG_PATH) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("[]", encoding="utf-8")

    def _read_all(self) -> List[AuditEvent]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        events: List[AuditEvent] = []
        for item in raw:
            try:
                events.append(AuditEvent.model_validate(item))
            except Exception:
                # Skip corrupt records rather than failing the whole log.
                continue
        return events

    def append(self, event: AuditEvent) -> AuditEvent:
        """Persist ``event`` to the audit log and return it."""
        with self._lock:
            events = self._read_all()
            events.append(event)
            payload = [e.model_dump(mode="json") for e in events]
            self._path.write_text(
                json.dumps(payload, default=str), encoding="utf-8"
            )
        return event

    def list(
        self,
        assessment_id: Optional[str] = None,
        actor_uid: Optional[str] = None,
    ) -> List[AuditEvent]:
        """Return audit events, optionally filtered by assessment or actor."""
        events = self._read_all()
        if assessment_id is not None:
            events = [e for e in events if e.assessment_id == assessment_id]
        if actor_uid is not None:
            events = [e for e in events if e.actor_uid == actor_uid]
        return events


# Module-level singletons.
user_store = UserStore()
audit_log = AuditLog()


def get_current_user(
    token: Optional[str] = None,
    uid: Optional[str] = None,
) -> Optional[User]:
    """Resolve the current user from a ``Bearer <uid>`` token or ``?uid=``.

    Accepts either a raw ``Bearer <uid>`` credential string or a plain
    ``uid`` query parameter. Returns ``None`` when the uid is unknown or the
    account is inactive — the caller is then responsible for deciding whether
    the endpoint tolerates anonymous access.

    This replaces the previous stub that returned the literal string
    ``"anonymous"`` for any credential.
    """
    candidate: Optional[str] = None
    if token:
        parts = token.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            candidate = parts[1].strip()
        else:
            candidate = token.strip()
    if candidate is None and uid is not None:
        candidate = uid.strip()

    if not candidate:
        return None

    user = user_store.get(candidate)
    if user is None or not user.active:
        return None
    return user


def require_role(user: User, roles: Set[Role]) -> None:
    """Raise ``HTTPException(403)`` unless ``user.role`` is in ``roles``."""
    if user.role not in roles:
        raise HTTPException(
            status_code=403,
            detail=f"Role {user.role.value} is not permitted for this action",
        )
