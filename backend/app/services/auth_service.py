"""
Authentication and audit service for the Cybog backend (PRD §6, §9, §50, §60).

Provides:
- `generate_uid(role: Role)`: Generates a cryptographically secure UID.
- `AuditLog`: Append-only audit trail persisted to `backend/app/data/audit_log.json`.
- `require_role`: Enforces the RBAC matrix.
"""
from __future__ import annotations

import json
import os
import threading
import secrets
import string
from pathlib import Path
from typing import List, Optional, Set

from fastapi import HTTPException

from app.models.auth import AuditEvent, Role, User


AUDIT_LOG_PATH = Path(__file__).resolve().parents[1] / "data" / "audit_log.json"


def generate_uid(role: Role) -> str:
    """
    Generate a secure UID (e.g., op_ + 20 random chars).
    Prefix is just a namespace convention. DB must be source of truth.
    """
    prefix_map = {
        Role.OPERATOR: "op_",
        Role.VALIDATOR: "val_",
        Role.MANAGEMENT: "mg_"
    }
    prefix = prefix_map.get(role, "usr_")
    chars = string.ascii_uppercase + string.digits
    random_part = "".join(secrets.choice(chars) for _ in range(20))
    return f"{prefix}{random_part}"


class AuditLog:
    """Append-only audit trail persisted to a JSON file."""

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
                continue
        return events

    def append(self, event: AuditEvent) -> AuditEvent:
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
        events = self._read_all()
        if assessment_id is not None:
            events = [e for e in events if e.assessment_id == assessment_id]
        if actor_uid is not None:
            events = [e for e in events if e.actor_uid == actor_uid]
        return events


audit_log = AuditLog()


def require_role(user: User, roles: Set[Role]) -> None:
    """Raise HTTPException(403) unless user.role is in roles."""
    if user.role not in roles:
        raise HTTPException(
            status_code=403,
            detail=f"Role {user.role.value} is not permitted for this action",
        )
