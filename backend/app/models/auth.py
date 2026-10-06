"""
Authentication and authorization models for the Cybog backend.

Defines the :class:`Role` enum, the :class:`User` model (keyed by a stable
``uid`` such as ``USR-0001``), and the :class:`AuditEvent` model that records
state-changing actions for the audit trail (PRD §6, §9, §60, §50).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Role(str, Enum):
    """Three-role RBAC model (PRD §9).

    - ``OPERATOR``: can create/start/cancel assessments and upload files.
    - ``VALIDATOR``: can validate/reject findings (exclusive) in addition to
      operator actions.
    - ``MANAGEMENT``: read-only oversight — dashboards and audit review.
    """

    OPERATOR = "OPERATOR"
    VALIDATOR = "VALIDATOR"
    MANAGEMENT = "MANAGEMENT"


class User(BaseModel):
    """A registered user identified by a stable ``uid`` (``USR-XXXX``)."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    uid: str
    name: str
    role: Role
    active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuditEvent(BaseModel):
    """A single state-changing action recorded in the audit trail (§50)."""

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    actor_uid: str
    actor_user_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str
    resource: str
    assessment_id: Optional[str] = None
    target_id: Optional[str] = None
    previous_state: Optional[str] = None
    new_state: Optional[str] = None
    detail: Optional[str] = None
