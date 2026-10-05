"""
cybog/models/assessment.py

Core assessment, authorization, and scope data models.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AssessmentStatus(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    RESUMING = "RESUMING"
    # Pipeline finished but findings still require human validation. This is
    # deliberately not COMPLETED: the assessment has unresolved findings.
    AWAITING_VALIDATION = "AWAITING_VALIDATION"
    # PRD §64: pipeline finished with some stages failing but the assessment
    # did not fully fail — a partial result is still reportable.
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"


class AuthorizationStatus(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"
    PENDING = "PENDING"


class Authorization(BaseModel):
    required: bool = True
    scope_file: str
    status: AuthorizationStatus = AuthorizationStatus.PENDING
    authorized_at: Optional[datetime] = None
    authorized_patterns: list[str] = Field(default_factory=list)


class Scope(BaseModel):
    patterns: list[str] = Field(default_factory=list)
    explicit_excludes: list[str] = Field(default_factory=list)


class Assessment(BaseModel):
    assessment_id: str = Field(
        default_factory=lambda: (
            f"assessment-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        )
    )
    profile: str = "standard"
    # Operator-supplied label. Optional so the CLI (which never sets one) is
    # unaffected; the HTTP API accepts a name and previously discarded it.
    name: Optional[str] = None
    target_input_file: str
    scope_file: str
    owner_id: Optional[str] = None
    status: AssessmentStatus = AssessmentStatus.CREATED
    authorization: Optional[Authorization] = None
    scope: Optional[Scope] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    config_snapshot: dict = Field(default_factory=dict)
    artifact_root: str = ""
    error: Optional[str] = None
