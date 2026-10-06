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
    # Preflight passed: target/scope/authorization/profile/toolchain/storage
    # all verified. Execution only starts from READY (T7 gate).
    READY = "READY"
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
    # PENDING at creation (scope validated, awaiting human confirmation);
    # AUTHORIZED only via explicit confirmation (T5). Never set by the
    # pipeline itself.
    status: AuthorizationStatus = AuthorizationStatus.PENDING
    authorized_at: Optional[datetime] = None
    # Human who confirmed. Attributable by construction.
    authorized_by_user_id: Optional[str] = None
    authorized_patterns: list[str] = Field(default_factory=list)
    # Pinned at confirmation: canonical scope rendering + admitted targets.
    # Execution admission (T9) enforces this snapshot, not live inputs.
    scope_snapshot: dict = Field(default_factory=dict)
    scope_sha256: Optional[str] = None


class Scope(BaseModel):
    patterns: list[str] = Field(default_factory=list)
    explicit_excludes: list[str] = Field(default_factory=list)


class OutOfScopeItem(BaseModel):
    """A discovered value refused by scope admission (T9).

    Recorded for transparency — the workspace shows these counts — but
    never scanned. Deduplicated by value at record time.
    """

    value: str
    kind: str = "asset"  # asset | url
    classification: str  # OUT_OF_SCOPE | AMBIGUOUS | INVALID
    reason: str = ""
    stage: str = ""
    observed_at: Optional[datetime] = None


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
    verified: bool = False
    verified_by_user_id: Optional[str] = None
    verified_at: Optional[datetime] = None
    config_snapshot: dict = Field(default_factory=dict)
    artifact_root: str = ""
    error: Optional[str] = None
