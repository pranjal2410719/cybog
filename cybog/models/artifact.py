"""cybog/models/artifact.py — Artifact model. Immutable after stage completion."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ArtifactType(str, Enum):
    RAW_OUTPUT = "raw_output"
    NORMALIZED = "normalized"
    STDOUT_LOG = "stdout_log"
    STDERR_LOG = "stderr_log"
    EXECUTION_META = "execution_meta"
    FINDINGS = "findings"
    REPORT = "report"
    STATE = "state"


class Artifact(BaseModel):
    artifact_id: str
    assessment_id: str
    target_id: Optional[str] = None
    stage: Optional[str] = None
    job_id: Optional[str] = None
    attempt: int = 1
    artifact_type: ArtifactType
    path: str  # Relative to artifact_root
    filename: str
    size_bytes: int = 0
    checksum: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    immutable: bool = False
