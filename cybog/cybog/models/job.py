"""
cybog/models/job.py  — StageJob: fundamental unit of pipeline execution.
Zero results != FAILED.  Tool crash / timeout = FAILED.
"""
from __future__ import annotations
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"


class StageJob(BaseModel):
    job_id: str = Field(default_factory=lambda: f"job-{uuid.uuid4().hex[:12]}")
    assessment_id: str
    target_id: str
    target_domain: str
    stage: str
    attempt: int = 1
    status: JobStatus = JobStatus.PENDING
    input_artifacts: list[str] = Field(default_factory=list)
    output_artifacts: list[str] = Field(default_factory=list)
    result_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
    command: Optional[str] = None
    duration_seconds: Optional[float] = None
    skip_reason: Optional[str] = None
