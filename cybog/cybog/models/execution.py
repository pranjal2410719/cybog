"""cybog/models/execution.py — ToolResult and StageExecution models."""
from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    tool: str
    binary: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    tool_version: Optional[str] = None


class StageExecution(BaseModel):
    stage: str
    target_id: str
    job_id: str
    attempt: int = 1
    tool_result: Optional[ToolResult] = None
    result_count: int = 0
    success: bool = False
    skip_reason: Optional[str] = None
    error: Optional[str] = None
    artifact_paths: dict[str, str] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
