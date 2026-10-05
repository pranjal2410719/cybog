"""
API models for the Cybog backend.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AssessmentCreate(BaseModel):
    """Request model for creating an assessment."""
    name: str = Field(..., description="Assessment name")
    targets_file: Optional[str] = Field(default=None, description="Path to targets file OR file content")
    scope_file: Optional[str] = Field(default=None, description="Path to scope file OR file content")
    target_id: Optional[str] = Field(default=None, description="Registered target ID")
    profile: str = Field(default="standard", description="Pipeline profile")

class FileUploadResponse(BaseModel):
    """Response model for file upload."""

    filename: str
    # The UUID-based name the upload was actually stored under. Declared
    # explicitly because FastAPI filters the response through this model, so
    # without it the field was silently dropped from every response.
    secure_filename: str
    file_path: str
    content: str


class FileUploadRequest(BaseModel):
    """Request model for file upload."""
    filename: str
    content: str


class AssessmentResponse(BaseModel):
    """Response model for assessment."""
    assessment_id: str
    name: Optional[str] = None
    status: str
    created_at: str
    profile: str
    artifact_root: str
    progress: Dict[str, Any] = {}
    findings_count: int = 0
    pending_validation_count: int = 0


class AssessmentStatusResponse(BaseModel):
    """Response model for assessment status."""
    assessment_id: str
    status: str
    progress: Dict[str, Any]
    findings_count: int
    pending_validation_count: int
    created_at: str
    updated_at: str


class FindingResponse(BaseModel):
    """Response model for a finding."""
    finding_id: str
    dedup_key: str
    title: str
    description: Optional[str] = None
    severity: str
    target_id: str
    target_domain: str
    url: Optional[str] = None
    source_tool: str
    validation_status: str
    first_seen: str
    last_seen: str
    occurrence_count: int
    evidence: List[Dict[str, Any]] = []


class FindingValidationRequest(BaseModel):
    """Request model for finding validation."""
    validation_type: str = Field(..., description="confirm or reject")
    notes: Optional[str] = None


class ExportRequest(BaseModel):
    """Request model for creating an export."""
    format: str = Field(default="zip", description="Export format")
    include_raw: bool = Field(
        default=True, description="Include raw stage output in the archive"
    )
    include_evidence: bool = Field(
        default=True, description="Include per-finding evidence files"
    )
    include_validated_only: bool = Field(
        default=False,
        description="Only include findings in VALIDATED or REPORTABLE state",
    )


class ExportResponse(BaseModel):
    """Response model for export."""
    export_id: str
    assessment_id: str
    format: str
    status: str
    created_at: str
    estimated_completion: Optional[str] = None
    error: Optional[str] = None
    file_size_bytes: Optional[int] = None
    file_count: Optional[int] = None


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    cybog_version: str


class ProgressUpdate(BaseModel):
    """WebSocket progress update message."""
    assessment_id: str
    stage: str
    target_id: str
    target_domain: str
    progress_percentage: float
    message: str
    timestamp: str


class FindingUpdate(BaseModel):
    """WebSocket finding update message."""
    assessment_id: str
    finding_id: str
    finding: Dict[str, Any]
    action: str  # created, updated, validated, rejected
    timestamp: str
class TargetCreate(BaseModel):
    name: str
    domain: str
    description: Optional[str] = None

class TargetResponse(BaseModel):
    id: str
    name: str
    domain: str
    description: Optional[str] = None
    owner_uid: str
    created_at: str
