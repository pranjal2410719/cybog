"""
cybog/models/finding.py

Finding, Evidence, ValidationStatus models.
Every scanner alert is DISCOVERED (candidate) until human/logic validates it.
"""
from __future__ import annotations
import hashlib
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ValidationStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    UNVALIDATED = "UNVALIDATED"
    VALIDATED = "VALIDATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REPORTABLE = "REPORTABLE"


class Evidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    finding_id: str
    tool: str
    raw_output: str
    request: Optional[str] = None
    response: Optional[str] = None
    artifact_path: Optional[str] = None
    collected_at: datetime = Field(default_factory=datetime.utcnow)


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    dedup_key: str = ""
    finding_type: str
    title: str
    severity: Severity = Severity.UNKNOWN
    target_id: str
    target_domain: str
    url: Optional[str] = None
    source_tool: str
    template_id: Optional[str] = None
    description: Optional[str] = None
    matcher_name: Optional[str] = None
    evidence: list[Evidence] = Field(default_factory=list)
    validation_status: ValidationStatus = ValidationStatus.DISCOVERED
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    occurrence_count: int = 1

    @model_validator(mode="after")
    def set_dedup_key(self) -> "Finding":
        if not self.dedup_key:
            key_parts = (
                f"{self.target_domain}:{self.finding_type}"
                f":{self.title}:{self.url or ''}:{self.template_id or ''}"
            )
            self.dedup_key = hashlib.sha256(key_parts.encode()).hexdigest()[:32]
        return self
