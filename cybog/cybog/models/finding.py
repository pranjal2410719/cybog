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
    NEEDS_VALIDATION = "NEEDS_VALIDATION"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REPORTABLE = "REPORTABLE"
    # PRD §24–§26: triage outcomes that exit the validation flow.
    DUPLICATE = "DUPLICATE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"


class Confidence(str, Enum):
    """PRD §26: automated confidence in the finding, distinct from validation."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


# The single authority for valid finding lifecycle transitions.
# Anything not listed here is rejected by Finding.transition_to().
ALLOWED_TRANSITIONS: dict[ValidationStatus, frozenset[ValidationStatus]] = {
    ValidationStatus.DISCOVERED: frozenset({ValidationStatus.NEEDS_VALIDATION}),
    ValidationStatus.NEEDS_VALIDATION: frozenset({
        ValidationStatus.VALIDATING,
        ValidationStatus.DUPLICATE,
        ValidationStatus.OUT_OF_SCOPE,
        ValidationStatus.NEEDS_INVESTIGATION,
    }),
    ValidationStatus.VALIDATING: frozenset({
        ValidationStatus.VALIDATED,
        ValidationStatus.FALSE_POSITIVE,
        ValidationStatus.DUPLICATE,
        ValidationStatus.OUT_OF_SCOPE,
        ValidationStatus.NEEDS_INVESTIGATION,
        # A validation attempt that cannot reach a verdict (no applicable
        # validator, or the tool failed) returns to the pending state rather
        # than guessing an outcome.
        ValidationStatus.NEEDS_VALIDATION,
    }),
    ValidationStatus.VALIDATED: frozenset({ValidationStatus.REPORTABLE}),
    ValidationStatus.FALSE_POSITIVE: frozenset(),
    ValidationStatus.REPORTABLE: frozenset(),
    ValidationStatus.DUPLICATE: frozenset(),
    ValidationStatus.OUT_OF_SCOPE: frozenset(),
    ValidationStatus.NEEDS_INVESTIGATION: frozenset({
        ValidationStatus.NEEDS_VALIDATION,
        ValidationStatus.VALIDATING,
    }),
}

# Statuses a finding can no longer move out of.
TERMINAL_VALIDATION_STATUSES = frozenset({
    ValidationStatus.VALIDATED,
    ValidationStatus.FALSE_POSITIVE,
    ValidationStatus.REPORTABLE,
    ValidationStatus.DUPLICATE,
    ValidationStatus.OUT_OF_SCOPE,
})


class InvalidTransitionError(ValueError):
    """Raised when a lifecycle transition is not permitted."""


class Evidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    finding_id: str
    tool: str
    raw_output: str
    request: Optional[str] = None
    response: Optional[str] = None
    artifact_path: Optional[str] = None
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    reproduction: Optional[str] = None
    analyst_notes: Optional[str] = None
    validation_result: Optional[str] = None


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
    attack_chain: Optional[str] = None  # dedup_key of related finding

    # --- PRD §24–§26 schema extension (all backward-compatible) ---
    confidence: Optional[Confidence] = None  # automated confidence (§26)
    analyst_id: Optional[str] = None  # UID of the analyst who validated (§24, §30)
    analyst_notes: Optional[str] = None  # analyst reasoning at finding level (§24)
    impact: Optional[str] = None  # impact statement (§24, §30)
    remediation: Optional[str] = None  # fix guidance (§24, §30)
    verification_method: Optional[str] = None  # how the analyst validated (§30)
    observed_behavior: Optional[str] = None  # what was observed (§30)
    source_tools: list[str] = Field(default_factory=list)  # PLURAL tool attribution (§24)
    affected_parameters: list[str] = Field(default_factory=list)  # PRD §24

    @model_validator(mode="after")
    def set_dedup_key(self) -> "Finding":
        if not self.dedup_key:
            key_parts = (
                f"{self.target_domain}:{self.finding_type}"
                f":{self.title}:{self.url or ''}:{self.template_id or ''}"
            )
            self.dedup_key = hashlib.sha256(key_parts.encode()).hexdigest()[:32]
        if not self.source_tools and self.source_tool:
            self.source_tools = [self.source_tool]
        return self

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def transition_to(self, new_status: ValidationStatus) -> "Finding":
        """
        Move this finding to new_status, enforcing the lifecycle.

        The full lifecycle is:
            DISCOVERED -> NEEDS_VALIDATION -> VALIDATING -> VALIDATED
                                                        -> FALSE_POSITIVE
            VALIDATED  -> REPORTABLE

        Anything not in ALLOWED_TRANSITIONS raises InvalidTransitionError.
        This is the only supported way to change validation_status; assigning
        the attribute directly bypasses enforcement.
        """
        if new_status is self.validation_status:
            return self
        allowed = ALLOWED_TRANSITIONS.get(self.validation_status, frozenset())
        if new_status not in allowed:
            raise InvalidTransitionError(
                f"Invalid transition {self.validation_status.value} -> "
                f"{new_status.value} for finding {self.finding_id} "
                f"(allowed: {sorted(s.value for s in allowed) or 'none'})"
            )
        self.validation_status = new_status
        return self

    def is_terminal(self) -> bool:
        """True if this finding has reached a final validation state."""
        return self.validation_status in TERMINAL_VALIDATION_STATUSES

    def is_pending_validation(self) -> bool:
        """True if this finding still requires validation work."""
        return self.validation_status in (
            ValidationStatus.DISCOVERED,
            ValidationStatus.NEEDS_VALIDATION,
            ValidationStatus.VALIDATING,
        )
