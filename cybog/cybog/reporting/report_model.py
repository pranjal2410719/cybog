"""
cybog/reporting/report_model.py

Report state model + versioning for Cybog (PRD S27-S32, S55-S58).

A report version is a snapshot of an AssessmentState at a point in time,
tagged with the level of confidence the operator should place in it:

    PRELIMINARY       - automated analysis, findings unverified
    UNDER_VALIDATION  - some findings verified, some still pending
    PARTIALLY_VERIFIED- a subset of findings has been verified
    VERIFIED          - all findings manually verified by an analyst
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from cybog.state.assessment_state import AssessmentState


class ReportState(str, Enum):
    """Confidence level of a generated report version."""

    PRELIMINARY = "PRELIMINARY"
    UNDER_VALIDATION = "UNDER_VALIDATION"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    VERIFIED = "VERIFIED"


@dataclass
class ReportVersion:
    """A single versioned snapshot of an assessment report."""

    version: int = 1
    state: ReportState = ReportState.PRELIMINARY
    generated_at: datetime = field(default_factory=datetime.utcnow)
    generated_by: str = "automated"
    findings_summary: dict = field(default_factory=dict)
    path: str = ""

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "state": self.state.value,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "findings_summary": self.findings_summary,
            "path": self.path,
        }


def auto_detect_report_state(state: AssessmentState) -> ReportState:
    """PRD S27-32: derive report state from the assessment's validation state."""
    if state.has_pending_validation():
        return ReportState.PRELIMINARY
    return ReportState.VERIFIED


def build_report_version(
    state: AssessmentState,
    version_state: Optional[ReportState] = None,
    generated_by: str = "automated",
) -> dict:
    """Return a report payload dict for the given version state."""
    from cybog.reporting.json_reporter import JSONReporter

    if version_state is None:
        version_state = auto_detect_report_state(state)

    reporter = JSONReporter()
    # Reuse JSONReporter._build_report so the payload (including the
    # report_state/disclaimer fields) stays consistent with JSON output.
    payload = reporter._build_report(state, version_state)
    payload["report_state"] = version_state.value

    # --- Versioning metadata (PRD S55-S58) ---
    payload["version"] = 1
    payload["generated_by"] = generated_by
    payload["generated_at"] = datetime.utcnow().isoformat()
    payload["findings_summary"] = {
        "total": len(state.findings),
        "by_severity": state.finding_counts_by_severity(),
        "by_validation_status": state.validation_counts(),
        "pending_validation": state.pending_validation_count(),
    }
    payload["path"] = ""
    return payload
