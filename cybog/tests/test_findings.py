import asyncio
import pytest
from cybog.models.assessment import AssessmentStatus
from cybog.models.finding import (
    ALLOWED_TRANSITIONS,
    Confidence,
    Finding,
    InvalidTransitionError,
    Severity,
    TERMINAL_VALIDATION_STATUSES,
    ValidationStatus,
)
from cybog.findings.deduplicator import FindingDeduplicator


def test_deduplicator():
    async def _run():
        dedup = FindingDeduplicator()

        f1 = Finding(
            finding_type="xss",
            title="Cross Site Scripting",
            severity=Severity.HIGH,
            target_id="t1",
            target_domain="example.com",
            url="https://example.com/search?q=1",
            source_tool="nuclei",
        )

        f2 = Finding(
            finding_type="xss",
            title="Cross Site Scripting",
            severity=Severity.HIGH,
            target_id="t1",
            target_domain="example.com",
            url="https://example.com/search?q=1",
            source_tool="nuclei",
        )

        is_new_1 = await dedup.add(f1)
        assert is_new_1 is True

        is_new_2 = await dedup.add(f2)
        assert is_new_2 is False

        unique = await dedup.get_unique()
        assert len(unique) == 1
        assert unique[0].occurrence_count == 2

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# PRD v2.0 §24–§26, §64 schema extension tests
# ---------------------------------------------------------------------------
def _make_finding(**overrides):
    base = dict(
        finding_type="xss",
        title="Cross Site Scripting",
        severity=Severity.HIGH,
        target_id="t1",
        target_domain="example.com",
        url="https://example.com/search?q=1",
        source_tool="nuclei",
    )
    base.update(overrides)
    return Finding(**base)


def test_confidence_enum_values():
    assert {c.value for c in Confidence} == {"high", "medium", "low", "unknown"}
    assert len(list(Confidence)) == 4


def test_new_validation_status_states_exist():
    assert ValidationStatus.DUPLICATE.value == "DUPLICATE"
    assert ValidationStatus.OUT_OF_SCOPE.value == "OUT_OF_SCOPE"
    assert ValidationStatus.NEEDS_INVESTIGATION.value == "NEEDS_INVESTIGATION"


def test_new_states_are_terminal():
    assert ValidationStatus.DUPLICATE in TERMINAL_VALIDATION_STATUSES
    assert ValidationStatus.OUT_OF_SCOPE in TERMINAL_VALIDATION_STATUSES
    assert ValidationStatus.NEEDS_INVESTIGATION not in TERMINAL_VALIDATION_STATUSES


def test_duplicate_and_out_of_scope_cannot_transition():
    f = _make_finding()
    f.transition_to(ValidationStatus.NEEDS_VALIDATION)
    f.transition_to(ValidationStatus.DUPLICATE)
    assert f.is_terminal()
    with pytest.raises(InvalidTransitionError):
        f.transition_to(ValidationStatus.VALIDATING)

    g = _make_finding()
    g.transition_to(ValidationStatus.NEEDS_VALIDATION)
    g.transition_to(ValidationStatus.OUT_OF_SCOPE)
    assert g.is_terminal()
    with pytest.raises(InvalidTransitionError):
        g.transition_to(ValidationStatus.VALIDATED)


def test_needs_validation_can_reach_new_states():
    f = _make_finding()
    f.transition_to(ValidationStatus.NEEDS_VALIDATION)
    assert ValidationStatus.DUPLICATE in ALLOWED_TRANSITIONS[ValidationStatus.NEEDS_VALIDATION]
    assert ValidationStatus.OUT_OF_SCOPE in ALLOWED_TRANSITIONS[ValidationStatus.NEEDS_VALIDATION]
    assert ValidationStatus.NEEDS_INVESTIGATION in ALLOWED_TRANSITIONS[ValidationStatus.NEEDS_VALIDATION]

    f.transition_to(ValidationStatus.DUPLICATE)
    assert f.validation_status == ValidationStatus.DUPLICATE

    g = _make_finding()
    g.transition_to(ValidationStatus.NEEDS_VALIDATION)
    g.transition_to(ValidationStatus.OUT_OF_SCOPE)
    assert g.validation_status == ValidationStatus.OUT_OF_SCOPE

    h = _make_finding()
    h.transition_to(ValidationStatus.NEEDS_VALIDATION)
    h.transition_to(ValidationStatus.NEEDS_INVESTIGATION)
    assert h.validation_status == ValidationStatus.NEEDS_INVESTIGATION


def test_round_trip_validation_flow():
    f = _make_finding()
    f.transition_to(ValidationStatus.NEEDS_VALIDATION)
    f.transition_to(ValidationStatus.VALIDATING)
    f.transition_to(ValidationStatus.NEEDS_INVESTIGATION)
    f.transition_to(ValidationStatus.NEEDS_VALIDATION)
    f.transition_to(ValidationStatus.VALIDATING)
    f.transition_to(ValidationStatus.VALIDATED)
    f.transition_to(ValidationStatus.REPORTABLE)
    assert f.validation_status == ValidationStatus.REPORTABLE
    assert f.is_terminal()


def test_backward_compat_old_fields_only():
    d = dict(
        finding_type="sqli",
        title="SQL Injection",
        severity="high",
        target_id="t2",
        target_domain="victim.com",
        url="https://victim.com/login",
        source_tool="nuclei",
    )
    f = Finding(**d)
    assert f.confidence is None
    assert f.analyst_id is None
    assert f.analyst_notes is None
    assert f.impact is None
    assert f.remediation is None
    assert f.verification_method is None
    assert f.observed_behavior is None
    assert f.source_tools == ["nuclei"]
    assert f.affected_parameters == []
    # dedup_key still populated by the existing validator
    assert f.dedup_key


def test_source_tools_populated_from_source_tool():
    f = _make_finding()
    assert f.source_tools == ["nuclei"]

    f2 = _make_finding(source_tool="httpx", source_tools=["katana", "ffuf"])
    assert f2.source_tools == ["katana", "ffuf"]


def test_partially_completed_is_valid_assessment_status():
    assert AssessmentStatus.PARTIALLY_COMPLETED.value == "PARTIALLY_COMPLETED"
    assert AssessmentStatus("PARTIALLY_COMPLETED") is AssessmentStatus.PARTIALLY_COMPLETED
    # existing states still intact
    assert {s.value for s in AssessmentStatus} >= {
        "CREATED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED",
        "RESUMING", "AWAITING_VALIDATION", "PARTIALLY_COMPLETED",
    }
