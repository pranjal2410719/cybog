import json
import pytest
from cybog.models.assessment import Assessment
from cybog.models.target import Target
from cybog.models.finding import Finding, Severity, ValidationStatus
from cybog.state.assessment_state import AssessmentState
from cybog.reporting import JSONReporter, JSONLReporter, HTMLReporter

def test_reporting_generation(tmp_path):
    assessment = Assessment(target_input_file="targets.txt", scope_file="scope.txt")
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)

    f = Finding(
        finding_type="xss",
        title="Reflected XSS",
        severity=Severity.HIGH,
        target_id=t.target_id,
        target_domain=t.domain,
        url="https://example.com/test",
        source_tool="nuclei"
    )
    state.add_finding(f)

    out_dir = tmp_path / "reports"
    
    # JSON
    json_path = JSONReporter().generate(state, out_dir)
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["assessment_id"] == assessment.assessment_id
    assert len(data["findings"]) == 1

    # JSONL
    jsonl_path = JSONLReporter().generate(state, out_dir)
    assert jsonl_path.exists()
    lines = [l for l in jsonl_path.read_text().splitlines() if l.strip()]
    assert len(lines) == 1

    # HTML
    html_path = HTMLReporter().generate(state, out_dir)
    assert html_path.exists()
    html_content = html_path.read_text()
    assert "Cybog Security Assessment Report" in html_content
    assert "Reflected XSS" in html_content


# ---------------------------------------------------------------------------
# PRD S27-S32, S55-S58: report state model + versioning
# ---------------------------------------------------------------------------
from cybog.reporting.report_model import (
    ReportState,
    ReportVersion,
    build_report_version,
)


def test_report_state_enum_has_4_states():
    states = {s.value for s in ReportState}
    assert states == {
        "PRELIMINARY",
        "UNDER_VALIDATION",
        "PARTIALLY_VERIFIED",
        "VERIFIED",
    }


def test_preliminary_report_has_disclaimer(tmp_path):
    """A state with a pending finding, generated as PRELIMINARY, carries the
    unverified disclaimer in both JSON and HTML output."""
    assessment = Assessment(target_input_file="targets.txt", scope_file="scope.txt")
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)

    f = Finding(
        finding_type="xss",
        title="Reflected XSS",
        severity=Severity.HIGH,
        target_id=t.target_id,
        target_domain=t.domain,
        url="https://example.com/test",
        source_tool="nuclei",
    )  # default validation_status is DISCOVERED -> pending
    state.add_finding(f)
    assert state.has_pending_validation()

    disclaimer = (
        "Automated analysis identified potential security issues. "
        "These findings have not yet been manually verified and "
        "should not be treated as confirmed vulnerabilities."
    )

    # JSON
    json_path = JSONReporter().generate(
        state, tmp_path / "json", version_state=ReportState.PRELIMINARY
    )
    data = json.loads(json_path.read_text())
    assert data["report_state"] == "PRELIMINARY"
    assert data["disclaimer"] == disclaimer

    # HTML banner
    html_path = HTMLReporter().generate(
        state, tmp_path / "html", version_state=ReportState.PRELIMINARY
    )
    html_content = html_path.read_text()
    assert "UNVERIFIED" in html_content
    assert "AUTOMATED ASSESSMENT" in html_content
    assert disclaimer in html_content


def test_verified_report_has_verified_badge(tmp_path):
    """A state with no pending findings, generated as VERIFIED, carries the
    verified badge and disclaimer in both JSON and HTML output."""
    assessment = Assessment(target_input_file="targets.txt", scope_file="scope.txt")
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)

    f = Finding(
        finding_type="xss",
        title="Reflected XSS",
        severity=Severity.HIGH,
        target_id=t.target_id,
        target_domain=t.domain,
        url="https://example.com/test",
        source_tool="nuclei",
    )
    # Move the finding out of the pending states so nothing is pending.
    f.transition_to(ValidationStatus.NEEDS_VALIDATION)
    f.transition_to(ValidationStatus.VALIDATING)
    f.transition_to(ValidationStatus.VALIDATED)
    f.transition_to(ValidationStatus.REPORTABLE)
    state.add_finding(f)
    assert not state.has_pending_validation()

    verified_disclaimer = (
        "These findings were manually verified by an authorized security analyst."
    )

    # JSON
    json_path = JSONReporter().generate(
        state, tmp_path / "json", version_state=ReportState.VERIFIED
    )
    data = json.loads(json_path.read_text())
    assert data["report_state"] == "VERIFIED"
    assert data["disclaimer"] == verified_disclaimer

    # HTML badge
    html_path = HTMLReporter().generate(
        state, tmp_path / "html", version_state=ReportState.VERIFIED
    )
    html_content = html_path.read_text()
    assert "VERIFIED" in html_content
    assert verified_disclaimer in html_content


def test_version_starts_at_1():
    rv = ReportVersion()
    assert rv.version == 1
    assert rv.state == ReportState.PRELIMINARY
    assert rv.generated_by == "automated"
    assert rv.path == ""
    assert rv.findings_summary == {}
    d = rv.to_dict()
    assert d["version"] == 1
    assert d["state"] == "PRELIMINARY"


def test_backward_compat_generate_without_version_state(tmp_path):
    """generate() must still be callable with no extra args (backward compat)."""
    assessment = Assessment(target_input_file="targets.txt", scope_file="scope.txt")
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)
    f = Finding(
        finding_type="xss",
        title="Reflected XSS",
        severity=Severity.HIGH,
        target_id=t.target_id,
        target_domain=t.domain,
        url="https://example.com/test",
        source_tool="nuclei",
    )
    state.add_finding(f)

    # No version_state -> auto-detect (pending finding => PRELIMINARY)
    json_path = JSONReporter().generate(state, tmp_path / "json")
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["report_state"] == "PRELIMINARY"

    html_path = HTMLReporter().generate(state, tmp_path / "html")
    assert html_path.exists()
    assert "UNVERIFIED" in html_path.read_text()


def test_build_report_version_reuses_json_reporter(tmp_path):
    assessment = Assessment(target_input_file="targets.txt", scope_file="scope.txt")
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)
    f = Finding(
        finding_type="xss",
        title="Reflected XSS",
        severity=Severity.HIGH,
        target_id=t.target_id,
        target_domain=t.domain,
        url="https://example.com/test",
        source_tool="nuclei",
    )
    state.add_finding(f)

    payload = build_report_version(state, ReportState.PRELIMINARY, generated_by="automated")
    assert payload["report_state"] == "PRELIMINARY"
    assert payload["version"] == 1
    assert payload["generated_by"] == "automated"
    assert "findings_summary" in payload
    assert payload["findings_summary"]["total"] == 1
