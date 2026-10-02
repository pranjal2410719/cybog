import json
import pytest
from cybog.models.assessment import Assessment
from cybog.models.target import Target
from cybog.models.finding import Finding, Severity
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
