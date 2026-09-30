import pytest
from cybog.models.target import Target, Host, Service
from cybog.models.assessment import Assessment
from cybog.state.assessment_state import AssessmentState
from cybog.workflow.router import PipelineRouter
from cybog.models.finding import Finding, Evidence, ValidationStatus, Severity


def test_pipeline_router_decisions():
    assessment = Assessment(target_input_file="t.txt", scope_file="s.txt")
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)

    router = PipelineRouter()

    # Step 1: Subfinder produced 0 hosts -> dnsx skipped
    should_dnsx, reason = router.should_run_dnsx(state, t.target_id)
    assert should_dnsx is False
    assert "0 subdomains" in reason

    # Now simulate subfinder produced a host
    state.add_hosts(t.target_id, [Host(hostname="api.example.com", target_id=t.target_id)])
    should_dnsx, _ = router.should_run_dnsx(state, t.target_id)
    assert should_dnsx is True

    # Step 2: Dnsx resolved host -> httpx & naabu should run
    should_httpx, _ = router.should_run_httpx(state, t.target_id)
    should_naabu, _ = router.should_run_naabu(state, t.target_id)
    assert should_httpx is True
    assert should_naabu is True

    # Step 3: No live services yet -> katana & ffuf should be skipped
    should_katana, _ = router.should_run_katana(state, t.target_id)
    assert should_katana is False

    # Simulate live service discovered by httpx
    state.add_services(t.target_id, [
        Service(host="api.example.com", port=443, scheme="https", url="https://api.example.com", target_id=t.target_id)
    ])
    should_katana, _ = router.should_run_katana(state, t.target_id)
    should_ffuf, _ = router.should_run_ffuf(state, t.target_id)
    assert should_katana is True
    assert should_ffuf is True


def test_finding_lifecycle_transitions():
    """Test that findings can transition through the validation lifecycle."""
    assessment = Assessment(target_input_file="t.txt", scope_file="s.txt")
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)

    # Create a finding with DISCOVERED status
    finding = Finding(
        finding_type="xss",
        title="Cross Site Scripting",
        severity=Severity.MEDIUM,
        target_id=t.target_id,
        target_domain=t.domain,
        url="https://example.com/test",
        source_tool="nuclei",
        validation_status=ValidationStatus.DISCOVERED,
    )
    state.add_finding(finding)

    # Verify starting state
    assert finding.validation_status == ValidationStatus.DISCOVERED

    # Transition to NEEDS_VALIDATION
    finding.validation_status = ValidationStatus.NEEDS_VALIDATION
    # Directly update the state's findings dict using the dedup key
    state.findings[finding.dedup_key] = finding

    # Transition to VALIDATING
    finding.validation_status = ValidationStatus.VALIDATING
    state.findings[finding.dedup_key] = finding

    # Transition to VALIDATED
    finding.validation_status = ValidationStatus.VALIDATED
    state.findings[finding.dedup_key] = finding

    # Check that finding state is preserved through resume
    import tempfile, os
    tmp = tempfile.mktemp(suffix=".json")
    state.save(tmp)
    loaded = AssessmentState.load(tmp)
    os.unlink(tmp)

    # Check that finding state is preserved through resume
    found = loaded.get_findings_for_target(t.target_id)[0]
    assert found.validation_status == ValidationStatus.VALIDATED


def test_evidence_model_expansion():
    """Test that Evidence model has the new fields."""
    from cybog.models.finding import Evidence

    e = Evidence(
        evidence_id="test1",
        finding_id="f1",
        tool="nuclei",
        raw_output="raw_output_test",
    )
    # New fields are optional, should default to None
    assert e.reproduction is None
    assert e.analyst_notes is None
    assert e.validation_result is None

    # Can set the new fields
    e.reproduction = "Reproduce XSS by injecting script"
    e.analyst_notes = "Notes about the finding"
    e.validation_result = "Confirmed XSS"
    assert e.reproduction == "Reproduce XSS by injecting script"
    assert e.analyst_notes == "Notes about the finding"
    assert e.validation_result == "Confirmed XSS"
