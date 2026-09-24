import pytest
from cybog.models.target import Target, Host, Service
from cybog.models.assessment import Assessment
from cybog.state.assessment_state import AssessmentState
from cybog.workflow.router import PipelineRouter

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
