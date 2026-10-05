import pytest
from cybog.models.assessment import Assessment
from cybog.models.target import Target
from cybog.models.job import StageJob, JobStatus
from cybog.state.assessment_state import AssessmentState

def test_state_persistence_and_resume(tmp_path):
    state_file = tmp_path / "state.json"
    assessment = Assessment(
        target_input_file="targets.txt",
        scope_file="scope.txt"
    )
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)

    j1 = StageJob(
        assessment_id=assessment.assessment_id,
        target_id=t.target_id,
        target_domain=t.domain,
        stage="subfinder",
        status=JobStatus.COMPLETED
    )
    j2 = StageJob(
        assessment_id=assessment.assessment_id,
        target_id=t.target_id,
        target_domain=t.domain,
        stage="dnsx",
        status=JobStatus.RUNNING
    )
    state.add_job(j1)
    state.add_job(j2)

    # Save
    state.save(state_file)
    assert state_file.exists()

    # Load
    loaded = AssessmentState.load(state_file)
    assert loaded.assessment.assessment_id == assessment.assessment_id
    assert len(loaded.targets) == 1
    assert loaded.is_stage_completed(t.target_id, "subfinder") is True
    
    # Incomplete jobs detection for resume
    incomplete = loaded.get_incomplete_jobs()
    assert len(incomplete) == 1
    assert incomplete[0].stage == "dnsx"


def test_add_hosts_merges_ips_and_sources():
    assessment = Assessment(target_input_file="t.txt", scope_file="s.txt")
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)

    from cybog.models.target import Host, IP
    state.add_hosts(t.target_id, [
        Host(hostname="api.example.com", target_id=t.target_id, ips=["1.2.3.4"], sources=["subfinder"]),
        Host(hostname="mentor.example.com", target_id=t.target_id, sources=["subfinder"]),
    ])
    state.add_hosts(t.target_id, [
        Host(hostname="api.example.com", target_id=t.target_id, ips=["5.6.7.8"], sources=["dnsx"]),
        Host(hostname="new.example.com", target_id=t.target_id, ips=["9.9.9.9"], sources=["subfinder"]),
    ])

    all_hosts = state.hosts[t.target_id]
    by_name = {h.hostname: h for h in all_hosts}
    assert set(by_name) == {"api.example.com", "mentor.example.com", "new.example.com"}
    assert by_name["api.example.com"].ips == ["1.2.3.4", "5.6.7.8"]
    assert "subfinder" in by_name["api.example.com"].sources
    assert "dnsx" in by_name["api.example.com"].sources
    assert by_name["mentor.example.com"].ips == []
