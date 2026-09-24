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
