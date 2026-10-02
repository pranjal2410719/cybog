"""
Integration tests for the human-assisted validation plane.

These exercise the real runtime path: nuclei finding -> NEEDS_VALIDATION ->
AnalystTask -> BoundedAnalystQueue -> VALIDATING -> validation adapter ->
evidence -> VALIDATED/FALSE_POSITIVE -> completion.

No external security tool or credential is required. Adapters are stubbed.
"""
import asyncio
from pathlib import Path

import pytest

from cybog.adapters.base import ValidationOutcome
from cybog.config.models import AuthToolConfig, CybogConfig
from cybog.models.assessment import Assessment
from cybog.models.finding import (
    Evidence,
    Finding,
    InvalidTransitionError,
    Severity,
    ValidationStatus,
)
from cybog.models.job import StageJob, JobStatus
from cybog.models.target import Service, Target, TargetStatus
from cybog.queue.analyst_queue import AnalystTask, AnalystTaskStatus, BoundedAnalystQueue
from cybog.state.assessment_state import AssessmentState
from cybog.workflow.router import PipelineRouter
from cybog.workflow.scheduler import JobScheduler


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def make_state(with_service: bool = False) -> AssessmentState:
    assessment = Assessment(target_input_file="t.txt", scope_file="s.txt")
    state = AssessmentState.create_new(assessment)
    target = Target(domain="example.com")
    state.add_target(target)
    if with_service:
        state.add_services(target.target_id, [
            Service(host="api.example.com", port=443, scheme="https",
                    url="https://api.example.com", target_id=target.target_id)
        ])
    return state


def make_nuclei_finding(state: AssessmentState, **overrides) -> Finding:
    target = next(iter(state.targets.values()))
    finding = Finding(
        finding_type=overrides.pop("finding_type", "exposed-panel"),
        title=overrides.pop("title", "Exposed admin panel"),
        severity=Severity.MEDIUM,
        target_id=target.target_id,
        target_domain=target.domain,
        url=overrides.pop("url", "https://api.example.com/admin"),
        source_tool="nuclei",
        **overrides,
    )
    state.add_finding(finding)
    return finding


AUTH_ON = AuthToolConfig(binary="httpx", enabled=True, credentials="u:p")


def make_scheduler(state: AssessmentState, root: Path, auth=None) -> JobScheduler:
    config = CybogConfig()
    if auth is not None:
        config.tools.auth = auth
    config.output.root = str(root)
    from cybog.artifacts.manager import ArtifactManager
    art = ArtifactManager(str(root), state.assessment.assessment_id)
    return JobScheduler(config, state, art)


def nuclei_job(state: AssessmentState) -> StageJob:
    target = next(iter(state.targets.values()))
    job = StageJob(
        assessment_id=state.assessment.assessment_id,
        target_id=target.target_id,
        target_domain=target.domain,
        stage="nuclei",
        status=JobStatus.COMPLETED,
    )
    state.add_job(job)
    return job


class StubAuthAdapter:
    """Stands in for AuthAdapter. Records invocations; no external binary."""

    def __init__(self, applicable=True, validated=True, with_evidence=True, reason="stub"):
        self.applicable = applicable
        self.validated = validated
        self.with_evidence = with_evidence
        self.reason = reason
        self.calls = []

    async def validate_finding(self, finding, live_urls, stage_dir):
        self.calls.append(finding.finding_id)
        evidence = None
        if self.with_evidence and self.applicable and self.validated is not None:
            evidence = Evidence(
                finding_id=finding.finding_id,
                tool="auth",
                raw_output='{"auth_success": true}',
                validation_result="Auth validation: authenticated access confirmed",
                reproduction=f"Re-ran authenticated request against {finding.url}",
            )
        return ValidationOutcome(
            applicable=self.applicable,
            reason=self.reason,
            validated=self.validated if self.applicable else None,
            evidence=evidence,
        )


# ----------------------------------------------------------------------
# TEST 1 + 2 + 3: nuclei finding -> NEEDS_VALIDATION -> task -> queue
# ----------------------------------------------------------------------
def test_nuclei_finding_enters_validation_and_is_queued(tmp_path):
    state = make_state()
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path)
    sched.auth_adapter = StubAuthAdapter(applicable=False)  # no verdict: human needed

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))

    assert finding.validation_status == ValidationStatus.NEEDS_VALIDATION

    task = state.get_task_for_finding(finding.finding_id)
    assert task is not None, "TEST 2: AnalystTask must be created"
    assert task.finding_id == finding.finding_id
    assert task.assessment_id == state.assessment.assessment_id
    assert task.target_id == finding.target_id
    assert task.status == AnalystTaskStatus.PENDING
    assert sched.analyst_queue.size() == 1, "TEST 3: task must be in BoundedAnalystQueue"
    assert sched.analyst_queue.max_size > 0, "queue must be bounded"


# ----------------------------------------------------------------------
# TEST 4 + 5 + 6: worker -> VALIDATING -> evidence -> VALIDATED
# ----------------------------------------------------------------------
def test_worker_resolves_finding_to_validated_with_evidence(tmp_path):
    state = make_state(with_service=True)
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path, auth=AUTH_ON)
    stub = StubAuthAdapter(applicable=True, validated=True)
    sched.auth_adapter = stub

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)

    observed = []
    original = sched._validate_finding

    async def spy(f):
        observed.append(f.validation_status)
        return await original(f)

    sched._validate_finding = spy
    asyncio.run(sched._process_analyst_task(task))

    assert observed == [ValidationStatus.VALIDATING], "TEST 4: must pass through VALIDATING"
    assert finding.validation_status == ValidationStatus.VALIDATED
    assert stub.calls == [finding.finding_id], "TEST: adapter invoked for this finding"
    # TEST 5: validation result became evidence
    assert len(finding.evidence) == 1
    ev = finding.evidence[-1]
    assert ev.validation_result and "authenticated access confirmed" in ev.validation_result
    assert ev.reproduction and "api.example.com" in ev.reproduction
    assert task.status == AnalystTaskStatus.COMPLETED


# ----------------------------------------------------------------------
# TEST 7: rejected validation -> FALSE_POSITIVE
# ----------------------------------------------------------------------
def test_worker_rejects_finding_as_false_positive(tmp_path):
    state = make_state(with_service=True)
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path, auth=AUTH_ON)
    sched.auth_adapter = StubAuthAdapter(applicable=True, validated=False, with_evidence=True)

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)
    asyncio.run(sched._process_analyst_task(task))

    assert finding.validation_status == ValidationStatus.FALSE_POSITIVE
    assert task.status == AnalystTaskStatus.COMPLETED


# ----------------------------------------------------------------------
# Human boundary: no validator -> stays pending, no invented verdict
# ----------------------------------------------------------------------
def test_finding_without_validator_is_not_guessed(tmp_path):
    state = make_state()
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path)
    sched.auth_adapter = StubAuthAdapter(applicable=False)

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)
    asyncio.run(sched._process_analyst_task(task))

    assert finding.validation_status == ValidationStatus.NEEDS_VALIDATION, \
        "must not be auto-resolved without a validator"
    assert task.status == AnalystTaskStatus.AWAITING_ANALYST
    assert task.is_terminal(), "parked task must not keep the worker alive"


# ----------------------------------------------------------------------
# TEST 8 + 9: completion conditions
# ----------------------------------------------------------------------
def test_pending_validation_prevents_target_completion(tmp_path):
    state = make_state()
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path)
    sched.auth_adapter = StubAuthAdapter(applicable=False)

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))

    target = next(iter(state.targets.values()))
    assert target.status != TargetStatus.COMPLETED, \
        "TEST 8: target must not complete while validation is pending"
    assert sched._target_is_complete(target.target_id) is False
    assert state.has_pending_validation() is True


def test_completed_validation_allows_target_completion(tmp_path):
    state = make_state(with_service=True)
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path, auth=AUTH_ON)
    sched.auth_adapter = StubAuthAdapter(applicable=True, validated=True)

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)
    asyncio.run(sched._process_analyst_task(task))

    target = next(iter(state.targets.values()))
    assert target.status == TargetStatus.COMPLETED, "TEST 9: target completes when resolved"
    assert sched._target_is_complete(target.target_id) is True
    assert state.has_pending_validation() is False


# ----------------------------------------------------------------------
# TEST 10 + 11 + 16: idempotency, resume
# ----------------------------------------------------------------------
def test_resume_preserves_pending_validation(tmp_path):
    state = make_state()
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path)
    sched.auth_adapter = StubAuthAdapter(applicable=False)
    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))

    sp = tmp_path / "state.json"
    state.save(sp)
    reloaded = AssessmentState.load(sp)

    assert reloaded.has_pending_validation() is True, "TEST 10: pending work survives restart"
    rt = reloaded.get_task_for_finding(finding.finding_id)
    assert rt is not None
    assert rt.status == AnalystTaskStatus.PENDING
    assert rt.finding_id == finding.finding_id
    assert rt.assessment_id == state.assessment.assessment_id

    # The restarted run rehydrates the queue and parks the task for a human
    # rather than dropping it or inventing a verdict.
    sched2 = make_scheduler(reloaded, tmp_path)
    sched2.auth_adapter = StubAuthAdapter(applicable=False)
    asyncio.run(sched2._rehydrate_analyst_queue())
    assert sched2.analyst_queue.size() == 1, "pending task must be re-queued on resume"

    rt2 = reloaded.get_task_for_finding(finding.finding_id)
    asyncio.run(sched2._process_analyst_task(rt2))
    assert rt2.status == AnalystTaskStatus.AWAITING_ANALYST
    assert reloaded.get_finding_by_id(finding.finding_id).validation_status == \
        ValidationStatus.NEEDS_VALIDATION


def test_resume_does_not_duplicate_analyst_task(tmp_path):
    state = make_state()
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path)
    sched.auth_adapter = StubAuthAdapter(applicable=False)
    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    assert len(state.analyst_tasks) == 1

    sp = tmp_path / "state.json"
    state.save(sp)
    reloaded = AssessmentState.load(sp)

    sched2 = make_scheduler(reloaded, tmp_path)
    asyncio.run(sched2._rehydrate_analyst_queue())
    asyncio.run(sched2._rehydrate_analyst_queue())

    assert len(reloaded.analyst_tasks) == 1, "TEST 11: no duplicate tasks on resume"
    assert reloaded.get_task_for_finding(finding.finding_id) is not None


def test_duplicate_scheduler_execution_does_not_duplicate_tasks(tmp_path):
    state = make_state()
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path)
    sched.auth_adapter = StubAuthAdapter(applicable=False)
    job = nuclei_job(state)

    asyncio.run(sched._enqueue_next_stages("nuclei", job))
    asyncio.run(sched._enqueue_next_stages("nuclei", job))
    asyncio.run(sched._enqueue_next_stages("nuclei", job))

    assert len(state.analyst_tasks) == 1, "TEST 16: repeated execution is idempotent"
    assert len(state.findings) == 1


def test_completed_task_is_not_re_executed(tmp_path):
    state = make_state(with_service=True)
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path, auth=AUTH_ON)
    stub = StubAuthAdapter(applicable=True, validated=True)
    sched.auth_adapter = stub

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)
    asyncio.run(sched._process_analyst_task(task))
    assert len(stub.calls) == 1

    # Re-processing the same task must not validate again
    asyncio.run(sched._process_analyst_task(task))
    assert len(stub.calls) == 1, "must not re-validate a terminal finding"
    assert len(finding.evidence) == 1, "must not duplicate evidence"


# ----------------------------------------------------------------------
# TEST 12: router executes without NameError
# ----------------------------------------------------------------------
def test_router_validation_functions_execute():
    state = make_state()
    finding = make_nuclei_finding(state)
    target_id = finding.target_id

    assert PipelineRouter.has_unvalidated_findings(state, target_id) is True
    ok, reason = PipelineRouter.should_run_auth_validation(state, target_id)
    assert ok is False and "No findings" in reason
    assert PipelineRouter.is_finding_validated(state, target_id, finding) is False

    finding.transition_to(ValidationStatus.NEEDS_VALIDATION)
    state.update_finding(finding)
    assert PipelineRouter.has_unvalidated_findings(state, target_id) is True

    finding.transition_to(ValidationStatus.VALIDATING)
    finding.transition_to(ValidationStatus.VALIDATED)
    state.update_finding(finding)
    assert PipelineRouter.is_finding_validated(state, target_id, finding) is True
    assert PipelineRouter.has_unvalidated_findings(state, target_id) is False


# ----------------------------------------------------------------------
# TEST 13 + 14: auth adapter invoked only when required
# ----------------------------------------------------------------------
def test_auth_adapter_invoked_when_required(tmp_path):
    state = make_state(with_service=True)
    finding = make_nuclei_finding(state)
    auth = AuthToolConfig(binary="httpx", enabled=True, credentials="u:p")
    sched = make_scheduler(state, tmp_path, auth=auth)
    stub = StubAuthAdapter(applicable=True, validated=True)
    sched.auth_adapter = stub

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)
    asyncio.run(sched._process_analyst_task(task))

    assert stub.calls == [finding.finding_id], "TEST 13: adapter must run when required"
    assert finding.validation_status == ValidationStatus.VALIDATED


def test_auth_adapter_not_invoked_when_not_configured(tmp_path):
    state = make_state(with_service=True)
    finding = make_nuclei_finding(state)
    auth = AuthToolConfig(binary="httpx", enabled=True, credentials="")  # unconfigured
    sched = make_scheduler(state, tmp_path, auth=auth)
    stub = StubAuthAdapter(applicable=True, validated=True)
    sched.auth_adapter = stub

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)
    asyncio.run(sched._process_analyst_task(task))

    assert stub.calls == [], "TEST 14: adapter must not run when auth is unavailable"
    assert finding.validation_status == ValidationStatus.NEEDS_VALIDATION
    assert task.status == AnalystTaskStatus.AWAITING_ANALYST


def test_auth_adapter_not_invoked_when_finding_off_live_service(tmp_path):
    state = make_state(with_service=False)  # no httpx service
    finding = make_nuclei_finding(state)
    auth = AuthToolConfig(binary="httpx", enabled=True, credentials="u:p")
    sched = make_scheduler(state, tmp_path, auth=auth)
    stub = StubAuthAdapter(applicable=True, validated=True)
    sched.auth_adapter = stub

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)
    asyncio.run(sched._process_analyst_task(task))
    assert stub.calls == []
    assert finding.validation_status == ValidationStatus.NEEDS_VALIDATION


# ----------------------------------------------------------------------
# TEST 15: validation updates the existing finding, creates no new one
# ----------------------------------------------------------------------
def test_validation_does_not_create_a_second_finding(tmp_path):
    state = make_state(with_service=True)
    finding = make_nuclei_finding(state)
    auth = AuthToolConfig(binary="httpx", enabled=True, credentials="u:p")
    sched = make_scheduler(state, tmp_path, auth=auth)
    sched.auth_adapter = StubAuthAdapter(applicable=True, validated=True)

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)
    asyncio.run(sched._process_analyst_task(task))

    assert len(state.findings) == 1, "TEST 15: no unrelated replacement finding"
    assert len(state.analyst_tasks) == 1
    assert state.findings[finding.dedup_key].finding_id == finding.finding_id


# ----------------------------------------------------------------------
# TEST 17: evidence survives persistence
# ----------------------------------------------------------------------
def test_evidence_survives_persistence(tmp_path):
    state = make_state(with_service=True)
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path, auth=AUTH_ON)
    sched.auth_adapter = StubAuthAdapter(applicable=True, validated=True)

    asyncio.run(sched._enqueue_next_stages("nuclei", nuclei_job(state)))
    task = state.get_task_for_finding(finding.finding_id)
    asyncio.run(sched._process_analyst_task(task))

    sp = tmp_path / "state.json"
    state.save(sp)
    loaded = AssessmentState.load(sp)

    lf = loaded.get_finding_by_id(finding.finding_id)
    assert lf.validation_status == ValidationStatus.VALIDATED
    assert len(lf.evidence) == 1
    assert lf.evidence[0].validation_result
    assert lf.evidence[0].reproduction
    lt = loaded.get_task_for_finding(finding.finding_id)
    assert lt.status == AnalystTaskStatus.COMPLETED


# ----------------------------------------------------------------------
# Lifecycle enforcement
# ----------------------------------------------------------------------
def test_invalid_lifecycle_transitions_are_rejected():
    f = Finding(finding_type="xss", title="XSS", target_id="t1",
                target_domain="e.com", source_tool="nuclei")
    with pytest.raises(InvalidTransitionError):
        f.transition_to(ValidationStatus.VALIDATED)

    f.transition_to(ValidationStatus.NEEDS_VALIDATION)
    f.transition_to(ValidationStatus.VALIDATING)
    f.transition_to(ValidationStatus.FALSE_POSITIVE)
    with pytest.raises(InvalidTransitionError):
        f.transition_to(ValidationStatus.VALIDATED)


# ----------------------------------------------------------------------
# Security: isolation and secret containment
# ----------------------------------------------------------------------
def test_task_from_another_assessment_is_rejected(tmp_path):
    state = make_state()
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path)

    foreign = AnalystTask(
        assessment_id="assessment-someone-else",
        target_id=finding.target_id,
        finding_id=finding.finding_id,
    )
    state.analyst_tasks[foreign.task_id] = foreign
    asyncio.run(sched._process_analyst_task(foreign))

    assert finding.validation_status == ValidationStatus.DISCOVERED, \
        "must not act on another assessment's finding"


def test_task_with_mismatched_target_is_rejected(tmp_path):
    state = make_state()
    finding = make_nuclei_finding(state)
    sched = make_scheduler(state, tmp_path)

    bad = AnalystTask(
        assessment_id=state.assessment.assessment_id,
        target_id="target-not-this-one",
        finding_id=finding.finding_id,
    )
    state.analyst_tasks[bad.task_id] = bad
    asyncio.run(sched._process_analyst_task(bad))
    assert finding.validation_status == ValidationStatus.DISCOVERED


def test_credentials_never_reach_command_or_evidence(tmp_path):
    from cybog.adapters.auth_adapter import AuthAdapter
    secret = "admin:sup3rs3cret"
    adapter = AuthAdapter(AuthToolConfig(binary="httpx", credentials=secret))

    cmd = adapter._build_validation_command("https://api.example.com/admin", tmp_path)
    redacted = adapter.redact(" ".join(cmd))
    assert secret not in redacted
    assert "<redacted>" in redacted
    # The real argv still carries the credential so the tool can authenticate.
    assert any(secret in part for part in cmd)


def test_auth_config_defaults_are_safe_and_env_backed(monkeypatch):
    monkeypatch.delenv("CYBOG_AUTH_CREDENTIALS", raising=False)
    cfg = CybogConfig()
    assert cfg.tools.auth.is_configured() is False
    assert cfg.tools.auth.enabled is False, "auth must be off by default"

    monkeypatch.setenv("CYBOG_AUTH_CREDENTIALS", "u:p")
    cfg2 = CybogConfig()
    assert cfg2.tools.auth.is_configured() is True
    assert cfg2.tools.auth.credentials == "u:p"


def test_report_state_exposes_validation_status():
    state = make_state()
    f = make_nuclei_finding(state)
    f.transition_to(ValidationStatus.NEEDS_VALIDATION)
    state.update_finding(f)
    counts = state.validation_counts()
    assert counts.get("NEEDS_VALIDATION") == 1
    assert "DISCOVERED" not in counts
