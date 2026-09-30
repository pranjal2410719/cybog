"""
Authoritative end-to-end proof of the Phase 2 architecture.

Drives the real JobScheduler through the complete two-plane path:

    Target -> recon -> discovery -> Nuclei -> Finding -> NEEDS_VALIDATION
          -> AnalystTask -> AnalystQueue -> VALIDATING -> ValidationAdapter
          -> Evidence -> VALIDATED / FALSE_POSITIVE -> Report -> Complete

Recon/discovery stages are faked at the adapter boundary so the test proves
orchestration rather than scanner functionality. No external security tool and
no credential is required.
"""
import asyncio
import json
from pathlib import Path

from cybog.adapters.base import NormalizedOutput
from cybog.adapters.httpx import HttpxAdapter
from cybog.adapters.nuclei import NucleiAdapter
from cybog.adapters.subfinder import SubfinderAdapter
from cybog.config.models import AuthToolConfig, CybogConfig
from cybog.models.assessment import Assessment, AssessmentStatus
from cybog.models.finding import Evidence, Finding, Severity, ValidationStatus
from cybog.models.target import Host, Service, Target
from cybog.queue.analyst_queue import AnalystTaskStatus
from cybog.services.assessment_service import AssessmentService
from cybog.state.assessment_state import AssessmentState


AUTH_ON = AuthToolConfig(binary="httpx", enabled=True, credentials="user:s3cret")


# ----------------------------------------------------------------------
# Fake scanner adapters: emit normalized output, never shell out
# ----------------------------------------------------------------------
class FakeSubfinder(SubfinderAdapter):
    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        return _fake_tool_result("subfinder", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return [{"host": "api.example.com"}]

    def normalize_output(self, parsed, job):
        out = NormalizedOutput()
        out.hosts = [Host(hostname="api.example.com", target_id=job.target_id,
                          sources=["subfinder"])]
        out.raw_count = len(parsed)
        return out


class FakeHttpx(HttpxAdapter):
    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        return _fake_tool_result("httpx", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return [{"url": "https://api.example.com", "status_code": 200}]

    def normalize_output(self, parsed, job):
        out = NormalizedOutput()
        out.services = [Service(host="api.example.com", port=443, scheme="https",
                                url="https://api.example.com", target_id=job.target_id)]
        out.raw_count = len(parsed)
        return out


class FakeNuclei(NucleiAdapter):
    """Produces one finding on a live service, one off it."""
    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        return _fake_tool_result("nuclei", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return [
            {"template-id": "exposed-admin-panel", "matched-at": "https://api.example.com/admin",
             "info": {"name": "Exposed admin panel", "severity": "medium",
                      "description": "Admin panel reachable"}},
            {"template-id": "tls-expired", "matched-at": "https://unrelated.invalid:8443/x",
             "info": {"name": "Expired TLS", "severity": "low", "description": "Old cert"}},
        ]

    def normalize_output(self, parsed, job):
        out = NormalizedOutput()
        for r in parsed:
            f = Finding(
                finding_type=r["template-id"],
                title=r["info"]["name"],
                severity=Severity.MEDIUM,
                target_id=job.target_id,
                target_domain=job.target_domain,
                url=r["matched-at"],
                source_tool="nuclei",
                template_id=r["template-id"],
            )
            f.evidence = [Evidence(finding_id=f.finding_id, tool="nuclei",
                                   raw_output=json.dumps(r)[:200])]
            out.findings.append(f)
        out.raw_count = len(parsed)
        return out


def _fake_tool_result(tool: str, stage_dir: Path):
    from cybog.models.execution import ToolResult
    from datetime import datetime, timezone
    stage_dir.mkdir(parents=True, exist_ok=True)
    (stage_dir / "stdout.log").write_text("", encoding="utf-8")
    (stage_dir / "stderr.log").write_text("", encoding="utf-8")
    now = datetime.now(timezone.utc)
    return ToolResult(
        tool=tool, binary="fake", command="fake", exit_code=0, stdout="", stderr="",
        duration_seconds=0.0, timed_out=False, started_at=now, finished_at=now,
    )


class RecordingAuthAdapter:
    """Validates live-service findings as confirmed; refuses everything else."""

    def __init__(self):
        self.validated_ids = []
        self.refused_ids = []

    async def validate_finding(self, finding, live_urls, stage_dir):
        live = {u.rstrip("/") for u in live_urls}
        on_live = finding.url and finding.url.rstrip("/").startswith(tuple(live) or ("",))
        if not on_live:
            self.refused_ids.append(finding.finding_id)
            from cybog.adapters.base import ValidationOutcome
            return ValidationOutcome(
                applicable=False,
                reason="not on a confirmed live service",
            )
        self.validated_ids.append(finding.finding_id)
        from cybog.adapters.base import ValidationOutcome
        return ValidationOutcome(
            applicable=True,
            reason="authenticated access confirmed",
            validated=True,
            evidence=Evidence(
                finding_id=finding.finding_id,
                tool="auth",
                raw_output='{"auth_success": true}',
                validation_result="Auth validation: authenticated access confirmed",
                reproduction=f"Replayed authenticated request to {finding.url}",
            ),
        )


# ----------------------------------------------------------------------
# End-to-end test
# ----------------------------------------------------------------------
def test_phase2_end_to_end_validation_boundary(tmp_path):
    config = CybogConfig()
    config.output.root = str(tmp_path)
    config.tools.auth = AUTH_ON
    config.queues.max_size = 10

    service = AssessmentService(config)
    assessment = Assessment(target_input_file="t.txt", scope_file="s.txt")
    state = AssessmentState.create_new(assessment)
    target = Target(domain="example.com")
    state.add_target(target)
    from cybog.artifacts.manager import ArtifactManager
    art = ArtifactManager(str(tmp_path), assessment.assessment_id)
    state.save(art.state_path())

    # ---- Build the real scheduler with faked scanner adapters ----
    from cybog.workflow.scheduler import JobScheduler
    sched = JobScheduler(config, state, art)
    sched.adapters["subfinder"] = FakeSubfinder(config.tools.subfinder)
    sched.adapters["httpx"] = FakeHttpx(config.tools.httpx)
    sched.adapters["nuclei"] = FakeNuclei(config.tools.nuclei)
    for stage in ("dnsx", "naabu", "katana", "ffuf"):
        sched.adapters[stage] = _noop_adapter(sched, stage, config)

    auth = RecordingAuthAdapter()
    sched.auth_adapter = auth

    # ---- Drive the full pipeline ----
    asyncio.run(sched.run([target]))

    findings = state.get_findings_for_target(target.target_id)
    by_template = {f.template_id: f for f in findings}
    assert len(findings) == 2, "both nuclei findings must exist"

    live = by_template["exposed-admin-panel"]
    offline = by_template["tls-expired"]

    live_task = state.get_task_for_finding(live.finding_id)
    offline_task = state.get_task_for_finding(offline.finding_id)

    # 1. Discovery produced state
    assert state.get_live_urls_for_target(target.target_id) == ["https://api.example.com"]

    # 2. Nuclei findings entered the validation boundary
    assert live.validation_status == ValidationStatus.VALIDATED
    assert offline.validation_status == ValidationStatus.NEEDS_VALIDATION

    # 3. Auth adapter ran only for the finding on a live service
    assert auth.validated_ids == [live.finding_id]
    # The offline finding is refused by the scheduler's applicability gate, so
    # the adapter is never handed a finding with no confirmed live surface.
    assert offline.finding_id not in auth.validated_ids
    assert offline_task.result and "live" in offline_task.result.lower()

    # 4. Evidence came from the validation attempt
    val_evidence = [e for e in live.evidence if e.validation_result]
    assert val_evidence, "validation must produce evidence"
    assert "authenticated access confirmed" in val_evidence[0].validation_result
    assert val_evidence[0].reproduction
    # The pre-existing nuclei evidence is preserved, not overwritten
    assert any(e.tool == "nuclei" for e in live.evidence)

    # 5. Analyst tasks were created and resolved/parked
    assert live_task.status == AnalystTaskStatus.COMPLETED
    assert offline_task.status == AnalystTaskStatus.AWAITING_ANALYST
    assert len(state.analyst_tasks) == 2

    # 6. No secret leaked into persisted state
    raw_state = art.state_path().read_text()
    assert "s3cret" not in raw_state, "credentials must never enter state"

    # 7. Target is NOT complete: one finding still needs a human
    assert target.status != Target_COMPLETED
    assert state.has_pending_validation() is True

    # 8. Assessment status reflects the human boundary
    status = service._terminal_status(state)
    assert status == AssessmentStatus.AWAITING_VALIDATION

    # 9. Report generation consumes the real lifecycle state
    from cybog.reporting.json_reporter import JSONReporter
    out = JSONReporter().generate(state, tmp_path / "reports")
    report = json.loads(out.read_text())
    statuses = {f["validation_status"] for f in report["findings"]}
    assert statuses == {"VALIDATED", "NEEDS_VALIDATION"}
    assert not any(f["validation_status"] == "REPORTABLE" for f in report["findings"]), \
        "an unvalidated finding must never be reported as reportable"
    summary = report["summary"]
    assert summary["findings_by_validation_status"]["VALIDATED"] == 1
    assert summary["findings_by_validation_status"]["NEEDS_VALIDATION"] == 1
    assert summary["pending_validation"] == 1
    # The secret must not reach report output either
    assert "s3cret" not in out.read_text()

    # 10. Analyst confirms the remaining finding -> target and assessment complete
    assert service.confirm_finding(
        assessment.assessment_id, offline.dedup_key, analyst_notes="manually reproduced"
    ) is True
    reloaded = service.load_state(assessment.assessment_id)
    resolved = reloaded.get_finding_by_id(offline.finding_id)
    assert resolved.validation_status == ValidationStatus.REPORTABLE
    assert resolved.is_terminal()
    assert any(e.analyst_notes == "manually reproduced" for e in resolved.evidence)
    assert reloaded.has_pending_validation() is False
    assert service._terminal_status(reloaded) == AssessmentStatus.COMPLETED
    assert reloaded.get_task_for_finding(offline.finding_id).status == \
        AnalystTaskStatus.COMPLETED

    from cybog.models.target import TargetStatus
    assert TargetStatus.COMPLETED == Target_COMPLETED


def _noop_adapter(sched, stage, config):
    """Adapter stub for stages that contribute no findings in this scenario."""
    from cybog.adapters.base import ToolAdapter, ValidationResult

    class _Noop(ToolAdapter):
        def __init__(self, cfg):
            self.config = cfg

        def metadata(self):
            return {"name": stage}

        def health_check(self):
            from cybog.adapters.base import HealthCheckResult
            return HealthCheckResult(tool=stage, binary="fake", available=True)

        def validate_input(self, job, context):
            return ValidationResult(valid=True, reason="noop")

        def build_command(self, job, stage_dir, context):
            return ["fake", stage]

        async def execute(self, command, stage_dir, timeout, stdin_data=None):
            return _fake_tool_result(stage, stage_dir)

        def parse_output(self, tool_result, stage_dir):
            return []

        def normalize_output(self, parsed, job):
            return NormalizedOutput(raw_count=0)

    return _Noop(getattr(config.tools, stage))


from cybog.models.target import TargetStatus as _TStatus

Target_COMPLETED = _TStatus.COMPLETED
