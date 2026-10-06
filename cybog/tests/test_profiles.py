"""
T8: profiles as workflow configuration.

- stages_for() resolves (and validates) stage sets.
- apply_profile() resolves Full tool overrides onto an independent copy.
- create() rejects unknown profiles fast.
- A Quick end-to-end run with faked scanners proves excluded stages never
  execute and leave exactly one profile-reasoned SKIPPED row each.
"""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cybog.adapters.base import NormalizedOutput
from cybog.adapters.dnsx import DnsxAdapter
from cybog.adapters.httpx import HttpxAdapter
from cybog.adapters.nuclei import NucleiAdapter
from cybog.adapters.subfinder import SubfinderAdapter
from cybog.artifacts.manager import ArtifactManager
from cybog.config.models import CybogConfig
from cybog.models.assessment import AssessmentStatus
from cybog.models.execution import ToolResult
from cybog.models.finding import Evidence, Finding, Severity
from cybog.models.job import JobStatus
from cybog.models.target import Host, Service
from cybog.profiles import (
    FULL_STAGES,
    QUICK_STAGES,
    STANDARD_STAGES,
    apply_profile,
    stages_for,
    validate_profile,
)
from cybog.services.assessment_service import AssessmentService
from cybog.workflow.scheduler import JobScheduler


def test_stage_sets():
    assert stages_for("quick") == QUICK_STAGES
    assert set(stages_for("quick")) == {"subfinder", "dnsx", "httpx", "nuclei"}
    assert set(stages_for("standard")) == set(STANDARD_STAGES)
    assert set(stages_for("full")) == set(FULL_STAGES) == set(STANDARD_STAGES)
    with pytest.raises(ValueError, match="Unknown profile"):
        stages_for("turbo")
    with pytest.raises(ValueError, match="Unknown profile"):
        validate_profile("")


def test_apply_profile_full_overrides_on_a_copy():
    config = CybogConfig()
    orig_auth = config.tools.auth.enabled
    orig_katana_args = list(config.tools.katana.extra_args)
    orig_nuclei_timeout = config.tools.nuclei.timeout

    full = apply_profile(config, "full")
    assert full is not config
    assert full.tools.auth.enabled is True
    assert full.tools.katana.extra_args == ["-ct", "120s", "-c", "10", "-d", "3"]
    assert full.tools.nuclei.timeout == 1800
    # The shared config is untouched: no cross-assessment leakage.
    assert config.tools.auth.enabled is orig_auth
    assert config.tools.katana.extra_args == orig_katana_args
    assert config.tools.nuclei.timeout == orig_nuclei_timeout

    quick = apply_profile(config, "quick")
    assert quick.tools.auth.enabled is orig_auth
    assert quick.tools.nuclei.timeout == orig_nuclei_timeout

    with pytest.raises(ValueError, match="Unknown profile"):
        apply_profile(config, "turbo")


def test_create_rejects_unknown_profile(tmp_path):
    config = CybogConfig()
    config.output.root = str(tmp_path)
    svc = AssessmentService(config)
    (tmp_path / "targets.txt").write_text("example.com\n")
    (tmp_path / "scope.txt").write_text("example.com\n")
    with pytest.raises(ValueError, match="Unknown profile"):
        svc.create(targets_file=str(tmp_path / "targets.txt"),
                   scope_file=str(tmp_path / "scope.txt"),
                   profile="turbo")


# ----------------------------------------------------------------------
# Quick end-to-end gating run with faked scanners
# ----------------------------------------------------------------------
def _fake_tool_result(tool: str, stage_dir: Path):
    stage_dir.mkdir(parents=True, exist_ok=True)
    (stage_dir / "stdout.log").write_text("", encoding="utf-8")
    (stage_dir / "stderr.log").write_text("", encoding="utf-8")
    now = datetime.now(timezone.utc)
    return ToolResult(
        tool=tool, binary="fake", command="fake", exit_code=0, stdout="",
        stderr="", duration_seconds=0.0, timed_out=False,
        started_at=now, finished_at=now,
    )


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


class FakeDnsx(DnsxAdapter):
    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        return _fake_tool_result("dnsx", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return [{"host": "api.example.com", "a": ["93.184.216.34"]}]

    def normalize_output(self, parsed, job):
        out = NormalizedOutput()
        out.hosts = [Host(hostname="api.example.com", ips=["93.184.216.34"],
                          target_id=job.target_id, sources=["dnsx"])]
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
                                url="https://api.example.com",
                                target_id=job.target_id)]
        out.raw_count = len(parsed)
        return out


class FakeNuclei(NucleiAdapter):
    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        return _fake_tool_result("nuclei", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return [{"template-id": "exposed-admin-panel",
                 "matched-at": "https://api.example.com/admin",
                 "info": {"name": "Exposed admin panel", "severity": "medium",
                          "description": "Admin panel reachable"}}]

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


def test_quick_profile_runs_subset_and_skips_rest(tmp_path):
    config = CybogConfig()
    config.output.root = str(tmp_path)
    config.queues.max_size = 10
    svc = AssessmentService(config)
    (tmp_path / "targets.txt").write_text("example.com\n")
    (tmp_path / "scope.txt").write_text("example.com\n")
    state = svc.create(targets_file=str(tmp_path / "targets.txt"),
                       scope_file=str(tmp_path / "scope.txt"),
                       profile="quick", owner_id="u")
    target = next(iter(state.targets.values()))
    art = ArtifactManager(str(tmp_path), state.assessment.assessment_id)

    sched = JobScheduler(config, state, art,
                         enabled_stages=set(stages_for("quick")),
                         profile_name="quick")
    sched.adapters["subfinder"] = FakeSubfinder(config.tools.subfinder)
    sched.adapters["dnsx"] = FakeDnsx(config.tools.dnsx)
    sched.adapters["httpx"] = FakeHttpx(config.tools.httpx)
    sched.adapters["nuclei"] = FakeNuclei(config.tools.nuclei)
    asyncio.run(sched.run([target]))

    # The vulnerability signal made it through on the short path.
    findings = state.get_findings_for_target(target.target_id)
    assert len(findings) == 1

    jobs = state.get_jobs_for_target(target.target_id)
    by_stage: dict[str, list] = {}
    for j in jobs:
        by_stage.setdefault(j.stage, []).append(j)

    # Excluded stages never executed: exactly one SKIPPED row each,
    # attributed to the profile (not to empty upstream results).
    for stage in ("naabu", "katana", "ffuf"):
        assert stage in by_stage, f"{stage} must have a SKIPPED row"
        assert {j.status for j in by_stage[stage]} == {JobStatus.SKIPPED}
        assert all("profile 'quick'" in (j.skip_reason or "")
                   for j in by_stage[stage]), stage

    # Enabled stages ran to completion.
    for stage in ("subfinder", "dnsx", "httpx", "nuclei"):
        assert JobStatus.COMPLETED in {j.status for j in by_stage.get(stage, [])}, stage

    # Terminal status still distinguishes "done" from "verified".
    assert svc._terminal_status(state) == AssessmentStatus.AWAITING_VALIDATION
