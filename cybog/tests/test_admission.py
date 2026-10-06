"""
T9: per-host scope admission.

- classify_asset() matrix: IN/OUT/AMBIGUOUS/INVALID with fail-closed
  semantics and matcher reuse (same rule as the create-time gate).
- partition() order + refusal triples.
- record_out_of_scope() deduplication.
- End-to-end with faked scanners: an out-of-scope domain and a bare IP
  emitted by discovery never reach any downstream input, are recorded
  exactly once with the right classifications, and the in-scope path
  still completes with findings.
"""
import asyncio

from cybog.adapters.dnsx import DnsxAdapter
from cybog.adapters.base import NormalizedOutput
from cybog.adapters.httpx import HttpxAdapter
from cybog.adapters.nuclei import NucleiAdapter
from cybog.adapters.subfinder import SubfinderAdapter
from cybog.artifacts.manager import ArtifactManager
from cybog.config.models import CybogConfig
from cybog.models.assessment import AssessmentStatus, Scope
from cybog.models.execution import ToolResult
from cybog.models.finding import Evidence, Finding, Severity
from cybog.models.job import JobStatus
from cybog.models.target import Host, Service
from cybog.profiles import stages_for
from cybog.scope.admission import (
    AssetClass,
    classify_asset,
    host_of_url,
    partition,
)
from cybog.services.assessment_service import AssessmentService
from cybog.state.assessment_state import AssessmentState
from cybog.workflow.scheduler import JobScheduler
from datetime import datetime, timezone
from pathlib import Path


def _scope() -> Scope:
    return Scope(patterns=["example.com"], explicit_excludes=["admin.example.com"])


def test_classify_matrix():
    s = _scope()
    assert classify_asset("example.com", s)[0] == AssetClass.IN_SCOPE
    assert classify_asset("api.example.com", s)[0] == AssetClass.IN_SCOPE
    assert classify_asset("  API.EXAMPLE.COM ", s)[0] == AssetClass.IN_SCOPE
    cls, reason = classify_asset("admin.example.com", s)
    assert cls == AssetClass.OUT_OF_SCOPE and "exclusion" in reason
    cls, _ = classify_asset("deep.admin.example.com", s)
    assert cls == AssetClass.OUT_OF_SCOPE
    cls, reason = classify_asset("evil-other.com", s)
    assert cls == AssetClass.OUT_OF_SCOPE and "no include" in reason


def test_classify_ambiguous_and_invalid():
    domain_only = Scope(patterns=["example.com"])
    cls, reason = classify_asset("93.184.216.99", domain_only)
    assert cls == AssetClass.AMBIGUOUS and "domain-only" in reason

    # The engine matcher has no CIDR semantics: a CIDR include cannot
    # prove membership, so the IP stays OUT (fail-closed), not ambiguous.
    cidr_scope = Scope(patterns=["10.0.0.0/24"])
    assert classify_asset("10.0.0.5", cidr_scope)[0] == AssetClass.OUT_OF_SCOPE
    # ...but the CIDR pattern itself is accepted as scope syntax.
    assert classify_asset("10.0.0.0/24", cidr_scope)[0] == AssetClass.IN_SCOPE

    for bad in ["", "   ", "a" * 254, "ta\tb.com", "x\ny.com"]:
        assert classify_asset(bad, domain_only)[0] == AssetClass.INVALID


def test_host_of_url_and_partition():
    assert host_of_url("https://api.example.com:8443/admin?q=1") == "api.example.com"
    assert host_of_url("not a url at all") == ""
    admitted, refused = partition(
        ["api.example.com", "evil-other.com", "93.184.216.99"],
        Scope(patterns=["example.com"]),
    )
    assert admitted == ["api.example.com"]
    assert [(v, c) for v, c, _ in refused] == [
        ("evil-other.com", AssetClass.OUT_OF_SCOPE),
        ("93.184.216.99", AssetClass.AMBIGUOUS),
    ]


def test_record_deduplicates(tmp_path):
    from cybog.models.assessment import Assessment
    state = AssessmentState.create_new(Assessment(
        target_input_file="t", scope_file="s"))
    assert state.record_out_of_scope("evil.com", "asset", "OUT_OF_SCOPE", "r", "dnsx") is True
    assert state.record_out_of_scope("evil.com", "asset", "OUT_OF_SCOPE", "r", "httpx") is False
    assert state.out_of_scope_count() == 1
    # Persistence round-trip keeps the record.
    path = tmp_path / "state.json"
    state.save(path)
    assert AssessmentState.load(path).out_of_scope_count() == 1


# ----------------------------------------------------------------------
# End-to-end gating run
# ----------------------------------------------------------------------
RECEIVED: dict[str, list] = {"dnsx": [], "nuclei_urls": []}


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


class LeakySubfinder(SubfinderAdapter):
    """Emits one in-scope host, one out-of-scope domain, one bare IP."""

    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        return _fake_tool_result("subfinder", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return [{"host": h} for h in
                ("api.example.com", "evil-other.com", "93.184.216.99")]

    def normalize_output(self, parsed, job):
        out = NormalizedOutput()
        out.hosts = [Host(hostname=r["host"], target_id=job.target_id,
                          sources=["subfinder"]) for r in parsed]
        out.raw_count = len(parsed)
        return out


class RecordingDnsx(DnsxAdapter):
    """Resolves whatever it receives; records the received input."""

    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        RECEIVED["dnsx"] = list(context.get("subfinder_hosts", []))
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


class RecordingNuclei(NucleiAdapter):
    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        RECEIVED["nuclei_urls"] = list(context.get("all_urls", []))
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        return _fake_tool_result("nuclei", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return [{"template-id": "t", "matched-at": "https://api.example.com/x",
                 "info": {"name": "T", "severity": "low", "description": "d"}}]

    def normalize_output(self, parsed, job):
        import json as _json
        out = NormalizedOutput()
        for r in parsed:
            f = Finding(
                finding_type=r["template-id"], title=r["info"]["name"],
                severity=Severity.LOW, target_id=job.target_id,
                target_domain=job.target_domain, url=r["matched-at"],
                source_tool="nuclei", template_id=r["template-id"])
            f.evidence = [Evidence(finding_id=f.finding_id, tool="nuclei",
                                   raw_output=_json.dumps(r)[:200])]
            out.findings.append(f)
        out.raw_count = len(parsed)
        return out


def test_scope_escape_blocked_end_to_end(tmp_path):
    RECEIVED["dnsx"] = []
    RECEIVED["nuclei_urls"] = []
    config = CybogConfig()
    config.output.root = str(tmp_path)
    config.queues.max_size = 10
    svc = AssessmentService(config)
    (tmp_path / "targets.txt").write_text("example.com\n")
    (tmp_path / "scope.txt").write_text("example.com\n")
    state = svc.create(targets_file=str(tmp_path / "targets.txt"),
                       scope_file=str(tmp_path / "scope.txt"),
                       # Quick: only faked stages run (naabu/katana/ffuf would
                       # need real binaries); the gating under test is
                       # identical on every profile.
                       profile="quick", owner_id="u")
    target = next(iter(state.targets.values()))
    art = ArtifactManager(str(tmp_path), state.assessment.assessment_id)

    sched = JobScheduler(config, state, art,
                         enabled_stages=set(stages_for("quick")),
                         profile_name="quick")
    sched.adapters["subfinder"] = LeakySubfinder(config.tools.subfinder)
    sched.adapters["dnsx"] = RecordingDnsx(config.tools.dnsx)
    sched.adapters["httpx"] = FakeHttpx(config.tools.httpx)
    sched.adapters["nuclei"] = RecordingNuclei(config.tools.nuclei)
    asyncio.run(sched.run([target]))

    # The out-of-scope domain and the bare IP never reached any input.
    assert RECEIVED["dnsx"] == ["api.example.com"]
    assert RECEIVED["nuclei_urls"] == ["https://api.example.com"]
    for url in RECEIVED["nuclei_urls"]:
        assert "evil-other.com" not in url and "93.184.216.99" not in url

    # ...but both were recorded exactly once with the right classes.
    by_value = {i.value: i for i in state.out_of_scope}
    assert by_value["evil-other.com"].classification == "OUT_OF_SCOPE"
    assert by_value["93.184.216.99"].classification == "AMBIGUOUS"

    # The in-scope path still completes with findings.
    assert len(state.get_findings_for_target(target.target_id)) == 1
    assert svc._terminal_status(state) == AssessmentStatus.AWAITING_VALIDATION

    # Guard: excluded stages never executed (no real subprocesses ran).
    # A regression here shows up as non-SKIPPED rows or minutes of runtime.
    jobs = state.get_jobs_for_target(target.target_id)
    by_stage: dict[str, list] = {}
    for j in jobs:
        by_stage.setdefault(j.stage, []).append(j)
    for stage in ("naabu", "katana", "ffuf"):
        assert {j.status for j in by_stage.get(stage, [])} == {JobStatus.SKIPPED}, stage
        assert all("profile" in (j.skip_reason or "") for j in by_stage[stage]), stage
