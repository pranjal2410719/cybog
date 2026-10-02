"""
Regression tests for the stage-loop drain race.

`_is_pipeline_drained()` only asked "is my queue empty right now?". A stage
loop that started while its own queue was still empty therefore exited almost
immediately -- long before the upstream stage finished and enqueued real work.
Those jobs were then stranded in PENDING for the rest of the run while the
assessment was still reported as COMPLETED.

The e2e test in test_e2e_validation.py cannot catch this: its fake adapters
return instantly, so every stage is enqueued and drained inside the same
0.2s poll window. A slow upstream stage is required to expose the race.
"""
import asyncio

from cybog.adapters.base import NormalizedOutput
from cybog.adapters.dnsx import DnsxAdapter
from cybog.adapters.httpx import HttpxAdapter
from cybog.adapters.subfinder import SubfinderAdapter
from cybog.config.models import CybogConfig
from cybog.models.assessment import Assessment
from cybog.models.job import JobStatus
from cybog.models.target import Host, Target
from cybog.services.assessment_service import AssessmentService
from cybog.state.assessment_state import AssessmentState

# Long enough that downstream loops are guaranteed to hit their first empty
# poll while subfinder is still running.
UPSTREAM_DELAY = 0.6


class SlowSubfinder(SubfinderAdapter):
    """Produces one host, but only after a delay longer than one poll window."""

    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        await asyncio.sleep(UPSTREAM_DELAY)
        return _result("subfinder", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return [{"host": "api.example.com"}]

    def normalize_output(self, parsed, job):
        out = NormalizedOutput()
        out.hosts = [Host(hostname="api.example.com", target_id=job.target_id,
                          sources=["subfinder"])]
        out.raw_count = len(parsed)
        return out


class RecordingDnsx(DnsxAdapter):
    def __init__(self, tool_config):
        super().__init__(tool_config)
        self.calls = 0

    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        self.calls += 1
        return _result("dnsx", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return []

    def normalize_output(self, parsed, job):
        out = NormalizedOutput()
        out.raw_count = 0
        return out


class RecordingHttpx(HttpxAdapter):
    def __init__(self, tool_config):
        super().__init__(tool_config)
        self.calls = 0

    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="fake")

    async def execute(self, command, stage_dir, timeout, stdin_data=None):
        self.calls += 1
        return _result("httpx", stage_dir)

    def parse_output(self, tool_result, stage_dir):
        return [{"url": "https://api.example.com", "status_code": 200}]

    def normalize_output(self, parsed, job):
        from cybog.models.target import Service
        out = NormalizedOutput()
        out.services = [Service(host="api.example.com", port=443, scheme="https",
                                url="https://api.example.com", target_id=job.target_id)]
        out.raw_count = len(parsed)
        return out


def _result(tool, stage_dir):
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


def _noop(sched, stage, config):
    from cybog.adapters.base import NormalizedOutput
    base_cls = {
        "naabu": sched.adapters["naabu"].__class__,
        "katana": sched.adapters["katana"].__class__,
        "ffuf": sched.adapters["ffuf"].__class__,
        "nuclei": sched.adapters["nuclei"].__class__,
    }[stage]

    class _Noop(base_cls):
        def validate_input(self, job, context):
            from cybog.adapters.base import ValidationResult
            return ValidationResult(valid=True, reason="fake")

        async def execute(self, command, stage_dir, timeout, stdin_data=None):
            return _result(stage, stage_dir)

        def parse_output(self, tool_result, stage_dir):
            return []

        def normalize_output(self, parsed, job):
            out = NormalizedOutput()
            out.raw_count = 0
            return out

    return _Noop(getattr(config.tools, stage))


def _build(tmp_path):
    config = CybogConfig()
    config.output.root = str(tmp_path)
    config.queues.max_size = 50

    service = AssessmentService(config)
    assessment = Assessment(target_input_file="t.txt", scope_file="s.txt")
    state = AssessmentState.create_new(assessment)
    target = Target(domain="example.com")
    state.add_target(target)

    from cybog.artifacts.manager import ArtifactManager
    art = ArtifactManager(str(tmp_path), assessment.assessment_id)
    state.save(art.state_path())

    from cybog.workflow.scheduler import JobScheduler
    sched = JobScheduler(config, state, art)
    sched.adapters["subfinder"] = SlowSubfinder(config.tools.subfinder)
    dnsx = RecordingDnsx(config.tools.dnsx)
    sched.adapters["dnsx"] = dnsx
    httpx = RecordingHttpx(config.tools.httpx)
    sched.adapters["httpx"] = httpx
    for stage in ("naabu", "katana", "ffuf", "nuclei"):
        sched.adapters[stage] = _noop(sched, stage, config)
    return sched, state, target, dnsx, httpx


def test_slow_upstream_stage_does_not_strand_downstream_jobs(tmp_path):
    """
    A downstream stage must not give up while an upstream stage is still
    running, even if nothing is queued for it yet.
    """
    sched, state, target, dnsx, httpx = _build(tmp_path)

    asyncio.run(sched.run([target]))

    jobs = {j.stage: j for j in state.get_jobs_for_target(target.target_id)}

    # subfinder found a host, so dnsx was legitimately enqueued.
    assert "dnsx" in jobs, "dnsx should have been enqueued after subfinder"
    assert jobs["dnsx"].status == JobStatus.COMPLETED, (
        f"dnsx was stranded as {jobs['dnsx'].status}; its stage loop exited "
        "while subfinder was still running"
    )
    assert dnsx.calls == 1, "the dnsx adapter must actually be invoked"

    # dnsx resolved nothing, so httpx still runs: the hosts subfinder recorded
    # remain in state and httpx performs its own resolution. What matters is
    # that it reaches a terminal state rather than being stranded.
    if "httpx" in jobs:
        assert jobs["httpx"].status in (JobStatus.COMPLETED, JobStatus.SKIPPED), (
            f"httpx should be terminal, got {jobs['httpx'].status}"
        )

    # No job may be left non-terminal.
    stranded = [j.stage for j in jobs.values()
                if j.status in (JobStatus.PENDING, JobStatus.READY, JobStatus.RUNNING)]
    assert not stranded, f"jobs left non-terminal: {stranded}"


def test_downstream_stage_runs_after_slow_upstream(tmp_path):
    """
    httpx must run when dnsx reports a live service, proving the whole chain
    still works once the drain check stops racing the upstream stage.
    """
    sched, state, target, dnsx, httpx = _build(tmp_path)

    # Make dnsx report one resolved host so the chain continues to httpx.
    from cybog.adapters.base import NormalizedOutput
    from cybog.models.target import Host as _Host

    def normalize_with_host(parsed, job):
        out = NormalizedOutput()
        out.hosts = [_Host(hostname="api.example.com", target_id=job.target_id,
                           sources=["dnsx"])]
        out.raw_count = 1
        return out

    dnsx.normalize_output = normalize_with_host

    asyncio.run(sched.run([target]))

    jobs = {j.stage: j for j in state.get_jobs_for_target(target.target_id)}
    assert "httpx" in jobs, "httpx should be enqueued once dnsx resolves a host"
    assert jobs["httpx"].status == JobStatus.COMPLETED, (
        f"httpx stranded as {jobs['httpx'].status} behind a slow subfinder"
    )
    assert httpx.calls == 1, "the httpx adapter must actually be invoked"
