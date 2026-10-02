"""
Concurrency tests for the validation plane.

The queue is a single-consumer transport guarded by the event loop, but task
creation, finding dedup, and lifecycle transitions happen from the scheduler's
concurrent stage workers. These tests assert the invariants under that load.
"""
import asyncio

from cybog.adapters.base import ValidationOutcome
from cybog.models.assessment import Assessment
from cybog.models.finding import Evidence, Finding, Severity, ValidationStatus
from cybog.models.target import Service, Target
from cybog.queue.analyst_queue import AnalystTaskStatus
from cybog.state.assessment_state import AssessmentState
from tests.test_validation_plane import AUTH_ON, make_scheduler


class CountingAdapter:
    def __init__(self):
        self.calls = []

    async def validate_finding(self, finding, live_urls, stage_dir):
        self.calls.append(finding.finding_id)
        await asyncio.sleep(0)  # yield, so a race would be observable
        return ValidationOutcome(
            applicable=True,
            reason="confirmed",
            validated=True,
            evidence=Evidence(
                finding_id=finding.finding_id,
                tool="auth",
                raw_output="{}",
                validation_result="confirmed",
            ),
        )


def _multi_finding_state(n=12):
    assessment = Assessment(target_input_file="t.txt", scope_file="s.txt")
    state = AssessmentState.create_new(assessment)
    t = Target(domain="example.com")
    state.add_target(t)
    state.add_services(t.target_id, [
        Service(host="api.example.com", port=443, scheme="https",
                url="https://api.example.com", target_id=t.target_id)
    ])
    for i in range(n):
        state.add_finding(Finding(
            finding_type=f"template-{i}",
            title=f"Finding {i}",
            severity=Severity.MEDIUM,
            target_id=t.target_id,
            target_domain=t.domain,
            url=f"https://api.example.com/p{i}",
            source_tool="nuclei",
        ))
    return state


def test_concurrent_task_creation_never_duplicates(tmp_path):
    """Many producers racing on the same findings produce one task each."""
    state = _multi_finding_state()
    sched = make_scheduler(state, tmp_path, auth=AUTH_ON)
    sched.auth_adapter = CountingAdapter()

    findings = list(state.findings.values())

    async def race():
        await asyncio.gather(*[
            sched._ensure_analyst_task(f) for f in findings for _ in range(4)
        ])

    asyncio.run(race())

    assert len(state.analyst_tasks) == len(findings), "one task per finding, no duplicates"
    for f in findings:
        tasks = [t for t in state.analyst_tasks.values() if t.finding_id == f.finding_id]
        assert len(tasks) == 1


def test_concurrent_validation_of_same_finding_executes_once(tmp_path):
    """Duplicate deliveries of one task must not double-validate."""
    state = _multi_finding_state(n=1)
    sched = make_scheduler(state, tmp_path, auth=AUTH_ON)
    adapter = CountingAdapter()
    sched.auth_adapter = adapter

    finding = list(state.findings.values())[0]
    asyncio.run(sched._ensure_analyst_task(finding))
    task = state.get_task_for_finding(finding.finding_id)

    async def race():
        await asyncio.gather(*[sched._process_analyst_task(task) for _ in range(5)])

    asyncio.run(race())

    assert adapter.calls == [finding.finding_id], "validated exactly once"
    assert finding.validation_status == ValidationStatus.VALIDATED
    assert len([e for e in finding.evidence if e.validation_result]) == 1, \
        "no duplicate validation evidence"


def test_parallel_targets_do_not_contaminate_each_other(tmp_path):
    """Two targets validated concurrently keep their findings separate."""
    assessment = Assessment(target_input_file="t.txt", scope_file="s.txt")
    state = AssessmentState.create_new(assessment)
    ta = Target(domain="a.example.com")
    tb = Target(domain="b.example.com")
    state.add_target(ta)
    state.add_target(tb)
    for t in (ta, tb):
        state.add_services(t.target_id, [
            Service(host=t.domain, port=443, scheme="https",
                    url=f"https://{t.domain}", target_id=t.target_id)
        ])
        state.add_finding(Finding(
            finding_type="x", title=f"Finding for {t.domain}",
            severity=Severity.MEDIUM, target_id=t.target_id,
            target_domain=t.domain, url=f"https://{t.domain}/x",
            source_tool="nuclei",
        ))

    sched = make_scheduler(state, tmp_path, auth=AUTH_ON)
    sched.auth_adapter = CountingAdapter()

    async def run():
        await asyncio.gather(
            sched._ensure_analyst_task(list(state.findings.values())[0]),
            sched._ensure_analyst_task(list(state.findings.values())[1]),
        )
        tasks = list(state.analyst_tasks.values())
        await asyncio.gather(*[sched._process_analyst_task(t) for t in tasks])

    asyncio.run(run())

    for t in (ta, tb):
        fs = state.get_findings_for_target(t.target_id)
        assert len(fs) == 1
        assert fs[0].target_domain == t.domain
        assert fs[0].validation_status == ValidationStatus.VALIDATED
        assert all(e.finding_id == fs[0].finding_id for e in fs[0].evidence)


def test_worker_loop_exits_when_only_human_work_remains(tmp_path):
    """The loop must terminate, not spin, when findings need a human."""
    state = _multi_finding_state(n=3)
    sched = make_scheduler(state, tmp_path)  # auth off -> nothing auto-resolvable

    class Refuse:
        async def validate_finding(self, finding, live_urls, stage_dir):
            return ValidationOutcome(applicable=False, reason="needs human")

    sched.auth_adapter = Refuse()

    async def run():
        for f in list(state.findings.values()):
            await sched._ensure_analyst_task(f)
        await asyncio.wait_for(sched._validation_worker_loop(), timeout=10)

    asyncio.run(run())

    assert sched.analyst_queue.is_empty()
    assert all(
        t.status == AnalystTaskStatus.AWAITING_ANALYST
        for t in state.analyst_tasks.values()
    )
    assert state.has_pending_validation() is True
