"""
cybog/workflow/scheduler.py

JobScheduler — the core async pipeline orchestrator.

Architecture:
    - All targets start simultaneously in the subfinder queue
    - Per-stage asyncio Queues (bounded) enforce backpressure
    - Per-stage WorkerPools (Semaphore) enforce concurrency limits
    - Targets advance INDEPENDENTLY: Target A in dnsx while Target B in subfinder
    - httpx and naabu run CONCURRENTLY for the same target (asyncio.gather)
    - Failure isolation: one target failure never stops other targets
    - Persistent state saved after EVERY job completion
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

from cybog.adapters.base import ToolAdapter
from cybog.adapters.subfinder import SubfinderAdapter
from cybog.adapters.dnsx import DnsxAdapter
from cybog.adapters.httpx import HttpxAdapter
from cybog.adapters.naabu import NaabuAdapter
from cybog.adapters.katana import KatanaAdapter
from cybog.adapters.ffuf import FfufAdapter
from cybog.adapters.nuclei import NucleiAdapter
from cybog.adapters.auth_adapter import AuthAdapter
from cybog.adapters.base import ValidationOutcome
from cybog.artifacts.manager import ArtifactManager
from cybog.config.models import CybogConfig
from cybog.models.finding import Finding, ValidationStatus
from cybog.models.job import StageJob, JobStatus
from cybog.models.target import Target, TargetStatus
from cybog.queue.job_queue import BoundedJobQueue
from cybog.queue.analyst_queue import (
    AnalystTask,
    AnalystTaskStatus,
    BoundedAnalystQueue,
)
from cybog.state.assessment_state import AssessmentState
from cybog.workers.pool import WorkerPool
from cybog.workflow.nodes import run_stage_node
from cybog.workflow.router import PipelineRouter
from cybog.logging_setup import ContextLogger


STAGES_ORDER = [
    "subfinder", "dnsx", "httpx", "naabu", "katana", "ffuf", "nuclei"
]


class JobScheduler:
    """
    Dependency-aware async pipeline scheduler.

    Pipeline dependency graph:
        subfinder -> dnsx -> httpx (parallel with naabu) -> katana -> ffuf -> nuclei
                          -> naabu (parallel with httpx) -'
    """

    def __init__(
        self,
        config: CybogConfig,
        state: AssessmentState,
        artifact_mgr: ArtifactManager,
    ):
        self.config = config
        self.state = state
        self.artifact_mgr = artifact_mgr
        self._log = ContextLogger(
            "workflow.scheduler",
            assessment_id=state.assessment.assessment_id,
        )
        self._cancelled = False

        # --- Adapters ---
        self.adapters: dict[str, ToolAdapter] = {
            "subfinder": SubfinderAdapter(config.tools.subfinder),
            "dnsx":      DnsxAdapter(config.tools.dnsx),
            "httpx":     HttpxAdapter(config.tools.httpx),
            "naabu":     NaabuAdapter(config.tools.naabu),
            "katana":    KatanaAdapter(config.tools.katana),
            "ffuf":      FfufAdapter(config.tools.ffuf),
            "nuclei":    NucleiAdapter(config.tools.nuclei),
        }

        # --- Worker pools ---
        wc = config.workers
        self.pools: dict[str, WorkerPool] = {
            "subfinder": WorkerPool("subfinder", wc.subfinder),
            "dnsx":      WorkerPool("dnsx", wc.dnsx),
            "httpx":     WorkerPool("httpx", wc.httpx),
            "naabu":     WorkerPool("naabu", wc.naabu),
            "katana":    WorkerPool("katana", wc.katana),
            "ffuf":      WorkerPool("ffuf", wc.ffuf),
            "nuclei":    WorkerPool("nuclei", wc.nuclei),
        }

        # --- Bounded queues ---
        max_q = config.queues.max_size
        self.queues: dict[str, BoundedJobQueue] = {
            "subfinder": BoundedJobQueue("subfinder", max_q),
            "dnsx":      BoundedJobQueue("dnsx", max_q),
            "httpx":     BoundedJobQueue("httpx", max_q),
            "naabu":     BoundedJobQueue("naabu", max_q),
            "katana":    BoundedJobQueue("katana", max_q),
            "ffuf":      BoundedJobQueue("ffuf", max_q),
            "nuclei":    BoundedJobQueue("nuclei", max_q),
        }

        self._retry_count = config.execution.retry_failed
        self._continue_on_error = config.execution.continue_on_error

        # --- Human-assisted validation plane ---
        # The analyst queue is an in-memory transport only. The authoritative
        # record of every AnalystTask lives in AssessmentState, so a restart
        # rebuilds the queue from state instead of losing pending work.
        self.analyst_queue = BoundedAnalystQueue("analyst", max_q)
        self.auth_adapter = AuthAdapter(config.tools.auth)

        # finding_ids currently being validated. Guards against a duplicate
        # delivery of the same task racing the lifecycle transition.
        self._validating_finding_ids: set[str] = set()

        # Number of jobs enqueued but not yet settled into a terminal state.
        #
        # A stage loop must not treat "my queue is empty right now" as "I am
        # done": an upstream stage may still be running and about to enqueue
        # work for this stage. The previous queue-empty-only heuristic made
        # every downstream loop exit within its first 0.2s poll window, stranding
        # the jobs the upstream stage later produced in PENDING for the rest of
        # the run. Stage loops now stop only when this counter reaches zero,
        # which can happen solely when nothing is in flight and nothing more can
        # be enqueued.
        self._inflight = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def run(self, targets: list[Target]) -> None:
        """
        Run the full pipeline for all targets.
        Targets advance independently through stages.
        """
        self._log.info(f"Starting scheduler for {len(targets)} targets")

        # Enqueue all targets into subfinder queue
        for target in targets:
            job = self._make_job(target, "subfinder")
            self._inflight += 1
            await self.queues["subfinder"].enqueue(job)
            self._log.info(f"Enqueued subfinder job for {target.domain}", target_id=target.target_id)

        # Count active targets for shutdown
        self._pending_count = len(targets)

        # Re-queue any validation work that survived a previous run. This is
        # what makes resume safe: nothing is re-enqueued from scratch, and
        # already-terminal findings are never re-validated.
        await self._rehydrate_analyst_queue()

        # Run all stage worker loops concurrently
        try:
            await asyncio.gather(
                self._run_stage_loop("subfinder"),
                self._run_stage_loop("dnsx"),
                self._run_stage_loop_parallel_pair("httpx", "naabu"),
                self._run_stage_loop("katana"),
                self._run_stage_loop("ffuf"),
                self._run_stage_loop("nuclei"),
                self._validation_worker_loop(),
            )
        except Exception as exc:
            self._log.error(f"Scheduler fatal error: {exc}")
            raise

        self._settle_target_states()
        self._log.info("All pipeline stages completed")

    def cancel(self) -> None:
        self._cancelled = True
        self._log.info("Scheduler cancellation requested")

    def get_pool_stats(self) -> dict:
        return {name: pool.stats for name, pool in self.pools.items()}

    def get_queue_stats(self) -> dict:
        return {name: q.stats for name, q in self.queues.items()}

    # ------------------------------------------------------------------
    # Stage loop runners
    # ------------------------------------------------------------------
    async def _run_stage_loop(self, stage: str) -> None:
        """Run worker tasks for a single stage until all jobs are processed."""
        pool = self.pools[stage]
        queue = self.queues[stage]
        worker_tasks: list[asyncio.Task] = []

        while not self._cancelled:
            try:
                job = await asyncio.wait_for(queue.dequeue(timeout=0.1), timeout=0.2)
            except (asyncio.TimeoutError, asyncio.QueueEmpty):
                # Check if we're done: no more jobs coming and queue is empty
                if self._is_pipeline_drained(stage):
                    break
                continue

            if job is None:  # Sentinel
                break

            # Acquire worker slot (backpressure via semaphore)
            async def _worker(j: StageJob = job, s: str = stage):
                async with pool.acquire():
                    if self._cancelled:
                        j.status = JobStatus.CANCELLED
                        self.state.update_job(j)
                        return
                    await self._execute_stage(s, j)

            task = asyncio.create_task(_worker())
            worker_tasks.append(task)

        # Wait for all in-flight workers to finish
        if worker_tasks:
            await asyncio.gather(*worker_tasks, return_exceptions=True)

    async def _run_stage_loop_parallel_pair(
        self, stage_a: str, stage_b: str
    ) -> None:
        """
        Run httpx and naabu in parallel for each target.
        Both depend on dnsx output. They share nothing else.
        """
        pool_a, pool_b = self.pools[stage_a], self.pools[stage_b]
        queue_a, queue_b = self.queues[stage_a], self.queues[stage_b]
        worker_tasks: list[asyncio.Task] = []

        while not self._cancelled:
            job_a = job_b = None
            try:
                job_a = await asyncio.wait_for(queue_a.dequeue(timeout=0.1), timeout=0.2)
            except (asyncio.TimeoutError,):
                pass
            try:
                job_b = await asyncio.wait_for(queue_b.dequeue(timeout=0.1), timeout=0.2)
            except (asyncio.TimeoutError,):
                pass

            if job_a is None and job_b is None:
                if self._is_pipeline_drained(stage_a) and self._is_pipeline_drained(stage_b):
                    break
                await asyncio.sleep(0.05)
                continue

            # Run both in parallel if both available for same target
            async def _parallel_worker(ja=job_a, jb=job_b):
                tasks = []
                if ja:
                    async def _a():
                        async with pool_a.acquire():
                            await self._execute_stage(stage_a, ja)
                    tasks.append(asyncio.create_task(_a()))
                if jb:
                    async def _b():
                        async with pool_b.acquire():
                            await self._execute_stage(stage_b, jb)
                    tasks.append(asyncio.create_task(_b()))
                await asyncio.gather(*tasks, return_exceptions=True)

            task = asyncio.create_task(_parallel_worker())
            worker_tasks.append(task)

        if worker_tasks:
            await asyncio.gather(*worker_tasks, return_exceptions=True)

    # ------------------------------------------------------------------
    # Core stage execution
    # ------------------------------------------------------------------
    async def _execute_stage(self, stage: str, job: StageJob) -> None:
        """Execute one stage for one target, handle result, enqueue next stages."""
        log = ContextLogger(
            "workflow.scheduler",
            assessment_id=job.assessment_id,
            target_id=job.target_id,
            stage=stage,
            job_id=job.job_id,
        )

        try:
            adapter = self.adapters[stage]
            context = self._build_context(job.target_id, stage)

            completed_job = await run_stage_node(
                stage=stage,
                adapter=adapter,
                job=job,
                state=self.state,
                artifact_mgr=self.artifact_mgr,
                context=context,
                max_retries=self._retry_count,
                log=log,
            )

            # Save state after every job
            state_path = self.artifact_mgr.state_path()
            self.state.save(state_path)

            # Enqueue next stages based on result
            await self._enqueue_next_stages(stage, completed_job)

        except Exception as exc:
            log.error(f"Unhandled exception in stage {stage}: {exc}")
            job.status = JobStatus.FAILED
            job.error = str(exc)[:500]
            job.finished_at = datetime.now(timezone.utc)
            self.state.update_job(job)
            self.state.save(self.artifact_mgr.state_path())
            if not self._continue_on_error:
                raise
        finally:
            # Decrement only after _enqueue_next_stages has run, so the counter
            # can never momentarily read zero between "this job finished" and
            # "its successors were queued". That ordering is what keeps a
            # downstream stage loop from concluding the pipeline is drained.
            self._inflight = max(0, self._inflight - 1)

    async def _enqueue_next_stages(self, completed_stage: str, job: StageJob) -> None:
        """Dependency-aware next-stage enqueueing after a stage completes or is skipped."""
        target_id = job.target_id
        router = PipelineRouter()

        if completed_stage == "subfinder":
            should_run, reason = router.should_run_dnsx(self.state, target_id)
            if should_run:
                await self._enqueue(target_id, job.target_domain, "dnsx")
            else:
                self._log.info(f"Skipping dnsx: {reason}", target_id=target_id)
                self._skip_downstream(target_id, job, ["dnsx", "httpx", "naabu", "katana", "ffuf", "nuclei"])
                self._mark_target_done(target_id)

        elif completed_stage == "dnsx":
            run_httpx, r1 = router.should_run_httpx(self.state, target_id)
            run_naabu, r2 = router.should_run_naabu(self.state, target_id)
            if run_httpx:
                await self._enqueue(target_id, job.target_domain, "httpx")
            else:
                self._log.info(f"Skipping httpx: {r1}", target_id=target_id)
            if run_naabu:
                await self._enqueue(target_id, job.target_domain, "naabu")
            else:
                self._log.info(f"Skipping naabu: {r2}", target_id=target_id)
            if not run_httpx and not run_naabu:
                self._mark_target_done(target_id)

        elif completed_stage in ("httpx", "naabu"):
            # Wait for BOTH httpx and naabu to complete before proceeding
            httpx_done = self.state.is_stage_completed(target_id, "httpx") or \
                         self.state.is_stage_failed(target_id, "httpx") or \
                         self._is_skipped(target_id, "httpx")
            naabu_done = self.state.is_stage_completed(target_id, "naabu") or \
                         self.state.is_stage_failed(target_id, "naabu") or \
                         self._is_skipped(target_id, "naabu")

            if httpx_done and naabu_done:
                run_katana, r1 = router.should_run_katana(self.state, target_id)
                run_ffuf, r2 = router.should_run_ffuf(self.state, target_id)
                if run_katana:
                    await self._enqueue(target_id, job.target_domain, "katana")
                if run_ffuf:
                    await self._enqueue(target_id, job.target_domain, "ffuf")
                if not run_katana and not run_ffuf:
                    self._skip_downstream(
                        target_id, job,
                        ["katana", "ffuf", "nuclei"],
                        reason=r1,
                    )
                    self._mark_target_done(target_id)

        elif completed_stage in ("katana", "ffuf"):
            katana_done = self.state.is_stage_completed(target_id, "katana") or \
                          self.state.is_stage_failed(target_id, "katana") or \
                          self._is_skipped(target_id, "katana")
            ffuf_done = self.state.is_stage_completed(target_id, "ffuf") or \
                        self.state.is_stage_failed(target_id, "ffuf") or \
                        self._is_skipped(target_id, "ffuf")

            if katana_done and ffuf_done:
                run_nuclei, reason = router.should_run_nuclei(self.state, target_id)
                if run_nuclei:
                    await self._enqueue(target_id, job.target_domain, "nuclei")
                else:
                    self._log.info(f"Skipping nuclei: {reason}", target_id=target_id)
                    self._mark_target_done(target_id)

        elif completed_stage == "nuclei":
            # Nuclei produced candidate findings. They are not reportable yet:
            # move each one into the human-validation boundary and queue work
            # for it. The target stays pending until validation resolves.
            for finding in self.state.get_findings_for_target(target_id):
                if (
                    finding.source_tool == "nuclei"
                    and finding.validation_status == ValidationStatus.DISCOVERED
                ):
                    finding.transition_to(ValidationStatus.NEEDS_VALIDATION)
                    self.state.update_finding(finding)

            for finding in self.state.get_findings_for_target(target_id):
                if finding.validation_status == ValidationStatus.NEEDS_VALIDATION:
                    await self._ensure_analyst_task(finding)

            self.state.save(self.artifact_mgr.state_path())
            self._settle_target_state(target_id)

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------
    def _build_context(self, target_id: str, stage: str) -> dict:
        """Build the context dict for an adapter based on current state."""
        subfinder_hosts = [h.hostname for h in self.state.hosts.get(target_id, [])]
        dnsx_hosts = [
            h.hostname for h in self.state.hosts.get(target_id, [])
            if h.ips
        ]
        return {
            "subfinder_hosts": subfinder_hosts,
            "dnsx_hosts": dnsx_hosts,
            "httpx_urls": self.state.get_live_urls_for_target(target_id),
            "all_urls": self.state.get_all_urls_for_target(target_id),
        }

    async def _enqueue(self, target_id: str, domain: str, stage: str) -> None:
        job = self._make_job_from_ids(target_id, domain, stage)
        self._inflight += 1
        await self.queues[stage].enqueue(job)
        self._log.info(f"Enqueued {stage} for {domain}", target_id=target_id)

    def _make_job(self, target: Target, stage: str) -> StageJob:
        job = StageJob(
            assessment_id=self.state.assessment.assessment_id,
            target_id=target.target_id,
            target_domain=target.domain,
            stage=stage,
        )
        self.state.add_job(job)
        return job

    def _make_job_from_ids(self, target_id: str, domain: str, stage: str) -> StageJob:
        job = StageJob(
            assessment_id=self.state.assessment.assessment_id,
            target_id=target_id,
            target_domain=domain,
            stage=stage,
        )
        self.state.add_job(job)
        return job

    def _is_skipped(self, target_id: str, stage: str) -> bool:
        job = self.state.get_job_for_stage(target_id, stage)
        return job is not None and job.status == JobStatus.SKIPPED

    def _skip_downstream(self, target_id: str, job: StageJob, stages: list[str], reason: str = "Upstream stage produced 0 results") -> None:
        for s in stages:
            skip_job = StageJob(
                assessment_id=job.assessment_id,
                target_id=target_id,
                target_domain=job.target_domain,
                stage=s,
                status=JobStatus.SKIPPED,
                skip_reason=reason,
            )
            self.state.add_job(skip_job)

    def _mark_target_done(self, target_id: str) -> None:
        target = self.state.get_target(target_id)
        if target:
            # Check if any job failed
            jobs = self.state.get_jobs_for_target(target_id)
            any_failed = any(j.status == JobStatus.FAILED for j in jobs)
            target.status = TargetStatus.FAILED if any_failed else TargetStatus.COMPLETED
        self._log.info(f"Target pipeline complete", target_id=target_id)

    def _is_pipeline_drained(self, stage: str) -> bool:
        """
        True only when this stage's queue is empty *and* no job is in flight
        anywhere in the pipeline.

        The in-flight check is what makes this correct rather than merely
        convenient: work is enqueued as a side effect of an upstream job
        completing, so an empty queue only means "nothing left to do here" once
        nothing is running that could still produce work for this stage.
        """
        return self.queues[stage].is_empty() and self._inflight <= 0

    # ------------------------------------------------------------------
    # Human-assisted validation plane
    # ------------------------------------------------------------------
    async def _ensure_analyst_task(self, finding: Finding) -> Optional[AnalystTask]:
        """
        Ensure exactly one AnalystTask exists for this finding, and that it is
        reachable from the queue. Idempotent: calling this repeatedly for the
        same finding never produces a second task.
        """
        existing = self.state.get_task_for_finding(finding.finding_id)
        if existing is not None:
            if not existing.is_terminal():
                # Non-terminal (e.g. rehydrating after a restart): make sure it
                # is reachable by the worker.
                await self.analyst_queue.enqueue(existing)
            return existing

        task = AnalystTask(
            assessment_id=self.state.assessment.assessment_id,
            target_id=finding.target_id,
            finding_id=finding.finding_id,
            analyst_id="unassigned",
            description=(
                f"Validate {finding.finding_type} finding "
                f"'{finding.title}' on {finding.target_domain}"
            ),
        )
        if not self.state.add_analyst_task(task):
            # Lost a race against a concurrent producer.
            return self.state.get_task_for_finding(finding.finding_id)
        await self.analyst_queue.enqueue(task)
        self._log.info(
            f"Queued validation task {task.task_id}",
            target_id=finding.target_id,
            finding_id=finding.finding_id,
        )
        return task

    async def _rehydrate_analyst_queue(self) -> None:
        """
        Rebuild the in-memory queue from persisted state.

        Only tasks that are not already resolved are re-queued, so a restart
        cannot re-run completed validation or duplicate tasks.
        """
        requeued = 0
        for task in list(self.state.analyst_tasks.values()):
            if task.is_terminal():
                continue
            if task.assessment_id != self.state.assessment.assessment_id:
                continue
            await self.analyst_queue.enqueue(task)
            requeued += 1
        if requeued:
            self._log.info(f"Rehydrated {requeued} pending validation task(s)")

        # A finding may be pending validation with no task at all if the
        # process died between the transition and the task being recorded.
        for finding in list(self.state.findings.values()):
            if (
                finding.validation_status == ValidationStatus.NEEDS_VALIDATION
                and self.state.get_task_for_finding(finding.finding_id) is None
            ):
                await self._ensure_analyst_task(finding)

    def _has_actionable_validation(self) -> bool:
        """
        True if validation work remains that this run can still make progress on.

        Tasks parked in AWAITING_ANALYST are terminal: they need a human, so
        they must not keep the worker loop alive.
        """
        return any(
            task.status in (AnalystTaskStatus.PENDING, AnalystTaskStatus.VALIDATING)
            for task in self.state.analyst_tasks.values()
        )

    async def _validation_worker_loop(self) -> None:
        """
        Drain the analyst queue, resolving findings through the lifecycle.

        Exits when the queue is empty and no actionable work remains, so an
        assessment whose findings need a human terminates rather than hanging.
        """
        while not self._cancelled:
            task = await self.analyst_queue.dequeue(timeout=0.2)
            if task is None:
                if not self._has_actionable_validation():
                    break
                continue
            try:
                await self._process_analyst_task(task)
            except Exception as exc:
                self._log.error(
                    f"Validation task {task.task_id} failed: {exc}",
                    target_id=task.target_id,
                    finding_id=task.finding_id,
                )
                self.state.save(self.artifact_mgr.state_path())

    async def _process_analyst_task(self, task: AnalystTask) -> None:
        """
        Resolve one AnalystTask: NEEDS_VALIDATION -> VALIDATING -> verdict.

        A finding is only moved to VALIDATED or FALSE_POSITIVE when a validator
        actually produced a verdict. Otherwise it returns to NEEDS_VALIDATION
        and the task is parked as AWAITING_ANALYST for a human decision.
        """
        # Isolation: never act on a task from another assessment (§16).
        if task.assessment_id != self.state.assessment.assessment_id:
            self._log.warning(
                f"Rejecting task {task.task_id}: assessment mismatch "
                f"({task.assessment_id})"
            )
            return

        finding = self.state.get_finding_by_id(task.finding_id)
        if finding is None:
            self._log.warning(f"Task {task.task_id} references unknown finding")
            task.status = AnalystTaskStatus.COMPLETED
            task.result = "finding no longer present in state"
            self.state.analyst_tasks[task.task_id] = task
            return

        # Isolation: the task must belong to the same target as the finding.
        if finding.target_id != task.target_id:
            self._log.warning(
                f"Rejecting task {task.task_id}: target mismatch "
                f"(task={task.target_id}, finding={finding.target_id})"
            )
            task.status = AnalystTaskStatus.COMPLETED
            task.result = "target isolation violation"
            self.state.analyst_tasks[task.task_id] = task
            return

        # Idempotency: an already-resolved finding is never validated twice.
        if finding.is_terminal():
            task.status = AnalystTaskStatus.COMPLETED
            task.result = f"finding already {finding.validation_status.value}"
            task.completed_at = datetime.now(timezone.utc)
            self.state.analyst_tasks[task.task_id] = task
            return

        # Concurrency: a duplicate delivery of this task is already in flight.
        # Claim the finding so a second coroutine cannot interleave its own
        # transition between ours.
        if finding.finding_id in self._validating_finding_ids:
            return
        self._validating_finding_ids.add(finding.finding_id)
        try:
            await self._resolve_finding(task, finding)
        finally:
            self._validating_finding_ids.discard(finding.finding_id)

    async def _resolve_finding(self, task: AnalystTask, finding: Finding) -> None:
        """Run the full NEEDS_VALIDATION -> VALIDATING -> verdict sequence."""
        # A queued task means the finding entered the validation boundary. Walk
        # the lifecycle in order rather than assuming the caller's state; the
        # transition table still rejects any genuinely invalid jump.
        if finding.validation_status == ValidationStatus.DISCOVERED:
            finding.transition_to(ValidationStatus.NEEDS_VALIDATION)
        if finding.validation_status == ValidationStatus.NEEDS_VALIDATION:
            finding.transition_to(ValidationStatus.VALIDATING)
            self.state.update_finding(finding)
            task.status = AnalystTaskStatus.VALIDATING
            self.state.analyst_tasks[task.task_id] = task
            self.state.save(self.artifact_mgr.state_path())

        outcome = await self._validate_finding(finding)

        if outcome.applicable and outcome.validated is not None:
            if outcome.evidence is not None:
                finding.evidence.append(outcome.evidence)
            if outcome.validated:
                finding.transition_to(ValidationStatus.VALIDATED)
            else:
                finding.transition_to(ValidationStatus.FALSE_POSITIVE)
            task.status = AnalystTaskStatus.COMPLETED
            task.result = outcome.reason
        else:
            # No verdict. Return to the pending state and wait for a human
            # rather than inventing an outcome.
            if finding.validation_status == ValidationStatus.VALIDATING:
                finding.transition_to(ValidationStatus.NEEDS_VALIDATION)
            task.status = AnalystTaskStatus.AWAITING_ANALYST
            task.result = outcome.reason

        task.completed_at = datetime.now(timezone.utc)
        self.state.update_finding(finding)
        self.state.analyst_tasks[task.task_id] = task
        self.state.save(self.artifact_mgr.state_path())
        self._log.info(
            f"Validation resolved for finding {finding.finding_id}: "
            f"{finding.validation_status.value} ({task.result})",
            target_id=finding.target_id,
            finding_id=finding.finding_id,
        )
        self._settle_target_state(finding.target_id)

    async def _validate_finding(self, finding: Finding) -> ValidationOutcome:
        """
        Run the applicable validator for a finding.

        The AuthAdapter is used only where authentication-based validation
        applies: auth must be enabled and configured, and the finding must sit
        on a live httpx service for its target. We authenticate against
        confirmed live services only — a finding URL that httpx never confirmed
        is not a validated live surface, so it is left for a human rather than
        probed speculatively.
        """
        if not (self.config.tools.auth.enabled and self.config.tools.auth.is_configured()):
            return ValidationOutcome(
                applicable=False,
                reason=(
                    "Auth validation is not enabled/configured; "
                    "requires analyst review"
                ),
            )

        live_urls = self.state.get_live_urls_for_target(finding.target_id)
        if not self._finding_is_on_live_service(finding, live_urls):
            return ValidationOutcome(
                applicable=False,
                reason=(
                    "Finding is not on a confirmed live httpx service; "
                    "requires analyst review"
                ),
            )

        stage_dir = self.artifact_mgr.stage_dir(
            finding.target_id, f"validation-auth-{finding.finding_id}"
        )
        return await self.auth_adapter.validate_finding(finding, live_urls, stage_dir)

    @staticmethod
    def _finding_is_on_live_service(finding: Finding, live_urls: list[str]) -> bool:
        """True if the finding's URL belongs to a confirmed live service."""
        if not finding.url:
            return bool(live_urls)
        target = finding.url.rstrip("/")
        for live in live_urls:
            live = live.rstrip("/")
            if target == live or target.startswith(live + "/") or live.startswith(target + "/"):
                return True
        return False

    # ------------------------------------------------------------------
    # Completion conditions
    # ------------------------------------------------------------------
    def _target_has_pending_validation(self, target_id: str) -> bool:
        return any(
            f.is_pending_validation()
            for f in self.state.get_findings_for_target(target_id)
        )

    def _target_is_complete(self, target_id: str) -> bool:
        """
        A target is complete only when no finding still awaits validation.

        Queue emptiness alone is not sufficient: downstream work can still be
        produced, and findings parked for a human are not resolved.
        """
        return not self._target_has_pending_validation(target_id)

    def _settle_target_state(self, target_id: str) -> None:
        """Mark a target done only once its findings have all reached a terminal state."""
        if not self._target_is_complete(target_id):
            self._log.info(
                f"Target pipeline finished but validation is still pending",
                target_id=target_id,
            )
            return
        self._mark_target_done(target_id)

    def _settle_target_states(self) -> None:
        for target_id in list(self.state.targets.keys()):
            self._settle_target_state(target_id)
