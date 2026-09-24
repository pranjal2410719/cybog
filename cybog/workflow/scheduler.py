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
from pathlib import Path
from typing import Optional

from cybog.adapters.base import ToolAdapter
from cybog.adapters.subfinder import SubfinderAdapter
from cybog.adapters.dnsx import DnsxAdapter
from cybog.adapters.httpx import HttpxAdapter
from cybog.adapters.naabu import NaabuAdapter
from cybog.adapters.katana import KatanaAdapter
from cybog.adapters.ffuf import FfufAdapter
from cybog.adapters.nuclei import NucleiAdapter
from cybog.artifacts.manager import ArtifactManager
from cybog.config.models import CybogConfig
from cybog.models.job import StageJob, JobStatus
from cybog.models.target import Target, TargetStatus
from cybog.queue.job_queue import BoundedJobQueue
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
            await self.queues["subfinder"].enqueue(job)
            self._log.info(f"Enqueued subfinder job for {target.domain}", target_id=target.target_id)

        # Count active targets for shutdown
        self._pending_count = len(targets)

        # Run all stage worker loops concurrently
        try:
            await asyncio.gather(
                self._run_stage_loop("subfinder"),
                self._run_stage_loop("dnsx"),
                self._run_stage_loop_parallel_pair("httpx", "naabu"),
                self._run_stage_loop("katana"),
                self._run_stage_loop("ffuf"),
                self._run_stage_loop("nuclei"),
            )
        except Exception as exc:
            self._log.error(f"Scheduler fatal error: {exc}")
            raise

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
            self._mark_target_done(target_id)

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------
    def _build_context(self, target_id: str, stage: str) -> dict:
        """Build the context dict for an adapter based on current state."""
        return {
            "subfinder_hosts": [h.hostname for h in self.state.hosts.get(target_id, [])],
            "dnsx_hosts": [h.hostname for h in self.state.hosts.get(target_id, [])
                           if h.sources and "dnsx" in h.sources or "subfinder" in h.sources],
            "httpx_urls": self.state.get_live_urls_for_target(target_id),
            "all_urls": self.state.get_all_urls_for_target(target_id),
        }

    async def _enqueue(self, target_id: str, domain: str, stage: str) -> None:
        job = self._make_job_from_ids(target_id, domain, stage)
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

    def _skip_downstream(self, target_id: str, job: StageJob, stages: list[str]) -> None:
        for s in stages:
            skip_job = StageJob(
                assessment_id=job.assessment_id,
                target_id=target_id,
                target_domain=job.target_domain,
                stage=s,
                status=JobStatus.SKIPPED,
                skip_reason="Upstream stage produced 0 results",
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
        """Heuristic: queue is empty. Not perfectly accurate but safe."""
        return self.queues[stage].is_empty()
