"""
cybog/workflow/nodes.py

LangGraph workflow node functions.
Each node corresponds to one pipeline stage.
Nodes contain NO tool-specific logic — they call adapters only via the ToolAdapter interface.
State transitions are explicit and deterministic.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cybog.models.job import StageJob, JobStatus
from cybog.logging_setup import ContextLogger

if TYPE_CHECKING:
    from cybog.workflow.graph import WorkflowState
    from cybog.adapters.base import ToolAdapter
    from cybog.state.assessment_state import AssessmentState
    from cybog.artifacts.manager import ArtifactManager


async def run_stage_node(
    stage: str,
    adapter: "ToolAdapter",
    job: StageJob,
    state: "AssessmentState",
    artifact_mgr: "ArtifactManager",
    context: dict,
    max_retries: int = 2,
    log: ContextLogger = None,
) -> StageJob:
    """
    Generic stage runner used by all node functions.
    Handles: validation, execution, parsing, normalization, artifact writing,
             state updates, retry logic, and immutable artifact check.

    Returns the finalized StageJob.
    """
    if log is None:
        from cybog.logging_setup import ContextLogger
        log = ContextLogger(
            "workflow.nodes",
            assessment_id=job.assessment_id,
            target_id=job.target_id,
            stage=stage,
            job_id=job.job_id,
        )

    # --- Idempotency check ---
    if artifact_mgr.stage_has_completed_artifact(job.target_id, stage):
        log.info(f"Stage already completed (idempotent skip): {stage}")
        job.status = JobStatus.COMPLETED
        return job

    # --- Input validation ---
    validation = adapter.validate_input(job, context)
    if not validation.valid:
        log.info(f"Stage SKIPPED: {stage} | reason={validation.reason}")
        job.status = JobStatus.SKIPPED
        job.skip_reason = validation.reason
        job.finished_at = datetime.now(timezone.utc)
        state.update_job(job)
        return job

    stage_dir = artifact_mgr.stage_dir(job.target_id, stage, job.attempt)
    job.status = JobStatus.RUNNING
    job.started_at = datetime.now(timezone.utc)
    state.update_job(job)

    # --- Build command ---
    command = adapter.build_command(job, stage_dir, context)
    job.command = " ".join(command)
    log.info(f"Executing: {job.command[:200]}")

    # --- Execute ---
    tool_cfg = adapter.config  # type: ignore[attr-defined]
    tool_result = await adapter.execute(
        command=command,
        stage_dir=stage_dir,
        timeout=tool_cfg.timeout,
    )

    finished_at = datetime.now(timezone.utc)
    job.finished_at = finished_at
    job.exit_code = tool_result.exit_code
    job.duration_seconds = tool_result.duration_seconds

    # --- Persist raw output (stdout already written by base.execute) ---
    raw_text = ""
    for candidate in ("raw.jsonl", "raw.json", "raw.txt"):
        candidate_path = stage_dir / candidate
        if candidate_path.exists():
            raw_text = candidate_path.read_text(encoding="utf-8")
            break
    if not raw_text and tool_result.stdout:
        raw_text = tool_result.stdout
        (stage_dir / "raw.jsonl").write_text(raw_text, encoding="utf-8")

    # --- Success determination: exit_code 0 OR timed_out=False with exit 0 ---
    # Zero results with exit 0 = COMPLETED, not FAILED
    is_success = (
        tool_result.exit_code == 0
        and not tool_result.timed_out
    )

    if not is_success and job.attempt < max_retries:
        log.warning(
            f"Stage {stage} failed (exit={tool_result.exit_code}). "
            f"Attempt {job.attempt}/{max_retries}. Retrying..."
        )
        job.attempt += 1
        job.status = JobStatus.PENDING
        state.update_job(job)
        # Recursive retry
        return await run_stage_node(
            stage, adapter, job, state, artifact_mgr, context, max_retries, log
        )

    if not is_success:
        err = tool_result.stderr[:500] if tool_result.stderr else f"exit={tool_result.exit_code}"
        if tool_result.timed_out:
            err = f"Tool timed out after {tool_cfg.timeout}s"
        log.error(f"Stage FAILED: {stage} | {err}")
        job.status = JobStatus.FAILED
        job.error = err
        # Persist execution meta
        _write_exec_meta(stage_dir, job, tool_result, success=False)
        state.update_job(job)
        return job

    # --- Parse & Normalize ---
    parsed = adapter.parse_output(tool_result, stage_dir)
    normalized = adapter.normalize_output(parsed, job)

    # --- Update AssessmentState with normalized entities ---
    if normalized.hosts:
        state.add_hosts(job.target_id, normalized.hosts)
    if normalized.ips:
        state.ips.setdefault(job.target_id, []).extend(normalized.ips)
    if normalized.ports:
        state.add_ports(job.target_id, normalized.ports)
    if normalized.services:
        state.add_services(job.target_id, normalized.services)
    if normalized.urls:
        state.add_urls(job.target_id, normalized.urls)
    if normalized.endpoints:
        state.add_endpoints(job.target_id, normalized.endpoints)
    for finding in normalized.findings:
        state.add_finding(finding)

    # --- Persist normalized output ---
    norm_data = {
        "hosts": [h.model_dump() for h in normalized.hosts],
        "ips": [i.model_dump() for i in normalized.ips],
        "ports": [p.model_dump() for p in normalized.ports],
        "services": [s.model_dump() for s in normalized.services],
        "urls": [u.model_dump() for u in normalized.urls],
        "endpoints": [e.model_dump() for e in normalized.endpoints],
        "findings": [f.model_dump() for f in normalized.findings],
        "raw_count": normalized.raw_count,
    }
    artifact_mgr.save_normalized(job.target_id, stage, job.attempt, norm_data)

    job.result_count = normalized.raw_count
    job.status = JobStatus.COMPLETED
    job.output_artifacts = adapter.collect_artifacts(stage_dir, job)

    _write_exec_meta(stage_dir, job, tool_result, success=True)
    state.update_job(job)

    log.info(
        f"Stage COMPLETED: {stage} | "
        f"results={normalized.raw_count} | duration={tool_result.duration_seconds}s"
    )
    return job


def _write_exec_meta(
    stage_dir: Path,
    job: StageJob,
    tool_result: Any,
    success: bool,
) -> None:
    meta = {
        "job_id": job.job_id,
        "stage": job.stage,
        "attempt": job.attempt,
        "command": job.command,
        "exit_code": job.exit_code,
        "duration_seconds": job.duration_seconds,
        "success": success,
        "error": job.error,
        "result_count": job.result_count,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "tool_timed_out": tool_result.timed_out,
    }
    (stage_dir / "execution.json").write_text(
        json.dumps(meta, indent=2, default=str), encoding="utf-8"
    )
