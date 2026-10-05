"""
progress_snapshot.py

Read-only projection of a persisted ``AssessmentState`` into a live-status
snapshot that the REST layer and the WebSocket broadcaster both serve.

Every field here is derived from real persisted state. Nothing is estimated,
interpolated or timed. The pipeline does not emit progress events today (the
scheduler has no observer/callback hook), so the snapshot is the only honest
source of live status.

Stage information is a *rollup of StageJob rows* -- the scheduler creates a
job when a stage is enqueued (scheduler.py:405-428) and saves state after
every job (scheduler.py:292) -- not an emitted "current stage" event.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from cybog.models.job import JobStatus, StageJob
from cybog.models.target import TargetStatus
from cybog.state.assessment_state import AssessmentState

#: Job statuses that mean the job will not change again.
TERMINAL_JOB_STATUSES = frozenset(
    {
        JobStatus.COMPLETED.value,
        JobStatus.FAILED.value,
        JobStatus.SKIPPED.value,
        JobStatus.CANCELLED.value,
    }
)

#: Assessment statuses after which the pipeline produces no further state
#: transitions on its own. AWAITING_VALIDATION is included: the scheduler has
#: finished and only human validation remains (_terminal_status,
#: cybog/services/assessment_service.py:174).
TERMINAL_ASSESSMENT_STATUSES = frozenset(
    {"COMPLETED", "FAILED", "CANCELLED", "AWAITING_VALIDATION"}
)

#: Pipeline graph order, used only to sort the derived stage list for display.
STAGE_ORDER = (
    "subfinder",
    "dnsx",
    "httpx",
    "naabu",
    "katana",
    "ffuf",
    "nuclei",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _stage_sort_key(stage: str) -> tuple:
    try:
        return (STAGE_ORDER.index(stage), stage)
    except ValueError:
        return (len(STAGE_ORDER), stage)


def _target_snapshot(
    target_id: str,
    target: Any,
    jobs: List[StageJob],
) -> Dict[str, Any]:
    total = len(jobs)
    completed = sum(1 for j in jobs if j.status.value in TERMINAL_JOB_STATUSES)
    return {
        "target_id": target_id,
        "domain": target.domain,
        "status": target.status.value,
        "total_jobs": total,
        "completed_jobs": completed,
        "completion_percentage": round(completed / total * 100, 2) if total else 0.0,
    }


def _stages_snapshot(jobs: List[StageJob]) -> List[Dict[str, Any]]:
    """Roll job statuses up per stage. Derived from state, not emitted."""
    by_stage: Dict[str, List[StageJob]] = {}
    for job in jobs:
        by_stage.setdefault(job.stage, []).append(job)

    stages: List[Dict[str, Any]] = []
    for stage, stage_jobs in sorted(
        by_stage.items(), key=lambda kv: _stage_sort_key(kv[0])
    ):
        counts: Dict[str, int] = {}
        for job in stage_jobs:
            counts[job.status.value] = counts.get(job.status.value, 0) + 1
        # Aggregate of the stage's job statuses: a failure dominates, then work
        # in flight, then work still queued, otherwise everything is terminal.
        if any(j.status == JobStatus.FAILED for j in stage_jobs):
            rollup = "FAILED"
        elif any(j.status == JobStatus.RUNNING for j in stage_jobs):
            rollup = "RUNNING"
        elif any(
            j.status in (JobStatus.PENDING, JobStatus.READY) for j in stage_jobs
        ):
            rollup = "PENDING"
        else:
            rollup = "COMPLETED"
        stages.append(
            {
                "stage": stage,
                "status": rollup,
                "job_count": len(stage_jobs),
                "running_jobs": counts.get(JobStatus.RUNNING.value, 0),
                "completed_jobs": sum(
                    counts.get(s, 0) for s in sorted(TERMINAL_JOB_STATUSES)
                ),
                "job_status_counts": counts,
            }
        )
    return stages


def _jobs_snapshot(jobs: List[StageJob]) -> List[Dict[str, Any]]:
    return [
        {
            "job_id": job.job_id,
            "target_id": job.target_id,
            "stage": job.stage,
            "status": job.status.value,
            "attempt": job.attempt,
            "started_at": _iso(job.started_at),
            "finished_at": _iso(job.finished_at),
            "duration_seconds": job.duration_seconds,
            "error": job.error,
        }
        for job in sorted(jobs, key=lambda j: (j.target_id, _stage_sort_key(j.stage)))
    ]


def build_progress_snapshot(
    state: AssessmentState,
    assessment_id: str | None = None,
) -> Dict[str, Any]:
    """Project a real ``AssessmentState`` into a live-status snapshot.

    Pure read: does not mutate the state and does not touch the filesystem.
    """
    aid = assessment_id or state.assessment.assessment_id
    status = state.assessment.status.value
    jobs = list(state.jobs.values())

    job_counts: Dict[str, int] = {}
    for job in jobs:
        job_counts[job.status.value] = job_counts.get(job.status.value, 0) + 1

    completed_jobs = sum(
        count
        for status_value, count in job_counts.items()
        if status_value in TERMINAL_JOB_STATUSES
    )
    total_jobs = len(jobs)

    jobs_by_target: Dict[str, List[StageJob]] = {}
    for job in jobs:
        jobs_by_target.setdefault(job.target_id, []).append(job)

    targets: List[Dict[str, Any]] = []
    for target_id, target in state.targets.items():
        snapshot = _target_snapshot(
            target_id, target, jobs_by_target.get(target_id, [])
        )
        snapshot["findings_count"] = len(state.get_findings_for_target(target_id))
        targets.append(snapshot)

    stages = _stages_snapshot(jobs)

    completed_targets = sum(
        1 for t in state.targets.values() if t.status == TargetStatus.COMPLETED
    )

    failed_targets = sum(
        1 for t in state.targets.values() if t.status == TargetStatus.FAILED
    )
    failed_stages = sorted(
        s["stage"] for s in stages if s["status"] == "FAILED"
    )
    partial_failure = bool(failed_targets) and not all(
        t.status in (TargetStatus.COMPLETED, TargetStatus.FAILED)
        for t in state.targets.values()
    )

    return {
        "type": "progress",
        "assessment_id": aid,
        "status": status,
        "is_terminal": status in TERMINAL_ASSESSMENT_STATUSES,
        "timestamp": _now_iso(),
        "last_updated": _iso(state.last_updated),
        # Kept for backwards compatibility with the existing /status and
        # /progress responses.
        "progress": {
            "total_targets": len(state.targets),
            "completed_targets": completed_targets,
            "total_jobs": total_jobs,
            "completed_jobs": completed_jobs,
            "failed_jobs": job_counts.get(JobStatus.FAILED.value, 0),
            "completion_percentage": (
                round(completed_jobs / total_jobs * 100, 2) if total_jobs else 0.0
            ),
            "targets": [
                {
                    "target_id": t["target_id"],
                    "domain": t["domain"],
                    "status": t["status"],
                    "completion_percentage": t["completion_percentage"],
                }
                for t in targets
            ],
        },
        "targets": targets,
        "targets_total": len(state.targets),
        "targets_completed": completed_targets,
        "stages": stages,
        # Stages with at least one RUNNING job. There is no single "current
        # stage": the scheduler runs one worker pool per stage concurrently
        # (scheduler.py:182-214), so several stages can be in flight at once.
        "running_stages": [s["stage"] for s in stages if s["status"] == "RUNNING"],
        "jobs": _jobs_snapshot(jobs),
        "jobs_total": total_jobs,
        "jobs_completed": completed_jobs,
        "jobs_failed": job_counts.get(JobStatus.FAILED.value, 0),
        "job_status_counts": job_counts,
        "completion_percentage": (
            round(completed_jobs / total_jobs * 100, 2) if total_jobs else 0.0
        ),
        "findings_count": len(state.findings),
        "pending_validation_count": state.pending_validation_count(),
        "created_at": _iso(state.assessment.created_at),
        "updated_at": _iso(getattr(state.assessment, "updated_at", None))
        or _iso(state.last_updated),
        "targets_failed": failed_targets,
        "partial_failure": partial_failure,
        "failed_stages": failed_stages,
    }


def is_terminal_snapshot(snapshot: Dict[str, Any]) -> bool:
    """True when the snapshot represents a finished assessment."""
    if snapshot.get("is_terminal"):
        return True
    return snapshot.get("status") in TERMINAL_ASSESSMENT_STATUSES


def not_found_snapshot(assessment_id: str) -> Dict[str, Any]:
    """Snapshot for an assessment that has no persisted state on disk."""
    return {
        "type": "progress",
        "assessment_id": assessment_id,
        "status": "NOT_FOUND",
        "is_terminal": True,
        "timestamp": _now_iso(),
        "error": f"No state found for assessment: {assessment_id}",
        "targets": [],
        "stages": [],
        "jobs": [],
        "findings_count": 0,
        "pending_validation_count": 0,
    }
