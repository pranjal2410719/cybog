"""
cybog/services/assessment_service.py

AssessmentService — the application layer.
Wires together: config, scope, ingestion, state, artifacts, scheduler, reporters.
CLI commands call ONLY this service. No business logic in CLI.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cybog.artifacts.manager import ArtifactManager
from cybog.config.models import CybogConfig
from cybog.ingestion.manifest import TargetManifestLoader
from cybog.models.assessment import Assessment, AssessmentStatus, Authorization, AuthorizationStatus
from cybog.models.job import JobStatus
from cybog.models.target import TargetStatus
from cybog.scope.validator import ScopeValidator
from cybog.state.assessment_state import AssessmentState
from cybog.workflow.scheduler import JobScheduler
from cybog.logging_setup import ContextLogger


class AssessmentService:
    def __init__(self, config: CybogConfig):
        self.config = config
        self._log = ContextLogger("services.assessment")

    # ------------------------------------------------------------------
    # create
    # ------------------------------------------------------------------
    def create(
        self,
        targets_file: str,
        scope_file: str,
        profile: str = "standard",
    ) -> AssessmentState:
        """
        Create a new assessment:
          1. Load and validate scope.
          2. Load and validate targets.
          3. Filter targets by scope (hard gate).
          4. Create AssessmentState and persist.
        """
        # 1. Scope validation
        scope_validator = ScopeValidator(scope_file)
        scope = scope_validator.load_scope()
        self._log.info(
            f"Scope loaded: {len(scope.patterns)} patterns from {scope_file}"
        )

        # 2. Build assessment
        assessment = Assessment(
            profile=profile,
            target_input_file=targets_file,
            scope_file=scope_file,
            authorization=Authorization(
                required=True,
                scope_file=scope_file,
                status=AuthorizationStatus.AUTHORIZED,
                authorized_patterns=scope.patterns,
            ),
            scope=scope,
            config_snapshot=json.loads(self.config.model_dump_json()),
        )
        assessment.artifact_root = str(
            Path(self.config.output.root) / assessment.assessment_id
        )

        # 3. Create artifact manager + state
        art_mgr = ArtifactManager(self.config.output.root, assessment.assessment_id)
        state = AssessmentState.create_new(assessment)

        # 4. Load targets from manifest
        loader = TargetManifestLoader(targets_file)
        candidates = loader.load(batch_name=Path(targets_file).name)
        self._log.info(f"Loaded {len(candidates)} candidate targets")

        # 5. Scope gate: HARD authorization check before any target is admitted
        in_scope_count = 0
        out_of_scope_count = 0
        for target in candidates:
            authorized, reason = scope_validator.validate_target(target, scope)
            if authorized:
                target.status = TargetStatus.IN_SCOPE
                state.add_target(target)
                in_scope_count += 1
                self._log.info(
                    f"IN_SCOPE: {target.domain}", target_id=target.target_id
                )
            else:
                target.status = TargetStatus.OUT_OF_SCOPE
                out_of_scope_count += 1
                self._log.info(
                    f"OUT_OF_SCOPE (excluded): {target.domain} — {reason}"
                )

        self._log.info(
            f"Scope gate: {in_scope_count} authorized, {out_of_scope_count} excluded"
        )

        if in_scope_count == 0:
            raise ValueError(
                "No targets passed scope validation. "
                "Update authorized_scope.txt to include your targets."
            )

        # 6. Write manifest
        manifest = {
            "assessment_id": assessment.assessment_id,
            "created_at": assessment.created_at.isoformat(),
            "profile": profile,
            "targets_file": targets_file,
            "scope_file": scope_file,
            "total_candidates": len(candidates),
            "in_scope": in_scope_count,
            "out_of_scope": out_of_scope_count,
            "authorized_patterns": scope.patterns,
        }
        art_mgr.write_json(art_mgr.manifest_path(), manifest)
        state.save(art_mgr.state_path())

        self._log.info(
            f"Assessment created: {assessment.assessment_id} "
            f"| root={assessment.artifact_root}"
        )
        return state

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------
    async def execute(self, assessment_id: str) -> AssessmentState:
        """Load state and run the full pipeline."""
        state = self.load_state(assessment_id)
        art_mgr = ArtifactManager(self.config.output.root, assessment_id)

        if state.assessment.status == AssessmentStatus.CANCELLED:
            raise ValueError(f"Assessment {assessment_id} is CANCELLED. Cannot execute.")

        state.assessment.status = AssessmentStatus.RUNNING
        state.assessment.started_at = datetime.now(timezone.utc)
        state.save(art_mgr.state_path())

        targets = [
            t for t in state.targets.values()
            if t.status == TargetStatus.IN_SCOPE
        ]

        self._log.info(
            f"Executing {len(targets)} in-scope targets for {assessment_id}",
            assessment_id=assessment_id,
        )

        scheduler = JobScheduler(self.config, state, art_mgr)
        try:
            await scheduler.run(targets)
            state.assessment.status = AssessmentStatus.COMPLETED
        except Exception as exc:
            self._log.error(f"Pipeline error: {exc}", assessment_id=assessment_id)
            state.assessment.status = AssessmentStatus.FAILED
            state.assessment.error = str(exc)
            raise
        finally:
            state.assessment.completed_at = datetime.now(timezone.utc)
            state.save(art_mgr.state_path())

        return state

    # ------------------------------------------------------------------
    # resume
    # ------------------------------------------------------------------
    async def resume(self, assessment_id: str) -> AssessmentState:
        """
        Resume: load state, identify incomplete jobs, re-run only those.
        Already completed stages are NOT re-run.
        """
        state = self.load_state(assessment_id)
        art_mgr = ArtifactManager(self.config.output.root, assessment_id)

        incomplete = state.get_incomplete_jobs()
        failed = state.get_failed_jobs()
        self._log.info(
            f"Resume: {len(incomplete)} incomplete, {len(failed)} failed jobs",
            assessment_id=assessment_id,
        )

        # Mark interrupted RUNNING jobs as PENDING for re-execution
        for job in incomplete:
            job.status = JobStatus.PENDING
            state.update_job(job)

        state.assessment.status = AssessmentStatus.RESUMING
        state.save(art_mgr.state_path())

        # Re-execute — scheduler will skip completed stages (idempotency check)
        targets = [
            t for t in state.targets.values()
            if t.status in (TargetStatus.IN_SCOPE, TargetStatus.RUNNING)
        ]
        scheduler = JobScheduler(self.config, state, art_mgr)
        try:
            await scheduler.run(targets)
            state.assessment.status = AssessmentStatus.COMPLETED
        except Exception as exc:
            state.assessment.status = AssessmentStatus.FAILED
            state.assessment.error = str(exc)
            raise
        finally:
            state.assessment.completed_at = datetime.now(timezone.utc)
            state.save(art_mgr.state_path())

        return state

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def load_state(self, assessment_id: str) -> AssessmentState:
        state_path = Path(self.config.output.root) / assessment_id / "state.json"
        if not state_path.exists():
            raise FileNotFoundError(
                f"No state found for assessment: {assessment_id}\n"
                f"Expected: {state_path}"
            )
        return AssessmentState.load(state_path)

    def save_state(self, state: AssessmentState) -> None:
        art_mgr = ArtifactManager(
            self.config.output.root, state.assessment.assessment_id
        )
        state.save(art_mgr.state_path())
