"""
cybog/services/assessment_service.py

AssessmentService — the application layer.
Wires together: config, scope, ingestion, state, artifacts, scheduler, reporters.
CLI commands call ONLY this service. No business logic in CLI.
"""
from __future__ import annotations
import hashlib
import json

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cybog.artifacts.manager import ArtifactManager
from cybog.config.models import CybogConfig
from cybog.ingestion.manifest import TargetManifestLoader
from cybog.models.assessment import (
    Assessment,
    AssessmentStatus,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from cybog.models.finding import Evidence, InvalidTransitionError, ValidationStatus
from cybog.models.job import JobStatus
from cybog.models.target import TargetStatus
from cybog.profiles import apply_profile, stages_for, validate_profile
from cybog.queue.analyst_queue import AnalystTaskStatus
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
        name: Optional[str] = None,
        owner_id: Optional[str] = None,
    ) -> AssessmentState:
        """
        Create a new assessment:
          1. Load and validate scope.
          2. Load and validate targets.
          3. Filter targets by scope (hard gate).
          4. Create AssessmentState and persist.
        """
        # T8: fail fast on unknown profiles (typos must not silently run).
        validate_profile(profile)
        # 1. Scope validation
        scope_validator = ScopeValidator(scope_file)
        scope = scope_validator.load_scope()
        self._log.info(
            f"Scope loaded: {len(scope.patterns)} patterns from {scope_file}"
        )

        # 2. Build assessment. Authorization starts PENDING: the scope gate
        # above proves the scope file is valid, but only an explicit human
        # confirmation (confirm_authorization) may set AUTHORIZED. Execution
        # refuses anything else (require_authorized).
        assessment = Assessment(
            profile=profile,
            name=name,
            target_input_file=targets_file,
            scope_file=scope_file,
            owner_id=owner_id,
            authorization=Authorization(
                required=True,
                scope_file=scope_file,
                status=AuthorizationStatus.PENDING,
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
    # authorization
    # ------------------------------------------------------------------
    @staticmethod
    def scope_snapshot(
        scope: Optional[Scope], state: AssessmentState
    ) -> tuple[dict, str]:
        """
        Canonical rendering of the authorized scope + admitted targets.

        Returns (snapshot, sha256). The digest is pinned on the
        Authorization record at confirmation time; execution admission (T9)
        enforces the pinned snapshot, never live inputs.
        """
        snapshot = {
            "include": sorted(scope.patterns) if scope else [],
            "exclude": sorted(scope.explicit_excludes) if scope else [],
            "targets": sorted(t.domain for t in state.targets.values()),
        }
        digest = hashlib.sha256(
            json.dumps(snapshot, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return snapshot, digest

    @staticmethod
    def require_authorized(state: AssessmentState) -> None:
        """Refuse execution for assessments without human authorization."""
        auth = state.assessment.authorization
        if not auth or auth.status != AuthorizationStatus.AUTHORIZED:
            raise ValueError(
                f"Assessment {state.assessment.assessment_id} has not been "
                f"human-authorized. Confirm authorization before starting."
            )

    def confirm_authorization(
        self, assessment_id: str, actor_user_id: str
    ) -> AssessmentState:
        """
        Record explicit human authorization (T5: blocking pre-execution step).

        Allowed only while the assessment is CREATED: once execution begins,
        target/scope are frozen and re-confirmation is rejected. Re-confirming
        an already-authorized CREATED assessment is idempotent.
        """
        state = self.load_state(assessment_id)
        a = state.assessment
        if a.status != AssessmentStatus.CREATED:
            raise ValueError(
                f"Assessment {assessment_id} scope/authorization is frozen "
                f"(status {a.status.value}). Authorization can only be "
                f"confirmed before execution begins."
            )
        auth = a.authorization or Authorization(
            required=True,
            scope_file=a.scope_file,
            status=AuthorizationStatus.PENDING,
        )
        snapshot, digest = self.scope_snapshot(a.scope, state)
        if auth.status == AuthorizationStatus.AUTHORIZED and auth.scope_sha256 == digest:
            return state  # idempotent retry: same scope, nothing to do
        auth.status = AuthorizationStatus.AUTHORIZED
        auth.authorized_at = datetime.now(timezone.utc)
        auth.authorized_by_user_id = actor_user_id
        auth.authorized_patterns = list(a.scope.patterns) if a.scope else []
        auth.scope_snapshot = snapshot
        auth.scope_sha256 = digest
        a.authorization = auth
        art_mgr = ArtifactManager(self.config.output.root, assessment_id)
        state.save(art_mgr.state_path())
        self._log.info(
            f"Authorization confirmed for {assessment_id} by {actor_user_id} "
            f"(scope sha256: {digest[:16]}…)"
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

        self.require_authorized(state)

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

        from cybog.services.executor import AssessmentExecutor
        # T8: resolve the profile to a stage set + tool overrides. The
        # overrides apply to an independent config copy: the shared loaded
        # config is never mutated, so concurrent assessments cannot leak
        # profile settings into each other.
        run_config = apply_profile(self.config, state.assessment.profile)
        executor: AssessmentExecutor = JobScheduler(
            run_config, state, art_mgr,
            enabled_stages=set(stages_for(state.assessment.profile)),
            profile_name=state.assessment.profile,
        )
        try:
            await executor.run(targets)
            state.assessment.status = self._terminal_status(state)
        except Exception as exc:
            self._log.error(f"Pipeline error: {exc}", assessment_id=assessment_id)
            state.assessment.status = AssessmentStatus.FAILED
            state.assessment.error = str(exc)
            raise
        finally:
            state.assessment.completed_at = datetime.now(timezone.utc)
            state.save(art_mgr.state_path())
            self._auto_generate_reports(state, art_mgr)

        return state

    def _terminal_status(self, state: AssessmentState) -> AssessmentStatus:
        """
        An assessment is only COMPLETED when every finding reached a terminal
        validation state AND no stages failed. If stages failed, the assessment
        is PARTIALLY_COMPLETED. If findings await validation, it is
        AWAITING_VALIDATION.
        """
        if state.has_pending_validation():
            pending = state.pending_validation_count()
            self._log.info(
                f"Pipeline finished with {pending} finding(s) awaiting validation"
            )
            return AssessmentStatus.AWAITING_VALIDATION
        # Check for failed stages: if any stage job failed, the assessment
        # is partially completed, not fully completed.
        failed_stages = state.get_failed_jobs()
        if failed_stages:
            self._log.info(
                f"Pipeline finished with failed stages, marking PARTIALLY_COMPLETED"
            )
            return AssessmentStatus.PARTIALLY_COMPLETED
        return AssessmentStatus.COMPLETED

    def _auto_generate_reports(self, state: AssessmentState, art_mgr: ArtifactManager) -> None:
        """Automatically generate preliminary reports when assessment finishes."""
        if state.assessment.status not in (AssessmentStatus.COMPLETED, AssessmentStatus.AWAITING_VALIDATION):
            return
        
        try:
            from cybog.reporting.json_reporter import JSONReporter
            from cybog.reporting.jsonl_reporter import JSONLReporter
            from cybog.reporting.html_reporter import HTMLReporter
            
            output_dir = art_mgr.root / "aggregate"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            context = {}
            if state.assessment.verified:
                context["verified_by"] = state.assessment.verified_by_user_id
                context["verified_at"] = state.assessment.verified_at.strftime("%Y-%m-%d %H:%M:%S UTC") if state.assessment.verified_at else None

            JSONReporter().generate(state, output_dir, context=context)
            JSONLReporter().generate(state, output_dir)
            HTMLReporter().generate(state, output_dir, context=context)
            try:
                from cybog.reporting.pdf_reporter import PDFReporter
                PDFReporter().generate(state, output_dir, context=context)
            except Exception as e:
                self._log.warning(f"Could not generate PDF: {e}")
            
            self._log.info(f"Auto-generated preliminary/verified reports for {state.assessment.assessment_id}")
        except Exception as exc:
            self._log.error(f"Failed to auto-generate reports: {exc}")

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

        self.require_authorized(state)

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
        from cybog.services.executor import AssessmentExecutor
        run_config = apply_profile(self.config, state.assessment.profile)
        executor: AssessmentExecutor = JobScheduler(
            run_config, state, art_mgr,
            enabled_stages=set(stages_for(state.assessment.profile)),
            profile_name=state.assessment.profile,
        )
        try:
            await executor.run(targets)
            state.assessment.status = self._terminal_status(state)
        except Exception as exc:
            state.assessment.status = AssessmentStatus.FAILED
            state.assessment.error = str(exc)
            raise
        finally:
            state.assessment.completed_at = datetime.now(timezone.utc)
            state.save(art_mgr.state_path())
            self._auto_generate_reports(state, art_mgr)

        return state

    # ------------------------------------------------------------------
    # Finding lifecycle
    #
    # These are the human/analyst entry points into the boundary. They go
    # through Finding.transition_to(), so an invalid transition is rejected
    # rather than silently applied. confirm/reject also settle the finding's
    # analyst task so the assessment can reach a terminal state.
    # ------------------------------------------------------------------
    def request_validation(self, assessment_id: str, finding_dedup_key: str) -> bool:
        """Analyst picks up a finding: NEEDS_VALIDATION -> VALIDATING.

        Returns False if the finding is absent or not in a state that permits
        the transition.
        """
        state = self.load_state(assessment_id)
        finding = state.findings.get(finding_dedup_key)
        if finding is None:
            return False
        try:
            finding.transition_to(ValidationStatus.VALIDATING)
        except InvalidTransitionError:
            return False
        state.update_finding(finding)
        task = state.get_task_for_finding(finding.finding_id)
        if task is not None and not task.is_terminal():
            task.status = AnalystTaskStatus.VALIDATING
        self._save(state)
        return True

    def confirm_finding(
        self,
        assessment_id: str,
        finding_dedup_key: str,
        analyst_notes: Optional[str] = None,
        actor_user_id: Optional[str] = None,
    ) -> bool:
        """Analyst confirms a finding: VALIDATING -> VALIDATED -> REPORTABLE.

        Returns False if the finding is absent or the transition is not
        permitted from its current state.
        """
        state = self.load_state(assessment_id)
        finding = state.findings.get(finding_dedup_key)
        if finding is None:
            return False
        try:
            if finding.validation_status == ValidationStatus.NEEDS_VALIDATION:
                # Allow confirming straight from the pending state: the analyst
                # has reviewed it, so the VALIDATING hop is bookkeeping only.
                finding.transition_to(ValidationStatus.VALIDATING)
            finding.transition_to(ValidationStatus.VALIDATED)
            finding.transition_to(ValidationStatus.REPORTABLE)
        except InvalidTransitionError:
            return False

        if analyst_notes:
            evidence = Evidence(
                finding_id=finding.finding_id,
                tool="analyst",
                raw_output=analyst_notes,
                analyst_notes=analyst_notes,
                validation_result="Confirmed by analyst",
            )
            finding.evidence.append(evidence)

        state.update_finding(finding)
        self._settle_task(state, finding.finding_id, "Confirmed by analyst")
        self._save(state)
        self._refresh_assessment_status(state, actor_user_id)
        return True

    def reject_finding(
        self,
        assessment_id: str,
        finding_dedup_key: str,
        analyst_notes: Optional[str] = None,
        actor_user_id: Optional[str] = None,
    ) -> bool:
        """Analyst rejects a finding: VALIDATING -> FALSE_POSITIVE."""
        state = self.load_state(assessment_id)
        finding = state.findings.get(finding_dedup_key)
        if finding is None:
            return False
        try:
            if finding.validation_status == ValidationStatus.NEEDS_VALIDATION:
                finding.transition_to(ValidationStatus.VALIDATING)
            finding.transition_to(ValidationStatus.FALSE_POSITIVE)
        except InvalidTransitionError:
            return False

        if analyst_notes:
            evidence = Evidence(
                finding_id=finding.finding_id,
                tool="analyst",
                raw_output=analyst_notes,
                analyst_notes=analyst_notes,
                validation_result="Rejected by analyst",
            )
            finding.evidence.append(evidence)

        state.update_finding(finding)
        self._settle_task(state, finding.finding_id, "Rejected by analyst")
        self._save(state)
        self._refresh_assessment_status(state, actor_user_id)
        return True

    def pending_validation(self, assessment_id: str) -> list[dict]:
        """List findings still awaiting a human validation decision."""
        state = self.load_state(assessment_id)
        return [
            {
                "dedup_key": f.dedup_key,
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity.value,
                "url": f.url,
                "target_id": f.target_id,
                "validation_status": f.validation_status.value,
            }
            for f in state.findings.values()
            if f.is_pending_validation()
        ]

    def _settle_task(
        self, state: AssessmentState, finding_id: str, result: str
    ) -> None:
        """
        Mark a finding's analyst task resolved by a human decision.

        AWAITING_ANALYST is terminal for the validation worker (it will not
        touch the task again) but is not a final outcome, so an analyst
        decision moves it to COMPLETED.
        """
        task = state.get_task_for_finding(finding_id)
        if task is None:
            return
        if task.status == AnalystTaskStatus.COMPLETED:
            return
        task.status = AnalystTaskStatus.COMPLETED
        task.result = result
        task.completed_at = datetime.now(timezone.utc)

    def _refresh_assessment_status(self, state: AssessmentState, actor_user_id: Optional[str] = None) -> None:
        """Recompute assessment status after an analyst decision."""
        if state.assessment.status in (
            AssessmentStatus.AWAITING_VALIDATION,
            AssessmentStatus.COMPLETED,
        ):
            new_status = self._terminal_status(state)
            if state.assessment.status != new_status:
                state.assessment.status = new_status
                if new_status == AssessmentStatus.COMPLETED:
                    # Mark as verified
                    state.assessment.verified = True
                    state.assessment.verified_by_user_id = actor_user_id
                    state.assessment.verified_at = datetime.now(timezone.utc)
                    # Regenerate reports as VERIFIED
                    art_mgr = ArtifactManager(self.config.output.root, state.assessment.assessment_id)
                    self._auto_generate_reports(state, art_mgr)
        self.save_state(state)

    def _save(self, state: AssessmentState) -> None:
        self.save_state(state)

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
