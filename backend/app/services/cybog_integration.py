"""
Cybog integration service for the backend API.

This service provides an abstraction layer between the backend API
and the Cybog pipeline, implementing the API contract while using
Cybog's existing service layer internally.
"""
from __future__ import annotations

import asyncio
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cybog.config.models import CybogConfig
from cybog.models.assessment import AssessmentStatus
from cybog.models.job import JobStatus
from cybog.models.target import TargetStatus
from cybog.services.assessment_service import AssessmentService
from cybog.state.assessment_state import AssessmentState
from cybog.logging_setup import get_logger
from app.services.export_service import ExportService
from app.services.progress_snapshot import build_progress_snapshot


# Module-level task registry shared across all service instances. Each
# CybogIntegrationService is request-scoped, so an instance attribute would
# not survive a single pipeline execution. This registry tracks background
# pipeline tasks so that duplicate starts are detectable and completed tasks
# are cleaned up automatically.
_running_tasks: Dict[str, "asyncio.Task[Any]"] = {}


# Report files actually produced by the Cybog reporting stage. Single source of
# truth for the API layer's allowlist; see cybog/reporting/{json,jsonl,html}_reporter.py
# (no Markdown reporter exists).
KNOWN_REPORT_FILES = frozenset({"report.json", "findings.jsonl", "report.html"})

# Report artifacts live in a single directory named after the assessment, so
# both the assessment id and the filename must be one safe path component.
# ``fullmatch`` (not ``match``) so a trailing newline is not accepted.
_SAFE_COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
_TRAVERSAL_CHARS = ("..", "/", "\\", "\x00")


def _is_safe_component(value: str) -> bool:
    """True if ``value`` is a single traversal-free path component."""
    if not isinstance(value, str):
        return False
    if any(bad in value for bad in _TRAVERSAL_CHARS):
        return False
    return _SAFE_COMPONENT_RE.fullmatch(value) is not None


class CybogIntegrationService:
    """
    Integration service that bridges the backend API to the Cybog pipeline.
    
    This service wraps Cybog's AssessmentService and provides a clean interface
    for the backend API to interact with Cybog.
    """

    def __init__(self, config: CybogConfig):
        self.config = config
        self._service = AssessmentService(config)
        self._log = get_logger("cybog_integration_service")
        self._assessment_states: Dict[str, AssessmentState] = {}

    def _is_file_content(self, value: str) -> bool:
        """
        Check if the provided value is file content rather than a file path.
        
        Heuristics:
        - Contains newlines (typical for text files)
        - Does not look like a path (no directory separators, no drive letters)
        - Is longer than typical path length
        """
        if not value:
            return False
        # Check for newlines (common in text files)
        if '\n' in value or '\r' in value:
            return True
        # Check if it looks like a path
        if '/' in value or '\\' in value:
            return False
        # If it's very long and doesn't look like a path, it's likely content
        if len(value) > 256:
            return True
        return False

    def _write_content_to_temp_file(self, content: str, prefix: str = "cybog_") -> str:
        """
        Write content to a temporary file and return the path.
        
        Args:
            content: The file content to write
            prefix: Prefix for the temp file
            
        Returns:
            Path to the temporary file
        """
        temp_dir = Path(self.config.output.root) / "temp_uploads"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Create a named temp file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.txt',
            prefix=prefix,
            dir=temp_dir,
            delete=False
        ) as f:
            f.write(content)
            return f.name

    async def create_assessment(
        self,
        name: str,
        targets_file: str,
        scope_file: str,
        profile: str = "standard",
    ) -> Dict[str, Any]:
        """
        Create a new assessment.
        
        Args:
            name: Assessment name (for API reference, not used by Cybog)
            targets_file: Path to targets file OR file content
            scope_file: Path to scope file OR file content
            profile: Pipeline profile
            
        Returns:
            Assessment response data
        """
        try:
            # Handle file content for targets_file
            targets_path = targets_file
            if self._is_file_content(targets_file):
                targets_path = self._write_content_to_temp_file(targets_file, "targets_")
                self._log.info(f"Wrote targets content to temp file: {targets_path}")
            
            # Handle file content for scope_file
            scope_path = scope_file
            if self._is_file_content(scope_file):
                scope_path = self._write_content_to_temp_file(scope_file, "scope_")
                self._log.info(f"Wrote scope content to temp file: {scope_path}")
            
            state = self._service.create(
                targets_file=targets_path,
                scope_file=scope_path,
                profile=profile,
                name=name,
            )
            
            return {
                "assessment_id": state.assessment.assessment_id,
                "name": name,
                "status": state.assessment.status.value,
                "created_at": state.assessment.created_at.isoformat(),
                "targets_file": targets_file,  # Return original input
                "scope_file": scope_file,      # Return original input
                "profile": profile,
                "artifact_root": state.assessment.artifact_root,
                "progress": {},
                "findings_count": 0,
            }
        except Exception as exc:
            self._log.error(f"Failed to create assessment: {exc}")
            raise

    async def get_assessment(self, assessment_id: str) -> Dict[str, Any]:
        """
        Get assessment details by ID.
        
        Args:
            assessment_id: Assessment identifier
            
        Returns:
            Assessment data
        """
        try:
            state = self._service.load_state(assessment_id)
            return self._format_assessment_response(state, assessment_id)
        except Exception as exc:
            self._log.error(f"Failed to load assessment {assessment_id}: {exc}")
            raise

    async def start_assessment(self, assessment_id: str) -> Dict[str, Any]:
        """
        Start an assessment execution.
        
        Args:
            assessment_id: Assessment identifier
            
        Returns:
            Execution response
        """
        try:
            state = await self._service.execute(assessment_id)
            return self._format_assessment_response(state, assessment_id)
        except Exception as exc:
            self._log.error(f"Failed to start assessment {assessment_id}: {exc}")
            raise

    def _pipeline_coroutine(self, assessment_id: str, pipeline_name: str, coro_factory):
        """
        Build, register, and return a background pipeline task.

        Duplicate-start protection is enforced here: if a non-terminal task is
        already registered for *assessment_id*, no replacement is created and
        the caller receives an ``already_running`` acknowledgement instead.

        The done callback logs any pipeline exception (the service layer already
        persists FAILED status) and removes the task from the registry only if
        it is still the exact task that was registered.
        """
        existing = _running_tasks.get(assessment_id)
        if existing is not None and not existing.done():
            return None, {
                "assessment_id": assessment_id,
                "status": "RUNNING",
                "already_running": True,
            }

        async def _run():
            try:
                await coro_factory()
            except Exception as exc:
                self._log.error(
                    f"Background {pipeline_name} error for {assessment_id}: {exc}",
                    assessment_id=assessment_id,
                )

        task = asyncio.create_task(_run())
        _running_tasks[assessment_id] = task

        def _on_done(t: "asyncio.Task[Any]") -> None:
            # Remove only if this is still the registered task (no-replacement guard).
            if _running_tasks.get(assessment_id) is t:
                _running_tasks.pop(assessment_id, None)
            if not t.cancelled():
                exc = t.exception()
                if exc is not None:
                    self._log.error(
                        f"Background {pipeline_name} exception for {assessment_id}: {exc}",
                        assessment_id=assessment_id,
                    )

        task.add_done_callback(_on_done)
        return task, {
            "assessment_id": assessment_id,
            "status": "RUNNING",
            "already_running": False,
        }

    def start_assessment_async(self, assessment_id: str) -> Dict[str, Any]:
        """
        Start an assessment in the background and return a 202 acknowledgement.

        Pre-launch validation ensures that a missing assessment yields 404 and
        a CANCELLED assessment yields 400 before any background work begins.

        If a pipeline is already running for this assessment, the response
        contains ``already_running: true`` and no new task is created.
        """
        try:
            state = self._service.load_state(assessment_id)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"No state found for assessment: {assessment_id}"
            )

        if state.assessment.status == AssessmentStatus.CANCELLED:
            raise ValueError(
                f"Assessment {assessment_id} is CANCELLED. Cannot execute."
            )

        task, response = self._pipeline_coroutine(
            assessment_id,
            "start",
            lambda: self._service.execute(assessment_id),
        )
        return response

    async def resume_assessment(self, assessment_id: str) -> Dict[str, Any]:
        """
        Resume an assessment execution.
        
        Args:
            assessment_id: Assessment identifier
            
        Returns:
            Execution response
        """
        try:
            state = await self._service.resume(assessment_id)
            return self._format_assessment_response(state, assessment_id)
        except Exception as exc:
            self._log.error(f"Failed to resume assessment {assessment_id}: {exc}")
            raise

    def resume_assessment_async(self, assessment_id: str) -> Dict[str, Any]:
        """
        Resume an assessment in the background and return a 202 acknowledgement.

        Mirrors :meth:`start_assessment_async` with the same pre-launch
        validation and duplicate-start protection.
        """
        try:
            state = self._service.load_state(assessment_id)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"No state found for assessment: {assessment_id}"
            )

        if state.assessment.status == AssessmentStatus.CANCELLED:
            raise ValueError(
                f"Assessment {assessment_id} is CANCELLED. Cannot resume."
            )

        task, response = self._pipeline_coroutine(
            assessment_id,
            "resume",
            lambda: self._service.resume(assessment_id),
        )
        return response

    async def cancel_assessment(self, assessment_id: str) -> bool:
        """
        Cancel an assessment.
        
        Args:
            assessment_id: Assessment identifier
            
        Returns:
            Success status
        """
        try:
            state = self._service.load_state(assessment_id)
            state.assessment.status = AssessmentStatus.CANCELLED
            
            from cybog.artifacts.manager import ArtifactManager
            art_mgr = ArtifactManager(
                self.config.output.root, assessment_id
            )
            state.save(art_mgr.state_path())
            
            return True
        except Exception as exc:
            self._log.error(f"Failed to cancel assessment {assessment_id}: {exc}")
            return False

    def load_state(self, assessment_id: str) -> AssessmentState:
        """
        Load the persisted AssessmentState for an assessment.

        Raises FileNotFoundError when no state file exists. Read-only: the
        caller receives the in-memory state as loaded from disk.
        """
        return self._service.load_state(assessment_id)

    async def get_assessment_status(
        self, assessment_id: str
    ) -> Dict[str, Any]:
        """
        Get the real live-status snapshot for an assessment.

        Serves both GET /assessments/{id}/status and
        GET /assessments/{id}/progress. Every value is derived from the
        persisted AssessmentState -- nothing is estimated or synthesised.
        """
        try:
            state = self.load_state(assessment_id)
            return build_progress_snapshot(state, assessment_id)
        except Exception as exc:
            self._log.error(f"Failed to get status for {assessment_id}: {exc}")
            raise

    async def get_findings(
        self, assessment_id: str, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get findings for an assessment.
        
        Args:
            assessment_id: Assessment identifier
            severity: Optional severity filter
            
        Returns:
            List of findings
        """
        try:
            state = self._service.load_state(assessment_id)
            
            findings = []
            for finding in state.findings.values():
                finding_data = {
                    "finding_id": finding.finding_id,
                    "dedup_key": finding.dedup_key,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "target_id": finding.target_id,
                    "target_domain": finding.target_domain,
                    "url": finding.url,
                    "source_tool": finding.source_tool,
                    "validation_status": finding.validation_status.value,
                    "first_seen": finding.first_seen.isoformat(),
                    "last_seen": finding.last_seen.isoformat(),
                    "occurrence_count": finding.occurrence_count,
                    "evidence": [
                        {
                            "evidence_id": evidence.evidence_id,
                            "tool": evidence.tool,
                            "raw_output": evidence.raw_output,
                            "analyst_notes": evidence.analyst_notes,
                            "validation_result": evidence.validation_result,
                            "collected_at": evidence.collected_at.isoformat(),
                        }
                        for evidence in finding.evidence
                    ],
                }
                
                if severity and finding.severity.value != severity:
                    continue
                    
                findings.append(finding_data)
                
            return findings
        except Exception as exc:
            self._log.error(f"Failed to get findings for {assessment_id}: {exc}")
            raise

    async def validate_finding(
        self,
        assessment_id: str,
        finding_id: str,
        validation_type: str = "confirm",
        notes: Optional[str] = None,
    ) -> bool:
        """
        Validate a finding (confirm or reject).
        
        Args:
            assessment_id: Assessment identifier
            finding_id: Finding ID
            validation_type: "confirm" or "reject"
            notes: Optional analyst notes
            
        Returns:
            Success status
        """
        try:
            state = self._service.load_state(assessment_id)
            finding = state.get_finding_by_id(finding_id)
            
            if not finding:
                return False
                
            if validation_type == "confirm":
                return self._service.confirm_finding(
                    assessment_id, finding.dedup_key, notes
                )
            else:  # reject
                return self._service.reject_finding(
                    assessment_id, finding.dedup_key, notes
                )
        except Exception as exc:
            self._log.error(f"Failed to validate finding {finding_id}: {exc}")
            return False

    async def get_pending_validation(
        self, assessment_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get findings awaiting validation.
        
        Args:
            assessment_id: Assessment identifier
            
        Returns:
            List of pending validation findings
        """
        return self._service.pending_validation(assessment_id)

    async def get_assessment_artifacts(
        self, assessment_id: str, artifact_type: str = "all"
    ) -> List[Dict[str, Any]]:
        """
        Get artifacts for an assessment.
        
        Args:
            assessment_id: Assessment identifier
            artifact_type: Type of artifacts to retrieve
            
        Returns:
            List of artifact metadata
        """
        try:
            state = self._service.load_state(assessment_id)
            artifacts = []
            
            # Get artifact records from state if available
            if state.artifacts:
                for artifact in state.artifacts.values():
                    artifacts.append({
                        "artifact_id": artifact.artifact_id,
                        "target_id": artifact.target_id,
                        "stage": artifact.stage,
                        "artifact_type": artifact.artifact_type.value,
                        "path": artifact.path,
                        "filename": artifact.filename,
                        "size_bytes": artifact.size_bytes,
                        "checksum": artifact.checksum,
                        "created_at": artifact.created_at.isoformat(),
                    })
            
            return artifacts
        except Exception as exc:
            self._log.error(f"Failed to get artifacts for {assessment_id}: {exc}")
            return []

    async def get_assessment_reports(
        self, assessment_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get generated reports for an assessment.
        
        Args:
            assessment_id: Assessment identifier
            
        Returns:
            List of report metadata
            
        Raises:
            FileNotFoundError: If the assessment does not exist
        """
        state = self._service.load_state(assessment_id)
        
        reports = []
        
        # Look for reports in the aggregate directory
        report_dir = Path(self.config.output.root) / assessment_id / "aggregate"
        if report_dir.exists():
            for report_file in report_dir.iterdir():
                if report_file.is_file() and report_file.suffix in [".json", ".jsonl", ".html"]:
                    stat = report_file.stat()
                    reports.append({
                        "filename": report_file.name,
                        "type": report_file.suffix.lstrip("."),
                        "path": str(report_file.relative_to(self.config.output.root)),
                        "size_bytes": stat.st_size,
                        "created_at": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    })
        
        return reports

    async def create_export(
        self,
        assessment_id: str,
        format: str = "zip",
        include_raw: bool = True,
        include_evidence: bool = True,
        include_validated_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Create an export of assessment results.

        Delegates to ExportService, which persists status to disk so status
        and download lookups work across service instances and processes.

        Args:
            assessment_id: Assessment identifier
            format: Export format (only "zip" is supported)
            include_raw: Include raw stage output in the archive
            include_evidence: Include per-finding evidence files
            include_validated_only: Only include VALIDATED/REPORTABLE findings

        Returns:
            Export task information
        """
        return await self._export_service().create_export(
            assessment_id,
            format,
            include_raw=include_raw,
            include_evidence=include_evidence,
            include_validated_only=include_validated_only,
        )

    def get_export_status(self, export_id: str) -> Optional[Dict[str, Any]]:
        """Return the persisted status for an export id, or None if unknown."""
        return self._export_service().get_status(export_id)

    def get_export_download_info(self, export_id: str) -> Optional[Dict[str, Any]]:
        """
        Return download metadata for a completed export, or None.

        None means the export is unknown or has not completed; ``ready`` is
        False when the recorded archive is missing from disk.
        """
        service = self._export_service()
        status = service.get_status(export_id)
        if status is None:
            return None
        path = service.get_export_path(export_id)
        if path is None:
            return {"ready": False, "status": status.get("status"), "path": None}
        return {"ready": True, "status": status.get("status"), "path": path}

    def _export_service(self) -> ExportService:
        """Build an ExportService bound to the configured artifact root."""
        return ExportService(self.config.output.root, assessment_service=self._service)

    def _format_assessment_response(
        self, state: AssessmentState, assessment_id: str
    ) -> Dict[str, Any]:
        """Format an assessment state into a response dictionary."""
        job_counts = state.job_counts_by_status()
        total_jobs = len(state.jobs)
        completed_jobs = (
            job_counts.get(JobStatus.COMPLETED.value, 0)
            + job_counts.get(JobStatus.SKIPPED.value, 0)
            + job_counts.get(JobStatus.CANCELLED.value, 0)
        )
        failed_jobs = job_counts.get(JobStatus.FAILED.value, 0)
        total_targets = len(state.targets)
        completed_targets = sum(
            1 for t in state.targets.values() if t.status == TargetStatus.COMPLETED
        )
        completion_percentage = (
            round(completed_jobs / total_jobs * 100, 2) if total_jobs > 0 else 0.0
        )
        name = getattr(state.assessment, "name", None) or assessment_id
        return {
            "assessment_id": assessment_id,
            "name": name,
            "status": state.assessment.status.value,
            "created_at": state.assessment.created_at.isoformat(),
            "updated_at": state.assessment.updated_at.isoformat()
            if hasattr(state.assessment, "updated_at")
            else state.assessment.created_at.isoformat(),
            "profile": state.assessment.profile,
            "artifact_root": state.assessment.artifact_root,
            "progress": {
                "total_targets": total_targets,
                "completed_targets": completed_targets,
                "total_jobs": total_jobs,
                "completed_jobs": completed_jobs,
                "failed_jobs": failed_jobs,
                "completion_percentage": completion_percentage,
            },
            "findings_count": len(state.findings),
            "pending_validation_count": state.pending_validation_count(),
        }

    async def list_assessments(self) -> List[Dict[str, Any]]:
        """
        Discover and return all persisted assessments from disk.

        Enumerates subdirectories of ``config.output.root`` and loads each
        ``state.json`` found. Directories without ``state.json`` (e.g.
        ``temp_uploads/``, ``exports/``) and any with a corrupt or
        partially-written state are skipped with a warning, so a single bad
        assessment never breaks the whole list.
        """
        root = Path(self.config.output.root)
        if not root.is_dir():
            self._log.info(f"output.root does not exist: {root}")
            return []

        results: List[Dict[str, Any]] = []
        for entry in sorted(root.iterdir(), key=lambda p: p.name):
            if not entry.is_dir():
                continue
            state_path = entry / "state.json"
            if not state_path.is_file():
                continue
            assessment_id = entry.name
            try:
                state = AssessmentState.load(state_path)
            except Exception as exc:
                self._log.warning(
                    f"Skipping unreadable state.json for {assessment_id}: {exc}"
                )
                continue
            results.append(self._format_assessment_response(state, assessment_id))

        results.sort(key=lambda r: r["created_at"], reverse=True)
        return results

    async def cleanup_completed_assessments(self) -> List[str]:
        """
        Clean up completed assessments.

        Returns:
            List of cleaned up assessment IDs
        """
        cleaned_up = []
        
        # This would clean up assessments that are no longer needed
        # For now, it's a placeholder for future implementation
        return cleaned_up
    async def get_assessment_report_file(
        self, assessment_id: str, filename: str
    ) -> Optional[Path]:
        """
        Get the path to a specific report file for an assessment.

        The file is resolved strictly inside
        ``<output.root>/<assessment_id>/aggregate/``:

        * both ``assessment_id`` and ``filename`` must be single, traversal-free
          path components (so one assessment can never address another's files);
        * ``filename`` must be one of :data:`KNOWN_REPORT_FILES`;
        * symlinks are rejected outright (report files are never symlinks);
        * the fully resolved path must still be inside the ``aggregate/`` dir.

        Args:
            assessment_id: Assessment identifier
            filename: Report filename (must be one of the known report files)

        Returns:
            Path to the report file if it exists, None otherwise

        Raises:
            InvalidExportRequest: If the id/filename is unsafe or not allowlisted
        """
        from app.services.export_service import InvalidExportRequest

        if not _is_safe_component(assessment_id):
            raise InvalidExportRequest("Invalid assessment id")

        if not _is_safe_component(filename):
            raise InvalidExportRequest("Path traversal attempt in filename")

        if filename not in KNOWN_REPORT_FILES:
            raise InvalidExportRequest("Unknown report file")

        aggregate_dir = Path(self.config.output.root) / assessment_id / "aggregate"
        try:
            aggregate_dir = aggregate_dir.resolve()
        except OSError:
            return None

        candidate = aggregate_dir / filename

        # Refuse symlinks: resolve() would otherwise silently follow one out of
        # the aggregate directory.
        if candidate.is_symlink():
            raise InvalidExportRequest("Report file must not be a symlink")

        file_path = candidate.resolve()
        try:
            file_path.relative_to(aggregate_dir)
        except ValueError:
            raise InvalidExportRequest("Path traversal attempt")

        if not file_path.is_file():
            return None

        return file_path

    async def get_assessment_report_file_inline(
        self, assessment_id: str, filename: str
    ) -> Optional[Path]:
        """
        Get the path to a specific report file for inline viewing (HTML only).

        This is the same as get_assessment_report_file but only allows HTML files.
        """
        if not filename.lower().endswith('.html'):
            return None
        return await self.get_assessment_report_file(assessment_id, filename)
