"""
app/services/export_service.py

Builds downloadable ZIP exports of a Cybog assessment.

Everything is derived from the on-disk artifact tree produced by
``cybog.artifacts.manager.ArtifactManager``::

    <output_root>/<assessment_id>/
        state.json
        manifest.json
        targets/<target_id>/metadata.json
        targets/<target_id>/<stage>/attempt_<N>/{raw.*,normalized.json,stdout.log,stderr.log,execution.json}
        aggregate/{findings.jsonl,findings.json,summary.json,report.html}

Produced archive layout (one directory per target, named after the target
domain, plus a ``_manifest/`` directory at the archive root)::

    <domain>/
        report/report.html          aggregate report, copied verbatim
        report/findings.json        per-target findings (honours filters)
        findings/finding-<fid>.json one file per exported finding
        evidence/<tool>-<fid>.json  one file per evidence item
        recon/subfinder-raw.jsonl   raw stage output, highest attempt wins
        discovery/dnsx-raw.jsonl
        discovery/httpx-raw.jsonl
        discovery/naabu-raw.jsonl
        crawl/katana-raw.jsonl
        crawl/ffuf-raw.jsonl
        scanning/nuclei-raw.jsonl
        artifacts/metadata.json     copied from targets/<tid>/metadata.json
        artifacts/<stage>/          stdout.log stderr.log normalized.json execution.json
    _manifest/assessment.json
    _manifest/targets.json
    _manifest/execution-summary.json
    _manifest/export-manifest.json

Stage -> group mapping (``STAGE_GROUPS``)::

    subfinder            -> recon
    dnsx, httpx, naabu   -> discovery
    katana, ffuf         -> crawl
    nuclei               -> scanning
    <anything else>      -> other

Every export is tracked by a ``status.json`` file inside
``<output_root>/exports/<export_id>/`` so that status and download lookups
work across processes and across freshly constructed service instances.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cybog.state.assessment_state import AssessmentState

EXPORT_VERSION = "1.0"
SUPPORTED_FORMATS = frozenset({"zip"})
EXPORT_TTL_HOURS = 24

STATUS_PENDING = "pending"
STATUS_IN_PROGRESS = "in_progress"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

# Identifiers coming from the URL must be boring. Note that this pattern also
# admits "." and ".." (both consist only of allowed characters), so callers
# additionally reject any resolved path that escapes the output root.
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

STAGE_GROUPS: Dict[str, str] = {
    "subfinder": "recon",
    "dnsx": "discovery",
    "httpx": "discovery",
    "naabu": "discovery",
    "katana": "crawl",
    "ffuf": "crawl",
    "nuclei": "scanning",
}
DEFAULT_GROUP = "other"

# Raw output file names, in the order they are probed.
RAW_FILENAMES: Tuple[str, ...] = ("raw.jsonl", "raw.json", "raw.txt")
# Per-stage side files copied verbatim into ``artifacts/<stage>/``.
STAGE_SIDECARS: Tuple[str, ...] = (
    "stdout.log",
    "stderr.log",
    "normalized.json",
    "execution.json",
)

# Only these validation statuses survive ``include_validated_only=True``.
REPORTABLE_STATUSES = frozenset({"VALIDATED", "REPORTABLE"})

MANIFEST_DIR = "_manifest"
MANIFEST_FILES = (
    f"{MANIFEST_DIR}/assessment.json",
    f"{MANIFEST_DIR}/targets.json",
    f"{MANIFEST_DIR}/execution-summary.json",
    f"{MANIFEST_DIR}/export-manifest.json",
)
EXPORT_MANIFEST_ARC = f"{MANIFEST_DIR}/export-manifest.json"

# Width of the filler field that keeps the export manifest a constant number of
# bytes long. See ``_write_zip_with_manifest``: it absorbs the digit-count delta
# of ``total_size_bytes`` so the archive size stops depending on its own value.
# 24 leaves room for sizes up to 1e23 bytes, far beyond a realistic ZIP.
MANIFEST_PAD_WIDTH = 24

# ``cleanup_expired`` is O(number of export dirs); run it opportunistically from
# export creation but no more than once per hour per process. No scheduler.
_CLEANUP_INTERVAL_SECONDS = 3600.0
_last_cleanup_monotonic: float = 0.0

# Characters that are unsafe in a directory name inside an archive.
_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class ExportError(RuntimeError):
    """Raised when an export cannot be built."""


class InvalidExportRequest(ValueError):
    """Raised when caller-supplied identifiers or options are unsafe/invalid."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Any) -> Optional[str]:
    """Best-effort ISO8601 rendering for datetimes / strings / None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _json_dumps(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def validate_identifier(value: Any, kind: str = "identifier") -> str:
    """
    Validate a caller-supplied identifier taken from a URL.

    Rejects anything outside ``[A-Za-z0-9._-]{1,128}`` and the relative
    components ``.`` / ``..`` (which the character class alone permits).
    """
    if not isinstance(value, str) or not value:
        raise InvalidExportRequest(f"Invalid {kind}")
    if "\x00" in value or not SAFE_ID_RE.match(value):
        raise InvalidExportRequest(f"Invalid {kind}")
    if value in (".", "..") or ".." in value:
        raise InvalidExportRequest(f"Invalid {kind}")
    return value


def sanitize_component(value: str, fallback: str = "unnamed") -> str:
    """
    Turn an arbitrary string (a target domain, say) into a safe single path
    component usable as a directory name inside the archive.

    Strips path separators, ``..``, control characters and NUL; never returns
    an empty or dotted name.
    """
    if not isinstance(value, str):
        value = ""
    cleaned = _UNSAFE_NAME_RE.sub("-", value)
    cleaned = cleaned.strip("-. ")
    if not cleaned or set(cleaned) <= {"."}:
        cleaned = fallback
    return cleaned[:96]


class ExportService:
    """
    Builds and tracks ZIP exports for a Cybog assessment.

    The service holds no authoritative in-memory state: status lives in
    ``<output_root>/exports/<export_id>/status.json`` so that a freshly
    constructed instance (which is what ``get_cybog_service()`` produces on
    every request) can answer status and download requests.
    """

    def __init__(
        self,
        output_root: str | Path,
        assessment_service: Any = None,
        ttl_hours: int = EXPORT_TTL_HOURS,
    ) -> None:
        self.output_root = Path(output_root)
        self._assessment_service = assessment_service
        self.ttl_hours = ttl_hours

    # ------------------------------------------------------------------
    # Paths and path safety
    # ------------------------------------------------------------------
    @property
    def exports_root(self) -> Path:
        return self.output_root / "exports"

    def _resolve_within(self, base: Path, *parts: str) -> Path:
        """
        Resolve ``base/parts...`` and guarantee the result stays inside base.

        Raises ``InvalidExportRequest`` if the resolved path escapes, which
        catches symlinks and ``..`` sequences that survive the regex check.
        """
        candidate = base.joinpath(*parts)
        resolved = candidate.resolve()
        base_resolved = base.resolve()
        if not (resolved == base_resolved or resolved.is_relative_to(base_resolved)):
            raise InvalidExportRequest(
                f"Path escapes the allowed root: {'/'.join(parts)}"
            )
        return resolved

    def export_dir(self, export_id: str) -> Path:
        """Validated, contained directory for an export id."""
        validate_identifier(export_id, "export_id")
        return self._resolve_within(self.exports_root, export_id)

    def assessment_dir(self, assessment_id: str) -> Path:
        """Validated, contained artifact directory for an assessment id."""
        validate_identifier(assessment_id, "assessment_id")
        return self._resolve_within(self.output_root, assessment_id)

    def _archive_source(self, path: Path, root: Path) -> Optional[Path]:
        """
        Return ``path`` if it is a readable regular file that stays inside
        ``root`` and is not a symlink, else ``None``.

        Symlinks are refused outright rather than resolved so that a link
        planted in the artifact tree cannot pull in files from elsewhere.
        """
        if path.is_symlink():
            return None
        try:
            if not path.is_file():
                return None
            root_resolved = root.resolve()
            resolved = path.resolve()
            if not (resolved == root_resolved or resolved.is_relative_to(root_resolved)):
                return None
        except OSError:
            return None
        return path

    # ------------------------------------------------------------------
    # Status persistence
    # ------------------------------------------------------------------
    def _status_path(self, export_id: str) -> Path:
        return self.export_dir(export_id) / "status.json"

    def _write_status(self, export_id: str, payload: Dict[str, Any]) -> None:
        path = self._status_path(export_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name("status.json.tmp")
        tmp.write_text(_json_dumps(payload), encoding="utf-8")
        os.replace(tmp, path)

    def get_status(self, export_id: str) -> Optional[Dict[str, Any]]:
        """Read the persisted status for ``export_id``; ``None`` if unknown.

        Raises ``InvalidExportRequest`` for unsafe identifiers so callers can
        distinguish a malformed request from an unknown export.
        """
        path = self._status_path(export_id)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def get_export_path(self, export_id: str) -> Optional[Path]:
        """Path of the finished archive, only when the export completed."""
        status = self.get_status(export_id)
        if not status or status.get("status") != STATUS_COMPLETED:
            return None
        archive_name = status.get("archive_name") or f"{export_id}.zip"
        try:
            path = self._resolve_within(self.export_dir(export_id), archive_name)
        except InvalidExportRequest:
            return None
        if path.is_symlink() or not path.is_file():
            return None
        return path

    def cleanup_expired(self, max_age_hours: Optional[float] = None) -> List[str]:
        """
        Delete export directories older than the TTL.

        Returns the ids that were removed. Uses the on-disk modification time
        so it works without any in-memory bookkeeping.
        """
        hours = self.ttl_hours if max_age_hours is None else max_age_hours
        if hours is None or hours < 0:
            return []
        cutoff = time.time() - hours * 3600
        removed: List[str] = []
        root = self.exports_root
        if not root.is_dir():
            return removed
        for entry in sorted(root.iterdir()):
            try:
                if not entry.is_dir() or entry.is_symlink():
                    continue
                if entry.stat().st_mtime >= cutoff:
                    continue
                validate_identifier(entry.name, "export_id")
                target = self._resolve_within(root, entry.name)
                if target != entry.resolve():
                    continue
                shutil.rmtree(target, ignore_errors=True)
                removed.append(entry.name)
            except (OSError, InvalidExportRequest):
                continue
        return removed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def create_export(
        self,
        assessment_id: str,
        format: str = "zip",
        include_raw: bool = True,
        include_evidence: bool = True,
        include_validated_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Create an export and schedule the build.

        Writes ``status.json`` with ``pending`` synchronously so the status is
        visible to any other process, then kicks off the build on a background
        asyncio task and returns immediately.
        """
        export_id, status, fmt, options = self._begin_export(
            assessment_id, format, include_raw, include_evidence, include_validated_only
        )

        coro = self._run_build(export_id, assessment_id, fmt, options)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No event loop (e.g. called from a sync context): build inline so
            # the caller still gets a usable export.
            asyncio.run(coro)
            return self.get_status(export_id) or status

        task = asyncio.create_task(coro)
        self._track_task(task, export_id)
        return dict(status)

    def create_export_sync(
        self,
        assessment_id: str,
        format: str = "zip",
        include_raw: bool = True,
        include_evidence: bool = True,
        include_validated_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Build an export inline and return the terminal status record.

        Same effect as :meth:`create_export` but without the background task,
        for callers that already run in a worker thread (CLI, tests).
        """
        export_id, status, fmt, options = self._begin_export(
            assessment_id, format, include_raw, include_evidence, include_validated_only
        )
        self._finish_build(export_id, assessment_id, fmt, options)
        return self.get_status(export_id) or status

    def _begin_export(
        self,
        assessment_id: str,
        format: str,
        include_raw: bool,
        include_evidence: bool,
        include_validated_only: bool,
    ) -> Tuple[str, Dict[str, Any], str, Dict[str, bool]]:
        """Validate the request and persist the initial ``pending`` record."""
        fmt = (format or "zip").strip().lower()
        if fmt not in SUPPORTED_FORMATS:
            raise InvalidExportRequest(
                f"Unsupported export format '{format}'. Supported: zip"
            )
        assessment_id = validate_identifier(assessment_id, "assessment_id")

        export_id = str(uuid.uuid4())
        # Creating the directory validates the id and keeps it inside root.
        export_dir = self.export_dir(export_id)
        export_dir.mkdir(parents=True, exist_ok=True)

        options = {
            "include_raw": bool(include_raw),
            "include_evidence": bool(include_evidence),
            "include_validated_only": bool(include_validated_only),
        }
        status: Dict[str, Any] = {
            "export_id": export_id,
            "assessment_id": assessment_id,
            "format": fmt,
            "status": STATUS_PENDING,
            "created_at": _utcnow().isoformat(),
            "started_at": None,
            "completed_at": None,
            "expires_at": (_utcnow() + timedelta(hours=self.ttl_hours)).isoformat(),
            "error": None,
            "file_size_bytes": None,
            "file_count": None,
            "archive_name": f"{export_id}.zip",
            "options": options,
        }
        self._write_status(export_id, status)
        self._maybe_cleanup_expired()
        return export_id, status, fmt, options

    def _maybe_cleanup_expired(self) -> None:
        """
        Opportunistically reclaim expired export directories.

        Scans the exports root, so it runs at most once per hour per process
        rather than on every request. Failures are swallowed: housekeeping must
        never fail an export.
        """
        global _last_cleanup_monotonic
        now = time.monotonic()
        if now - _last_cleanup_monotonic < _CLEANUP_INTERVAL_SECONDS:
            return
        _last_cleanup_monotonic = now
        try:
            self.cleanup_expired()
        except OSError:
            pass

    def _track_task(self, task: "asyncio.Task[Any]", export_id: str) -> None:
        """Keep a strong reference so the task is not garbage collected."""
        registry = getattr(self, "_tasks", None)
        if registry is None:
            registry = set()
            self._tasks = registry  # type: ignore[attr-defined]
        registry.add(task)
        task.add_done_callback(registry.discard)

    async def _run_build(
        self,
        export_id: str,
        assessment_id: str,
        fmt: str,
        options: Dict[str, bool],
    ) -> None:
        """Run the build off the event loop, recording terminal status."""
        await asyncio.to_thread(self._finish_build, export_id, assessment_id, fmt, options)

    def _finish_build(
        self,
        export_id: str,
        assessment_id: str,
        fmt: str,
        options: Dict[str, bool],
    ) -> Dict[str, Any]:
        """
        Build the archive synchronously and record the terminal status.

        A build failure is recorded as ``status: failed`` with an ``error``
        message rather than propagating, so the API never 500s on a bad export.
        """
        status = self.get_status(export_id) or {}
        status["status"] = STATUS_IN_PROGRESS
        status["started_at"] = _utcnow().isoformat()
        status["error"] = None
        self._write_status(export_id, status)
        try:
            result = self.build_archive(export_id, assessment_id, fmt, options)
        except Exception as exc:  # noqa: BLE001 - failures are recorded, not raised
            failure = self.get_status(export_id) or status
            failure["status"] = STATUS_FAILED
            failure["error"] = f"{type(exc).__name__}: {exc}"
            failure["completed_at"] = _utcnow().isoformat()
            failure["file_size_bytes"] = None
            failure["file_count"] = None
            self._write_status(export_id, failure)
            return failure

        final = self.get_status(export_id) or status
        final["status"] = STATUS_COMPLETED
        final["completed_at"] = _utcnow().isoformat()
        final["file_size_bytes"] = result["total_size_bytes"]
        final["file_count"] = result["total_files"]
        final["archive_name"] = result["archive_name"]
        final["error"] = None
        self._write_status(export_id, final)
        return final

    async def wait_for_completion(
        self, export_id: str, timeout: float = 60.0, poll_interval: float = 0.02
    ) -> Optional[Dict[str, Any]]:
        """
        Poll ``status.json`` until the export reaches a terminal status.

        Returns the terminal status dict, or ``None`` on timeout. Safe to call
        from tests and from a different process than the one building.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            status = self.get_status(export_id)
            if status and status.get("status") in (STATUS_COMPLETED, STATUS_FAILED):
                return status
            if loop.time() >= deadline:
                return status
            await asyncio.sleep(poll_interval)

    # ------------------------------------------------------------------
    # Archive construction (synchronous; runs in a worker thread)
    # ------------------------------------------------------------------
    def build_archive(
        self,
        export_id: str,
        assessment_id: str,
        fmt: str = "zip",
        options: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        """
        Build the ZIP for an assessment and return summary info.

        Raises ``ExportError`` if the assessment state cannot be read; callers
        record that as ``status: failed``.
        """
        options = options or {}
        include_raw = bool(options.get("include_raw", True))
        include_evidence = bool(options.get("include_evidence", True))
        include_validated_only = bool(options.get("include_validated_only", False))

        assessment_dir = self.assessment_dir(assessment_id)
        state_path = assessment_dir / "state.json"
        if not state_path.is_file():
            raise ExportError(f"No state.json for assessment '{assessment_id}'")
        try:
            state = AssessmentState.load(state_path)
        except Exception as exc:  # noqa: BLE001
            raise ExportError(f"Unreadable state.json: {exc}") from exc

        export_dir = self.export_dir(export_id)
        export_dir.mkdir(parents=True, exist_ok=True)
        archive_name = f"{export_id}.zip"
        archive_path = export_dir / archive_name

        dir_names = self._target_dir_names(state)

        # Collect (arcname, source_path) / (arcname, bytes) entries.
        entries: List[Tuple[str, Any]] = []
        for target in state.targets.values():
            entries.extend(
                self._collect_target_entries(
                    assessment_dir,
                    target,
                    dir_names[target.target_id],
                    state,
                    include_raw,
                    include_evidence,
                    include_validated_only,
                )
            )

        exported_findings = [
            f for f in state.findings.values() if self._finding_exported(f, include_validated_only)
        ]
        entries.append(
            (
                f"{MANIFEST_DIR}/assessment.json",
                _json_dumps(self._assessment_manifest(state, exported_findings)).encode("utf-8"),
            )
        )
        entries.append(
            (
                f"{MANIFEST_DIR}/targets.json",
                _json_dumps(self._targets_manifest(state)).encode("utf-8"),
            )
        )
        entries.append(
            (
                f"{MANIFEST_DIR}/execution-summary.json",
                _json_dumps(
                    self._execution_summary(
                        state,
                        exported_findings,
                        include_raw,
                        include_evidence,
                        include_validated_only,
                    )
                ).encode("utf-8"),
            )
        )

        # Record the archive in write order so file_list mirrors namelist().
        file_list = [arc for arc, _ in entries] + [EXPORT_MANIFEST_ARC]

        total_size, total_files = self._write_zip_with_manifest(
            archive_path,
            entries,
            export_id,
            assessment_id,
            fmt,
            file_list,
        )
        return {
            "archive_name": archive_name,
            "archive_path": str(archive_path),
            "total_size_bytes": total_size,
            "total_files": total_files,
        }

    # -- manifest builders ------------------------------------------------
    @staticmethod
    def _finding_exported(finding: Any, include_validated_only: bool) -> bool:
        if not include_validated_only:
            return True
        status = getattr(finding.validation_status, "value", finding.validation_status)
        return str(status) in REPORTABLE_STATUSES

    def _assessment_manifest(
        self, state: AssessmentState, exported: Iterable[Any]
    ) -> Dict[str, Any]:
        a = state.assessment
        counts = state.validation_counts()
        statuses = list(exported)
        return {
            "assessment_id": a.assessment_id,
            "name": getattr(a, "name", None),
            "profile": a.profile,
            "status": a.status.value,
            "status_message": a.error,
            "created_at": _iso(a.created_at),
            "started_at": _iso(a.started_at),
            "completed_at": _iso(a.completed_at),
            "total_targets": len(state.targets),
            "completed_targets": sum(
                1 for t in state.targets.values() if t.status.value == "COMPLETED"
            ),
            "total_findings": len(statuses),
            "validated_findings": counts.get("VALIDATED", 0) + counts.get("REPORTABLE", 0),
            "false_positive_findings": counts.get("FALSE_POSITIVE", 0),
            "pending_validation_findings": state.pending_validation_count(),
            "artifact_root": a.artifact_root or str(self.output_root / a.assessment_id),
            "config_snapshot": a.config_snapshot or {},
            "exported_at": _utcnow().isoformat(),
            "export_version": EXPORT_VERSION,
        }

    def _targets_manifest(self, state: AssessmentState) -> Dict[str, Any]:
        def row(t: Any) -> Dict[str, Any]:
            return {"target_id": t.target_id, "domain": t.domain, "status": t.status.value}

        targets = sorted(state.targets.values(), key=lambda t: t.target_id)
        in_scope = [row(t) for t in targets if t.status.value in ("IN_SCOPE", "COMPLETED", "RUNNING")]
        out_of_scope = [row(t) for t in targets if t.status.value == "OUT_OF_SCOPE"]
        return {
            "assessment_id": state.assessment.assessment_id,
            "targets_file": state.assessment.target_input_file,
            "targets": [row(t) for t in targets],
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
        }

    def _execution_summary(
        self,
        state: AssessmentState,
        exported: List[Any],
        include_raw: bool,
        include_evidence: bool,
        include_validated_only: bool,
    ) -> Dict[str, Any]:
        job_counts = state.job_counts_by_status()
        per_target: List[Dict[str, Any]] = []
        for target_id in sorted(state.targets):
            jobs = state.get_jobs_for_target(target_id)
            counts: Dict[str, int] = {}
            for job in jobs:
                counts[job.status.value] = counts.get(job.status.value, 0) + 1
            target = state.targets[target_id]
            per_target.append(
                {
                    "target_id": target_id,
                    "domain": target.domain,
                    "jobs_total": len(jobs),
                    "jobs_completed": counts.get("COMPLETED", 0),
                    "jobs_failed": counts.get("FAILED", 0),
                    "jobs_skipped": counts.get("SKIPPED", 0) + counts.get("CANCELLED", 0),
                    "findings_count": sum(1 for f in exported if f.target_id == target_id),
                }
            )
        return {
            "assessment_id": state.assessment.assessment_id,
            "total_jobs": len(state.jobs),
            "completed_jobs": job_counts.get("COMPLETED", 0),
            "failed_jobs": job_counts.get("FAILED", 0),
            "skipped_jobs": job_counts.get("SKIPPED", 0) + job_counts.get("CANCELLED", 0),
            "total_findings": len(exported),
            "findings_by_severity": _count_exported(exported, lambda f: f.severity.value),
            "findings_by_validation_status": _count_exported(
                exported, lambda f: f.validation_status.value
            ),
            "per_target_summary": per_target,
            "export_summary": {
                "export_version": EXPORT_VERSION,
                "include_raw": include_raw,
                "include_evidence": include_evidence,
                "include_validated_only": include_validated_only,
                "stage_groups": dict(STAGE_GROUPS),
                "exported_at": _utcnow().isoformat(),
            },
        }

    # -- per-target entry collection --------------------------------------
    def _target_dir_names(self, state: AssessmentState) -> Dict[str, str]:
        """
        Map target_id -> unique, safe directory name inside the archive.

        Names are derived from the domain; collisions (and sanitised-to-empty
        domains) are disambiguated with the target_id suffix.
        """
        names: Dict[str, str] = {}
        used: set[str] = set()
        ordered = sorted(state.targets.values(), key=lambda t: t.target_id)
        for target in ordered:
            base = sanitize_component(target.domain, fallback=f"target-{target.target_id}")
            name = base
            suffix = 1
            while name in used:
                suffix += 1
                name = f"{base}-{sanitize_component(target.target_id, 't')}-{suffix}"
            used.add(name)
            names[target.target_id] = name
        return names

    def _collect_target_entries(
        self,
        assessment_dir: Path,
        target: Any,
        dir_name: str,
        state: AssessmentState,
        include_raw: bool,
        include_evidence: bool,
        include_validated_only: bool,
    ) -> List[Tuple[str, Any]]:
        entries: List[Tuple[str, Any]] = []
        target_dir = assessment_dir / "targets" / target.target_id
        prefix = f"{dir_name}"

        # -- report.html from the aggregate directory
        report_src = self._archive_source(assessment_dir / "aggregate" / "report.html", assessment_dir)
        if report_src is not None:
            entries.append((f"{prefix}/report/report.html", report_src))

        findings = sorted(
            state.get_findings_for_target(target.target_id),
            key=lambda f: f.finding_id,
        )
        exported = [f for f in findings if self._finding_exported(f, include_validated_only)]

        entries.append(
            (
                f"{prefix}/report/findings.json",
                _json_dumps([f.model_dump() for f in exported]).encode("utf-8"),
            )
        )

        for finding in exported:
            entries.append(
                (
                    f"{prefix}/findings/finding-{finding.finding_id}.json",
                    _json_dumps(finding.model_dump()).encode("utf-8"),
                )
            )
            if include_evidence:
                for index, evidence in enumerate(finding.evidence):
                    name = sanitize_component(
                        f"{finding.source_tool}-{finding.finding_id}", "evidence"
                    )
                    if index:
                        name = f"{name}-{index}"
                    entries.append(
                        (
                            f"{prefix}/evidence/{name}.json",
                            _json_dumps(evidence.model_dump()).encode("utf-8"),
                        )
                    )

        # -- stage artifacts
        if target_dir.is_dir() and not target_dir.is_symlink():
            entries.extend(
                self._collect_stage_entries(target_dir, prefix, assessment_dir, include_raw)
            )
            meta = self._archive_source(target_dir / "metadata.json", assessment_dir)
            if meta is not None:
                entries.append((f"{prefix}/artifacts/metadata.json", meta))
        return entries

    def _collect_stage_entries(
        self,
        target_dir: Path,
        prefix: str,
        assessment_dir: Path,
        include_raw: bool,
    ) -> List[Tuple[str, Any]]:
        """
        Copy raw output and per-stage side files.

        Only the highest-numbered ``attempt_<N>`` directory for each stage is
        considered, so the export reflects the latest attempt and is
        deterministic regardless of how many retries happened.
        """
        entries: List[Tuple[str, Any]] = []
        try:
            stage_dirs = sorted(p for p in target_dir.iterdir() if p.is_dir() and not p.is_symlink())
        except OSError:
            return entries

        for stage_dir in stage_dirs:
            stage = stage_dir.name
            group = STAGE_GROUPS.get(stage, DEFAULT_GROUP)
            attempt = self._latest_attempt(stage_dir)
            if attempt is None:
                continue

            if include_raw:
                raw_name = next(
                    (n for n in RAW_FILENAMES if (attempt / n).is_file()), None
                )
                if raw_name is not None:
                    src = self._archive_source(attempt / raw_name, assessment_dir)
                    if src is not None:
                        ext = raw_name.split(".", 1)[1]
                        entries.append((f"{prefix}/{group}/{stage}-raw.{ext}", src))

            for sidecar in STAGE_SIDECARS:
                candidate = attempt / sidecar
                if not candidate.is_file():
                    continue
                src = self._archive_source(candidate, assessment_dir)
                if src is not None:
                    entries.append((f"{prefix}/artifacts/{stage}/{sidecar}", src))
        return entries

    @staticmethod
    def _latest_attempt(stage_dir: Path) -> Optional[Path]:
        """Highest ``attempt_<N>`` sub-directory, or None."""
        best: Optional[Path] = None
        best_n = -1
        try:
            children = list(stage_dir.iterdir())
        except OSError:
            return None
        for child in children:
            if not child.is_dir() or child.is_symlink():
                continue
            match = re.fullmatch(r"attempt_(\d+)", child.name)
            if not match:
                continue
            n = int(match.group(1))
            if n > best_n:
                best_n, best = n, child
        return best

    # -- zip writing ------------------------------------------------------
    def _write_zip_with_manifest(
        self,
        archive_path: Path,
        entries: List[Tuple[str, Any]],
        export_id: str,
        assessment_id: str,
        fmt: str,
        file_list: List[str],
    ) -> Tuple[int, int]:
        """
        Write the archive so the manifest's ``total_size_bytes`` is exact.

        Chicken-and-egg: ``export-manifest.json`` must report the archive's own
        size, which depends on the manifest's own bytes. Two properties make
        this solvable exactly instead of by iteration:

        1. The manifest entry is STORED, not deflated. Deflate output length is
           not a function of input length (two manifests of identical length
           can compress to different sizes), which is precisely why the
           previous fixed-point loop oscillated. Stored, the entry's on-disk
           length equals its byte length, so the archive size depends only on
           the manifest's *length*.
        2. A ``_pad`` filler absorbs the digit-count delta of
           ``total_size_bytes``, keeping that length constant.

        So: write once with a placeholder, measure the real size M, then
        rewrite with ``total_size_bytes = M`` and the pad shrunk by exactly the
        digit delta. The rewrite is byte-for-byte the same length as the
        placeholder, so the archive is the same size M. The equality is
        asserted before ``os.replace`` commits anything.
        """
        tmp_path = archive_path.with_name(archive_path.name + ".tmp")
        # Fixed once so a pass boundary landing exactly on a whole second (isoformat
        # then drops its microseconds) cannot change the manifest's length.
        created_at = _utcnow()
        expires_at = created_at + timedelta(hours=self.ttl_hours)

        def manifest_bytes(total_size_bytes: int) -> bytes:
            digits = len(str(total_size_bytes))
            pad = MANIFEST_PAD_WIDTH - (digits - 1)
            if pad < 0:
                raise ExportError(
                    f"Archive size {total_size_bytes} exceeds the padded manifest budget"
                )
            manifest = {
                "export_id": export_id,
                "assessment_id": assessment_id,
                "format": fmt,
                "total_size_bytes": total_size_bytes,
                "total_files": len(file_list),
                "target_count": len({
                    arc.split("/", 1)[0]
                    for arc in file_list
                    if not arc.startswith(MANIFEST_DIR)
                }),
                "created_at": created_at.isoformat(),
                "expires_at": expires_at.isoformat(),
                "file_list": list(file_list),
                "_pad": "." * pad,
            }
            return _json_dumps(manifest).encode("utf-8")

        def write_archive(manifest: bytes) -> int:
            with zipfile.ZipFile(
                tmp_path, "w", compression=zipfile.ZIP_DEFLATED
            ) as zf:
                for arc, source in entries:
                    if isinstance(source, (bytes, bytearray)):
                        zf.writestr(arc, source)
                    else:
                        zf.write(source, arc)
                # Written last so it is also last in namelist(). Stored, so its
                # compressed length is exactly its byte length.
                zf.writestr(
                    EXPORT_MANIFEST_ARC,
                    manifest,
                    compress_type=zipfile.ZIP_STORED,
                )
            return tmp_path.stat().st_size

        placeholder = manifest_bytes(0)
        measured = write_archive(placeholder)

        final = manifest_bytes(measured)
        if len(final) != len(placeholder):
            # Would break the length invariant that makes the second write a
            # fixed point; fail loudly rather than commit a wrong size.
            raise ExportError("Export manifest padding failed to hold its length")

        total_size = write_archive(final)
        if total_size != measured:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise ExportError(
                "Export manifest size did not converge: recorded "
                f"{measured} but archive is {total_size}"
            )

        os.replace(tmp_path, archive_path)
        return total_size, len(file_list)


def _count_exported(items: Iterable[Any], key) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        value = key(item)
        counts[value] = counts.get(value, 0) + 1
    return counts