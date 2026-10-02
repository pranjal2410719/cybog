"""
cybog/artifacts/manager.py

ArtifactManager — controls all file I/O for pipeline artifacts.
Enforces immutability after stage completion.
All paths stored relative to artifact_root for portability.

Layout:
    <root>/
        <assessment_id>/
            state.json
            manifest.json
            targets/
                <target_id>/
                    metadata.json
                    <stage>/
                        attempt_<N>/
                            raw.jsonl | raw.json | raw.txt
                            normalized.json
                            stdout.log
                            stderr.log
                            execution.json
            aggregate/
                findings.jsonl
                findings.json
                summary.json
                report.html
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from cybog.models.artifact import Artifact, ArtifactType


class ArtifactManager:
    def __init__(self, output_root: str | Path, assessment_id: str):
        self.root = Path(output_root) / assessment_id
        self.assessment_id = assessment_id
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Directory helpers
    # ------------------------------------------------------------------
    def assessment_dir(self) -> Path:
        return self.root

    def target_dir(self, target_id: str) -> Path:
        d = self.root / "targets" / target_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def stage_dir(self, target_id: str, stage: str, attempt: int = 1) -> Path:
        d = self.target_dir(target_id) / stage / f"attempt_{attempt}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def aggregate_dir(self) -> Path:
        d = self.root / "aggregate"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------
    def write_text(self, path: Path, content: str, immutable: bool = False) -> Path:
        """Write text content to path. Raises if immutable and file exists."""
        if immutable and path.exists():
            raise FileExistsError(
                f"Artifact is immutable and already exists: {path}"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)
        return path

    def write_json(self, path: Path, data: dict | list, immutable: bool = False) -> Path:
        return self.write_text(path, json.dumps(data, indent=2, default=str), immutable)

    def write_bytes(self, path: Path, data: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
        return path

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------
    def read_text(self, path: Path) -> str:
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    def read_json(self, path: Path) -> dict | list:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # Stage artifact writers
    # ------------------------------------------------------------------
    def save_stdout(self, target_id: str, stage: str, attempt: int, content: str) -> Path:
        p = self.stage_dir(target_id, stage, attempt) / "stdout.log"
        return self.write_text(p, content)

    def save_stderr(self, target_id: str, stage: str, attempt: int, content: str) -> Path:
        p = self.stage_dir(target_id, stage, attempt) / "stderr.log"
        return self.write_text(p, content)

    def save_raw_output(
        self, target_id: str, stage: str, attempt: int,
        content: str, ext: str = "jsonl", immutable: bool = True
    ) -> Path:
        p = self.stage_dir(target_id, stage, attempt) / f"raw.{ext}"
        return self.write_text(p, content, immutable=False)  # allow overwrite on retry

    def save_normalized(
        self, target_id: str, stage: str, attempt: int, data: dict | list
    ) -> Path:
        p = self.stage_dir(target_id, stage, attempt) / "normalized.json"
        return self.write_json(p, data)

    def save_execution_meta(
        self, target_id: str, stage: str, attempt: int, meta: dict
    ) -> Path:
        p = self.stage_dir(target_id, stage, attempt) / "execution.json"
        return self.write_json(p, meta)

    # ------------------------------------------------------------------
    # Artifact record creation
    # ------------------------------------------------------------------
    def make_artifact(
        self,
        path: Path,
        artifact_type: ArtifactType,
        target_id: Optional[str] = None,
        stage: Optional[str] = None,
        job_id: Optional[str] = None,
        attempt: int = 1,
    ) -> Artifact:
        rel = str(path.relative_to(self.root.parent))
        size = path.stat().st_size if path.exists() else 0
        chk = self._checksum(path) if path.exists() else None
        return Artifact(
            artifact_id=f"art-{hashlib.md5(rel.encode()).hexdigest()[:12]}",
            assessment_id=self.assessment_id,
            target_id=target_id,
            stage=stage,
            job_id=job_id,
            attempt=attempt,
            artifact_type=artifact_type,
            path=rel,
            filename=path.name,
            size_bytes=size,
            checksum=chk,
        )

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------
    def state_path(self) -> Path:
        return self.root / "state.json"

    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
    def relative_path(self, absolute: Path) -> str:
        try:
            return str(absolute.relative_to(self.root.parent))
        except ValueError:
            return str(absolute)

    @staticmethod
    def _checksum(path: Path) -> str:
        h = hashlib.md5()
        h.update(path.read_bytes())
        return h.hexdigest()

    def stage_has_completed_artifact(self, target_id: str, stage: str) -> bool:
        """Check if a stage already has a completed execution.json (idempotency)."""
        exec_path = self.stage_dir(target_id, stage, 1) / "execution.json"
        if not exec_path.exists():
            return False
        try:
            meta = self.read_json(exec_path)
            return meta.get("success", False) is True
        except Exception:
            return False
