"""
cybog/adapters/base.py

ToolAdapter ABC — every tool must implement this interface.
The workflow depends on this interface only.
Tool-specific logic stays in concrete adapters.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cybog.models.execution import ToolResult
from cybog.models.finding import Finding
from cybog.models.job import StageJob
from cybog.models.target import Host, IP, Port, Service, URL, Endpoint


@dataclass
class NormalizedOutput:
    """Common entities produced by any adapter. Workflow consumes ONLY this."""
    hosts: list[Host] = field(default_factory=list)
    ips: list[IP] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    urls: list[URL] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    raw_count: int = 0


@dataclass
class HealthCheckResult:
    tool: str
    binary: str
    available: bool
    version: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ValidationResult:
    valid: bool
    reason: str


class ToolAdapterError(Exception):
    """Raised for unrecoverable adapter failures (misconfiguration etc.)."""


class ToolAdapter(ABC):
    """
    Abstract base for all security tool adapters.
    Adapters are stateless. State lives in AssessmentState.
    """

    @abstractmethod
    def metadata(self) -> dict:
        """Return: name, version_flag, description, output_format."""

    @abstractmethod
    def health_check(self) -> HealthCheckResult:
        """Verify binary exists and returns a version string."""

    @abstractmethod
    def validate_input(self, job: StageJob, context: dict) -> ValidationResult:
        """
        Validate all required inputs exist for this job.
        context: dict of {stage_name: list[str]} e.g. {"subfinder": ["host1", "host2"]}
        """

    @abstractmethod
    def build_command(
        self, job: StageJob, stage_dir: Path, context: dict
    ) -> list[str]:
        """Construct the CLI command list. Must NOT execute anything."""

    @abstractmethod
    def parse_output(
        self, tool_result: ToolResult, stage_dir: Path
    ) -> list[dict]:
        """
        Parse raw tool output into list of dicts.
        Each dict is a raw parsed record. No Pydantic models yet.
        Must handle: empty stdout, malformed JSON lines (skip + warn, don't crash).
        """

    @abstractmethod
    def normalize_output(
        self, parsed: list[dict], job: StageJob
    ) -> NormalizedOutput:
        """Convert parsed records into common NormalizedOutput entities."""

    # ------------------------------------------------------------------
    # Concrete execution — shared by all adapters
    # ------------------------------------------------------------------
    async def execute(
        self,
        command: list[str],
        stage_dir: Path,
        timeout: int,
        stdin_data: Optional[str] = None,
    ) -> ToolResult:
        """
        Run command as asyncio subprocess.
        Captures stdout, stderr, exit_code, duration.
        Writes stdout.log and stderr.log to stage_dir.
        Returns ToolResult — never raises (errors captured in result).
        """
        started_at = datetime.now(timezone.utc)
        start = time.monotonic()
        timed_out = False
        stdout_data = ""
        stderr_data = ""
        exit_code = -1

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
            )
            stdin_bytes = stdin_data.encode() if stdin_data else None
            try:
                raw_out, raw_err = await asyncio.wait_for(
                    proc.communicate(input=stdin_bytes),
                    timeout=float(timeout),
                )
                stdout_data = raw_out.decode(errors="replace").strip()
                stderr_data = raw_err.decode(errors="replace").strip()
                exit_code = proc.returncode or 0
            except asyncio.TimeoutError:
                timed_out = True
                proc.kill()
                await proc.communicate()
                exit_code = -1
        except FileNotFoundError:
            stderr_data = (
                f"Binary not found: '{command[0]}'. "
                "Install it or set correct path in config/tools.yaml."
            )
            exit_code = -2
        except Exception as exc:
            stderr_data = f"Unexpected error: {exc}"
            exit_code = -3

        duration = round(time.monotonic() - start, 3)
        finished_at = datetime.now(timezone.utc)

        # Persist logs
        stage_dir.mkdir(parents=True, exist_ok=True)
        (stage_dir / "stdout.log").write_text(stdout_data, encoding="utf-8")
        (stage_dir / "stderr.log").write_text(stderr_data, encoding="utf-8")

        tool_name = self.metadata().get("name", command[0])
        return ToolResult(
            tool=tool_name,
            binary=command[0],
            command=" ".join(command),
            exit_code=exit_code,
            stdout=stdout_data,
            stderr=stderr_data,
            duration_seconds=duration,
            timed_out=timed_out,
            started_at=started_at,
            finished_at=finished_at,
        )

    def collect_artifacts(self, stage_dir: Path, job: StageJob) -> list[str]:
        """Return list of artifact paths (relative strings) created by this stage."""
        return [str(p) for p in stage_dir.iterdir() if p.is_file()]

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _check_binary(self, binary: str) -> HealthCheckResult:
        found = shutil.which(binary)
        if not found:
            return HealthCheckResult(
                tool=self.metadata().get("name", binary),
                binary=binary,
                available=False,
                error=f"Binary '{binary}' not found in PATH.",
            )
        # Try to get version
        version: Optional[str] = None
        try:
            import subprocess
            res = subprocess.run(
                [binary, "--version"],
                capture_output=True, text=True, timeout=10
            )
            version_text = (res.stdout or res.stderr or "").strip().splitlines()
            version = version_text[0][:80] if version_text else "unknown"
        except Exception:
            version = "unknown"
        return HealthCheckResult(
            tool=self.metadata().get("name", binary),
            binary=binary,
            available=True,
            version=version,
        )

    @staticmethod
    def _parse_jsonl(text: str, logger=None) -> list[dict]:
        """Parse JSONL text. Skips malformed lines with optional warning."""
        records: list[dict] = []
        for i, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                if logger:
                    logger.warning(f"Skipping malformed JSONL line {i}: {line[:80]}")
        return records

    @staticmethod
    def _write_input_file(path: Path, lines: list[str]) -> Path:
        """Write a list of strings (one per line) to a temp input file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
