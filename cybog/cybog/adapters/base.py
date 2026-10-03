"""
cybog/adapters/base.py

ToolAdapter ABC — every tool must implement this interface.
The workflow depends on this interface only.
Tool-specific logic stays in concrete adapters.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cybog.models.execution import ToolResult
from cybog.models.finding import Evidence, Finding
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


@dataclass
class ValidationOutcome:
    """
    Result of validating an EXISTING finding, as opposed to NormalizedOutput
    which produces new entities.

    applicable:   whether this adapter can meaningfully judge the finding.
    validated:    True/False when the adapter reached a verdict.
                  None when it could not determine one — the caller must then
                  keep the finding pending rather than guess.
    evidence:     evidence to attach to the finding, or None if none was produced.
    """

    applicable: bool
    reason: str
    validated: Optional[bool] = None
    evidence: Optional["Evidence"] = None


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
            env = self._exec_env()
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                env=env,
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

    def _exec_env(self) -> Optional[dict[str, str]]:
        cfg = getattr(self, "config", None)
        if cfg is None:
            return None
        bin_dirs = getattr(cfg, "bin_dirs", []) or []
        if not bin_dirs:
            return None
        expanded = [str(Path(d).expanduser()) for d in bin_dirs]
        env = dict(os.environ)
        env["PATH"] = ":".join(expanded) + ":" + env.get("PATH", "")
        return env

    def collect_artifacts(self, stage_dir: Path, job: StageJob) -> list[str]:
        """Return list of artifact paths (relative strings) created by this stage."""
        return [str(p) for p in stage_dir.iterdir() if p.is_file()]

    def secrets(self) -> list[str]:
        """
        Return literal secret values this adapter may place on a command line.

        Used to redact commands before they are logged or persisted. Adapters
        that carry credentials (e.g. auth) override this. Adapters that embed no
        secrets return nothing.
        """
        return []

    def redact(self, text: str) -> str:
        """Replace any known secret literal in text with a redaction marker."""
        for secret in self.secrets():
            if secret:
                text = text.replace(secret, "<redacted>")
        return text

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

    @staticmethod
    def looks_like_compiled_binary(path: str) -> bool:
        p = Path(path)
        if not p.is_file():
            return False
        try:
            with open(p, "rb") as fh:
                header = fh.read(4)
            if not header:
                return False
            if header[:2] == b"#!":
                return False
            if header[:4] == b"\x7fELF":
                return True
            if header[:2] in (b"MZ", b"ZM"):
                return True
            return False
        except OSError:
            return False

    def build_commands(
        self, job: StageJob, stage_dir: Path, context: dict
    ) -> list[list[str]]:
        return [self.build_command(job, stage_dir, context)]

    def _check_binary(self, binary: str) -> HealthCheckResult:
        resolved = binary
        cfg = getattr(self, "config", None)
        if cfg is not None:
            resolved = cfg.resolve_binary()

        if not Path(resolved).is_file() or not os.access(resolved, os.X_OK):
            return HealthCheckResult(
                tool=self.metadata().get("name", binary),
                binary=binary,
                available=False,
                error=f"Binary '{binary}' not found (resolved: {resolved}).",
            )

        if not self.looks_like_compiled_binary(resolved):
            return HealthCheckResult(
                tool=self.metadata().get("name", binary),
                binary=binary,
                available=False,
                error=(
                    f"{binary} resolved to '{resolved}', which is not a "
                    f"compiled binary (e.g. a Python script) — another "
                    f"program of the same name is shadowing it in PATH."
                ),
            )

        version_args = getattr(getattr(self, "config", None), "version_args", ["--version"]) or ["--version"]
        version: Optional[str] = None
        try:
            import subprocess
            res = subprocess.run(
                [resolved] + version_args,
                capture_output=True, text=True, timeout=10
            )
            version_text = (res.stdout or res.stderr or "").strip().splitlines()
            version = version_text[0][:80] if version_text else "unknown"
            first = (res.stdout or res.stderr or "").strip().splitlines()[0].lower() if version_text else ""
            if "usage:" in first or "python" in first or "click" in first:
                return HealthCheckResult(
                    tool=self.metadata().get("name", binary),
                    binary=binary,
                    available=False,
                    error=(
                        f"Version probe for '{binary}' returned a Python/Click "
                        f"usage string — a script is shadowing the compiled binary."
                    ),
                )
        except Exception:
            version = "unknown"
        return HealthCheckResult(
            tool=self.metadata().get("name", binary),
            binary=binary,
            available=True,
            version=version,
        )
