"""
cybog/adapters/subfinder.py

SubfinderAdapter — passive subdomain enumeration.
Output: Host entities (one per discovered subdomain).
"""
from __future__ import annotations

from pathlib import Path

from cybog.adapters.base import ToolAdapter, NormalizedOutput, HealthCheckResult, ValidationResult, ToolAdapterError
from cybog.adapters.validation import is_valid_domain
from cybog.config.models import ToolConfig
from cybog.models.execution import ToolResult
from cybog.models.job import StageJob
from cybog.models.target import Host
from cybog.logging_setup import get_logger

_log = get_logger("adapters.subfinder")


class SubfinderAdapter(ToolAdapter):
    def __init__(self, config: ToolConfig):
        self.config = config
        self.binary = config.binary

    def metadata(self) -> dict:
        return {
            "name": "subfinder",
            "description": "Passive subdomain enumeration",
            "output_format": "jsonl",
            "stage": "subfinder",
        }

    def health_check(self) -> HealthCheckResult:
        return self._check_binary(self.binary)

    def validate_input(self, job: StageJob, context: dict) -> ValidationResult:
        if not job.target_domain:
            return ValidationResult(valid=False, reason="target_domain is empty")
        if not is_valid_domain(job.target_domain):
            # Reject argument-injection / scope-escape characters in the seed domain.
            return ValidationResult(
                valid=False,
                reason=f"target_domain '{job.target_domain}' is not a valid domain "
                       f"(argument injection / scope-escape guard)",
            )
        return ValidationResult(valid=True, reason="OK")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        if not is_valid_domain(job.target_domain):
            raise ToolAdapterError(
                f"Refusing to build subfinder command: target_domain "
                f"'{job.target_domain}' is not a valid domain "
                f"(argument-injection / scope-escape guard)"
            )
        out_file = stage_dir / "raw.jsonl"
        cmd = [
            self.binary,
            "-d", job.target_domain,
            "-o", str(out_file),
            "-json",
            "-silent",
        ]
        cmd.extend(self.config.extra_args)
        return cmd

    def parse_output(self, tool_result: ToolResult, stage_dir: Path) -> list[dict]:
        """
        subfinder -json outputs one JSON obj per line: {"host": "sub.example.com", ...}
        Fallback: plain text one host per line.
        """
        raw_file = stage_dir / "raw.jsonl"
        if raw_file.exists() and raw_file.stat().st_size > 0:
            text = raw_file.read_text(encoding="utf-8")
        else:
            text = tool_result.stdout

        if not text.strip():
            return []

        # Try JSONL first
        records = self._parse_jsonl(text, _log)
        if records:
            return records

        # Fallback: plain text (one host per line)
        return [{"host": line.strip()} for line in text.splitlines() if line.strip()]

    def normalize_output(self, parsed: list[dict], job: StageJob) -> NormalizedOutput:
        out = NormalizedOutput()
        seen: set[str] = set()
        for record in parsed:
            hostname = (
                record.get("host")
                or record.get("hostname")
                or record.get("subdomain")
                or ""
            )
            hostname = hostname.strip().lower()
            if hostname and hostname not in seen:
                seen.add(hostname)
                out.hosts.append(
                    Host(
                        hostname=hostname,
                        target_id=job.target_id,
                        sources=["subfinder"],
                    )
                )

        # Always ensure the target domain itself is included as a host
        target_host = job.target_domain.strip().lower()
        if target_host and target_host not in seen:
            seen.add(target_host)
            out.hosts.append(
                Host(
                    hostname=target_host,
                    target_id=job.target_id,
                    sources=["target_manifest"],
                )
            )

        out.raw_count = len(out.hosts)
        return out
