"""
cybog/adapters/dnsx.py

DnsxAdapter — DNS validation and resolution.
Input: subdomains from subfinder.
Output: Host entities with IPs populated (dead hosts filtered).
"""
from __future__ import annotations

from pathlib import Path

from cybog.adapters.base import ToolAdapter, NormalizedOutput, HealthCheckResult, ValidationResult
from cybog.config.models import ToolConfig
from cybog.models.execution import ToolResult
from cybog.models.job import StageJob
from cybog.models.target import Host, IP
from cybog.logging_setup import get_logger

_log = get_logger("adapters.dnsx")


class DnsxAdapter(ToolAdapter):
    def __init__(self, config: ToolConfig):
        self.config = config
        self.binary = config.binary

    def metadata(self) -> dict:
        return {
            "name": "dnsx",
            "description": "DNS validation and IP resolution",
            "output_format": "jsonl",
            "stage": "dnsx",
        }

    def health_check(self) -> HealthCheckResult:
        return self._check_binary(self.binary)

    def validate_input(self, job: StageJob, context: dict) -> ValidationResult:
        hosts = context.get("subfinder_hosts", [])
        if not hosts:
            return ValidationResult(
                valid=False,
                reason="No subdomains from subfinder stage — nothing to resolve"
            )
        return ValidationResult(valid=True, reason=f"{len(hosts)} hosts to resolve")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        hosts = context.get("subfinder_hosts", [job.target_domain])
        # Write input file
        input_file = stage_dir / "input_hosts.txt"
        self._write_input_file(input_file, hosts)

        out_file = stage_dir / "raw.jsonl"
        cmd = [
            self.binary,
            "-l", str(input_file),
            "-o", str(out_file),
            "-json",
            "-silent",
            "-resp",      # include A record response
            "-a",         # resolve A records
        ]
        cmd.extend(self.config.extra_args)
        return cmd

    def parse_output(self, tool_result: ToolResult, stage_dir: Path) -> list[dict]:
        """
        dnsx -json JSONL: {"host": "sub.example.com", "a": ["1.2.3.4"], ...}
        """
        raw_file = stage_dir / "raw.jsonl"
        if raw_file.exists() and raw_file.stat().st_size > 0:
            text = raw_file.read_text(encoding="utf-8")
        else:
            text = tool_result.stdout

        if not text.strip():
            return []

        records = self._parse_jsonl(text, _log)
        if records:
            return records

        # Fallback: plain text
        return [{"host": line.strip()} for line in text.splitlines() if line.strip()]

    def normalize_output(self, parsed: list[dict], job: StageJob) -> NormalizedOutput:
        out = NormalizedOutput()
        seen_hosts: set[str] = set()
        seen_ips: set[str] = set()

        for record in parsed:
            hostname = record.get("host", "").strip().lower()
            if not hostname or hostname in seen_hosts:
                continue
            seen_hosts.add(hostname)

            # Collect IPs from A/AAAA records
            ips: list[str] = []
            for field in ("a", "aaaa", "A", "AAAA"):
                val = record.get(field, [])
                if isinstance(val, list):
                    ips.extend(v for v in val if v)
                elif isinstance(val, str) and val:
                    ips.append(val)

            # Deduplicate IPs
            unique_ips = list(dict.fromkeys(ip.strip() for ip in ips if ip.strip()))

            out.hosts.append(
                Host(
                    hostname=hostname,
                    target_id=job.target_id,
                    ips=unique_ips,
                    sources=["dnsx"],
                )
            )
            for ip_addr in unique_ips:
                if ip_addr not in seen_ips:
                    seen_ips.add(ip_addr)
                    out.ips.append(
                        IP(
                            address=ip_addr,
                            target_id=job.target_id,
                            sources=["dnsx"],
                        )
                    )

        out.raw_count = len(parsed)
        return out
