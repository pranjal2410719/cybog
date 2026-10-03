"""
cybog/adapters/naabu.py

NaabuAdapter — high-speed port scanning.
Input: resolved hosts from dnsx. Runs PARALLEL with httpx.
Output: Port entities.
"""
from __future__ import annotations

from pathlib import Path

from cybog.adapters.base import ToolAdapter, NormalizedOutput, HealthCheckResult, ValidationResult, ToolAdapterError
from cybog.adapters.validation import validate_host_list
from cybog.config.models import ToolConfig
from cybog.models.execution import ToolResult
from cybog.models.job import StageJob
from cybog.models.target import Port
from cybog.logging_setup import get_logger

_log = get_logger("adapters.naabu")

_DEFAULT_PORTS = "80,443,8080,8443,8000,8888,3000,5000,9090,9443"


class NaabuAdapter(ToolAdapter):
    def __init__(self, config: ToolConfig):
        self.config = config
        self.binary = config.resolve_binary()

    def metadata(self) -> dict:
        return {
            "name": "naabu",
            "description": "Port discovery scanner",
            "output_format": "jsonl",
            "stage": "naabu",
        }

    def health_check(self) -> HealthCheckResult:
        return self._check_binary(self.binary)

    def validate_input(self, job: StageJob, context: dict) -> ValidationResult:
        hosts = context.get("dnsx_hosts", [])
        if not hosts:
            return ValidationResult(
                valid=False, reason="No resolved hosts from dnsx"
            )
        _valid, rejected = validate_host_list(hosts)
        if rejected:
            _log.warning(
                "naabu.validate_input rejected %d hostile host(s): %r",
                len(rejected), rejected,
            )
            return ValidationResult(
                valid=False,
                reason=(
                    f"{len(rejected)} host(s) rejected by validation "
                    f"(argument injection / scope escape): {rejected}"
                ),
            )
        return ValidationResult(valid=True, reason=f"{len(hosts)} hosts to scan")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        hosts = context.get("dnsx_hosts", [job.target_domain])
        valid, rejected = validate_host_list(hosts)
        if rejected:
            _log.warning(
                "naabu.build_command rejected %d hostile host(s): %r",
                len(rejected), rejected,
            )
            raise ToolAdapterError(
                f"Refusing to build naabu command: {len(rejected)} host(s) failed "
                f"validation (argument injection / scope escape): {rejected}"
            )
        input_file = stage_dir / "input_hosts.txt"
        self._write_input_file(input_file, valid)

        out_file = stage_dir / "raw.jsonl"
        cmd = [
            self.binary,
            "-list", str(input_file),
            "-o", str(out_file),
            "-json",
            "-silent",
            "-p", _DEFAULT_PORTS,
        ]
        cmd.extend(self.config.extra_args)
        return cmd

    def parse_output(self, tool_result: ToolResult, stage_dir: Path) -> list[dict]:
        raw_file = stage_dir / "raw.jsonl"
        text = raw_file.read_text(encoding="utf-8") if raw_file.exists() else tool_result.stdout
        if not text.strip():
            return []
        records = self._parse_jsonl(text, _log)
        if records:
            return records
        # Fallback: "host:port" lines
        result = []
        for line in text.splitlines():
            line = line.strip()
            if ":" in line:
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    try:
                        result.append({"host": parts[0], "port": int(parts[1])})
                    except ValueError:
                        pass
        return result

    def normalize_output(self, parsed: list[dict], job: StageJob) -> NormalizedOutput:
        out = NormalizedOutput()
        seen: set[tuple] = set()
        for record in parsed:
            host = record.get("host", record.get("ip", "")).strip()
            port_val = record.get("port", 0)
            proto = record.get("protocol", record.get("proto", "tcp"))
            try:
                port_int = int(port_val)
            except (ValueError, TypeError):
                continue
            key = (host, port_int)
            if not host or key in seen:
                continue
            seen.add(key)
            out.ports.append(
                Port(
                    host=host,
                    port=port_int,
                    protocol=proto,
                    target_id=job.target_id,
                    sources=["naabu"],
                )
            )
        out.raw_count = len(parsed)
        return out
