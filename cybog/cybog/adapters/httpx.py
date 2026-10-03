"""
cybog/adapters/httpx.py

HttpxAdapter — HTTP probing for live web services.
Input: resolved hosts from dnsx.
Output: Service entities (URL, status_code, title, technology).
"""
from __future__ import annotations

from pathlib import Path

from cybog.adapters.base import ToolAdapter, NormalizedOutput, HealthCheckResult, ValidationResult, ToolAdapterError
from cybog.adapters.validation import validate_host_list
from cybog.config.models import ToolConfig
from cybog.models.execution import ToolResult
from cybog.models.job import StageJob
from cybog.models.target import Service, URL
from cybog.logging_setup import get_logger

_log = get_logger("adapters.httpx")


class HttpxAdapter(ToolAdapter):
    def __init__(self, config: ToolConfig):
        self.config = config
        self.binary = config.resolve_binary()

    def metadata(self) -> dict:
        return {
            "name": "httpx",
            "description": "HTTP probing — discovers live web services",
            "output_format": "jsonl",
            "stage": "httpx",
        }

    def health_check(self) -> HealthCheckResult:
        return self._check_binary(self.binary)

    def validate_input(self, job: StageJob, context: dict) -> ValidationResult:
        hosts = context.get("dnsx_hosts", [])
        if not hosts:
            return ValidationResult(
                valid=False,
                reason="No resolved hosts from dnsx — nothing to probe"
            )
        _valid, rejected = validate_host_list(hosts)
        if rejected:
            _log.warning(
                "httpx.validate_input rejected %d hostile host(s): %r",
                len(rejected), rejected,
            )
            return ValidationResult(
                valid=False,
                reason=(
                    f"{len(rejected)} host(s) rejected by validation "
                    f"(argument injection / scope escape): {rejected}"
                ),
            )
        return ValidationResult(valid=True, reason=f"{len(hosts)} hosts to probe")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        hosts = context.get("dnsx_hosts", [job.target_domain])
        valid, rejected = validate_host_list(hosts)
        if rejected:
            _log.warning(
                "httpx.build_command rejected %d hostile host(s): %r",
                len(rejected), rejected,
            )
            raise ToolAdapterError(
                f"Refusing to build httpx command: {len(rejected)} host(s) failed "
                f"validation (argument injection / scope escape): {rejected}"
            )
        input_file = stage_dir / "input_hosts.txt"
        self._write_input_file(input_file, valid)

        out_file = stage_dir / "raw.jsonl"
        cmd = [
            self.binary,
            "-l", str(input_file),
            "-o", str(out_file),
            "-json",
            "-silent",
            "-title",
            "-status-code",
            "-tech-detect",
            "-follow-redirects",
            "-no-color",
        ]
        cmd.extend(self.config.extra_args)
        return cmd

    def parse_output(self, tool_result: ToolResult, stage_dir: Path) -> list[dict]:
        raw_file = stage_dir / "raw.jsonl"
        text = raw_file.read_text(encoding="utf-8") if raw_file.exists() else tool_result.stdout
        if not text.strip():
            return []
        return self._parse_jsonl(text, _log)

    def normalize_output(self, parsed: list[dict], job: StageJob) -> NormalizedOutput:
        out = NormalizedOutput()
        seen_urls: set[str] = set()

        for record in parsed:
            url = record.get("url", "").strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            host = record.get("host", "")
            port = record.get("port", 0)
            scheme = "https" if "https" in url else "http"
            status_code = record.get("status-code") or record.get("status_code")
            title = record.get("title", "")

            # Technology detection — httpx returns list or dict
            tech_raw = record.get("tech", record.get("technologies", []))
            if isinstance(tech_raw, list):
                technology = [str(t) for t in tech_raw]
            elif isinstance(tech_raw, dict):
                technology = list(tech_raw.keys())
            else:
                technology = []

            try:
                port_int = int(port) if port else (443 if scheme == "https" else 80)
            except (ValueError, TypeError):
                port_int = 80

            out.services.append(
                Service(
                    host=host,
                    port=port_int,
                    scheme=scheme,
                    url=url,
                    technology=technology,
                    status_code=status_code,
                    title=title,
                    target_id=job.target_id,
                    source="httpx",
                )
            )
            out.urls.append(URL(url=url, target_id=job.target_id, source="httpx"))

        out.raw_count = len(parsed)
        return out
