"""
cybog/adapters/katana.py

KatanaAdapter — web crawling (JS-aware, discovers endpoints).
Input: live URLs from httpx.
Output: Endpoint and URL entities.
"""
from __future__ import annotations

from pathlib import Path

from cybog.adapters.base import ToolAdapter, NormalizedOutput, HealthCheckResult, ValidationResult
from cybog.config.models import ToolConfig
from cybog.models.execution import ToolResult
from cybog.models.job import StageJob
from cybog.models.target import URL, Endpoint
from cybog.logging_setup import get_logger

_log = get_logger("adapters.katana")


class KatanaAdapter(ToolAdapter):
    def __init__(self, config: ToolConfig):
        self.config = config
        self.binary = config.binary

    def metadata(self) -> dict:
        return {
            "name": "katana",
            "description": "Web crawler — discovers JS endpoints and routes",
            "output_format": "jsonl",
            "stage": "katana",
        }

    def health_check(self) -> HealthCheckResult:
        return self._check_binary(self.binary)

    def validate_input(self, job: StageJob, context: dict) -> ValidationResult:
        live_urls = context.get("httpx_urls", [])
        if not live_urls:
            return ValidationResult(
                valid=False, reason="No live URLs from httpx — skipping crawl"
            )
        return ValidationResult(valid=True, reason=f"{len(live_urls)} URLs to crawl")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        live_urls = context.get("httpx_urls", [f"https://{job.target_domain}"])
        input_file = stage_dir / "input_urls.txt"
        self._write_input_file(input_file, live_urls)

        out_file = stage_dir / "raw.jsonl"
        cmd = [
            self.binary,
            "-list", str(input_file),
            "-o", str(out_file),
            "-jsonl",
            "-silent",
            "-jc",         # JavaScript crawling
            "-kf", "all",  # Known files
            "-d", "3",     # Depth
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
        # Fallback: plain URLs
        return [{"endpoint": line.strip()} for line in text.splitlines() if line.strip()]

    def normalize_output(self, parsed: list[dict], job: StageJob) -> NormalizedOutput:
        out = NormalizedOutput()
        seen: set[str] = set()
        for record in parsed:
            url = (
                record.get("endpoint")
                or record.get("url")
                or record.get("request", {}).get("endpoint", "")
                or ""
            )
            url = url.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            out.urls.append(URL(url=url, target_id=job.target_id, source="katana"))
            out.endpoints.append(
                Endpoint(url=url, target_id=job.target_id, source="katana")
            )
        out.raw_count = len(parsed)
        return out
