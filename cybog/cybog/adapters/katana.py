"""
cybog/adapters/katana.py

KatanaAdapter — web crawling (JS-aware, discovers endpoints).
Input: live URLs from httpx.
Output: Endpoint and URL entities.
"""
from __future__ import annotations

import json
from pathlib import Path

from cybog.adapters.base import ToolAdapter, NormalizedOutput, HealthCheckResult, ValidationResult, ToolAdapterError
from cybog.adapters.validation import validate_url_list
from cybog.config.models import ToolConfig
from cybog.models.execution import ToolResult
from cybog.models.job import StageJob
from cybog.models.target import URL, Endpoint
from cybog.logging_setup import get_logger

_log = get_logger("adapters.katana")


class KatanaAdapter(ToolAdapter):
    def __init__(self, config: ToolConfig):
        self.config = config
        self.binary = config.resolve_binary()

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
        _valid, rejected = validate_url_list(live_urls)
        if rejected:
            _log.warning(
                "katana.validate_input rejected %d hostile URL(s): %r",
                len(rejected), rejected,
            )
            return ValidationResult(
                valid=False,
                reason=(
                    f"{len(rejected)} URL(s) rejected by validation "
                    f"(argument injection / scope escape): {rejected}"
                ),
            )
        return ValidationResult(valid=True, reason=f"{len(live_urls)} URLs to crawl")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        live_urls = context.get("httpx_urls", [f"https://{job.target_domain}"])
        valid, rejected = validate_url_list(live_urls)
        if rejected:
            _log.warning(
                "katana.build_command rejected %d hostile URL(s): %r",
                len(rejected), rejected,
            )
            raise ToolAdapterError(
                f"Refusing to build katana command: {len(rejected)} URL(s) failed "
                f"validation (argument injection / scope escape): {rejected}"
            )
        input_file = stage_dir / "input_urls.txt"
        self._write_input_file(input_file, valid)

        out_file = stage_dir / "raw.jsonl"
        cmd = [
            self.binary,
            "-list", str(input_file),
            "-o", str(out_file),
            "-jsonl",
            "-silent",
            "-jc",         # JavaScript crawling
            "-kf", "all",  # Known files
            # Depth is controlled by config.yaml extra_args only (single source
            # of truth). Adding a second -d here would shadow the user's value.
        ]
        cmd.extend(self.config.extra_args)
        return cmd

    def parse_output(self, tool_result: ToolResult, stage_dir: Path) -> list[dict]:
        raw_file = stage_dir / "raw.jsonl"
        records: list[dict] = []
        if raw_file.exists():
            with open(raw_file, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        records.append({"endpoint": line})
                    if len(records) >= 5000:  # Cap at 5000 records to prevent memory exhaust
                        break
            return records

        if tool_result.stdout.strip():
            return self._parse_jsonl(tool_result.stdout[:50000], _log)
        return []

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
            if len(out.endpoints) >= 1000:  # Cap normalized state endpoints per target
                break
        out.raw_count = len(parsed)
        return out
