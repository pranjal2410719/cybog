"""
cybog/adapters/ffuf.py

FfufAdapter — directory/content fuzzing.
Input: live URLs from httpx.
Output: Endpoint entities (discovered hidden paths).
"""
from __future__ import annotations

import json
from pathlib import Path

from cybog.adapters.base import ToolAdapter, NormalizedOutput, HealthCheckResult, ValidationResult, ToolAdapterError
from cybog.adapters.validation import is_safe_path_value, validate_url_list
from cybog.config.models import FfufToolConfig
from cybog.models.execution import ToolResult
from cybog.models.job import StageJob
from cybog.models.target import Endpoint
from cybog.logging_setup import get_logger

_log = get_logger("adapters.ffuf")


class FfufAdapter(ToolAdapter):
    def __init__(self, config: FfufToolConfig):
        self.config = config
        self.binary = config.binary

    def metadata(self) -> dict:
        return {
            "name": "ffuf",
            "description": "Web content and directory fuzzer",
            "output_format": "json",
            "stage": "ffuf",
        }

    def health_check(self) -> HealthCheckResult:
        return self._check_binary(self.binary)

    def validate_input(self, job: StageJob, context: dict) -> ValidationResult:
        live_urls = context.get("httpx_urls", [])
        if not live_urls:
            return ValidationResult(
                valid=False, reason="No live URLs from httpx — nothing to fuzz"
            )
        _valid, rejected = validate_url_list(live_urls)
        if rejected:
            _log.warning(
                "ffuf.validate_input rejected %d hostile URL(s): %r",
                len(rejected), rejected,
            )
            return ValidationResult(
                valid=False,
                reason=(
                    f"{len(rejected)} URL(s) rejected by validation "
                    f"(argument injection / scope escape): {rejected}"
                ),
            )
        wordlist = self.config.wordlist
        if not is_safe_path_value(wordlist):
            # Security gate: traversal / control chars in a path config must fail.
            return ValidationResult(
                valid=False,
                reason=(
                    f"config.wordlist '{wordlist}' is not a safe path "
                    f"(path traversal / control characters rejected)"
                ),
            )
        # A missing wordlist is NOT a validation failure: let the tool itself
        # report the failure at runtime (preserve existing runtime behaviour).
        if not Path(wordlist).exists():
            _log.warning(
                "ffuf wordlist not found on disk (tool will report failure at runtime): %r",
                wordlist,
            )
        return ValidationResult(valid=True, reason=f"{len(live_urls)} URLs to fuzz")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        live_urls = context.get("httpx_urls", [f"https://{job.target_domain}"])
        valid, rejected = validate_url_list(live_urls)
        if rejected:
            _log.warning(
                "ffuf.build_command rejected %d hostile URL(s): %r",
                len(rejected), rejected,
            )
            raise ToolAdapterError(
                f"Refusing to build ffuf command: {len(rejected)} URL(s) failed "
                f"validation (argument injection / scope escape): {rejected}"
            )
        if not valid:
            raise ToolAdapterError("No valid URLs to fuzz")
        # Use first live URL as the base
        base_url = valid[0].rstrip("/") + "/FUZZ"
        wordlist = self.config.wordlist
        if not is_safe_path_value(wordlist):
            _log.warning(
                "ffuf.build_command rejected unsafe wordlist path: %r", wordlist
            )
            raise ToolAdapterError(
                f"Refusing to build ffuf command: config.wordlist '{wordlist}' "
                f"is not a safe path (path traversal / control characters rejected)"
            )
        # A missing wordlist is a runtime error reported by the tool itself —
        # do not raise here so behaviour matches the documented contract.
        if not Path(wordlist).exists():
            _log.warning(
                "ffuf wordlist not found on disk (tool will report failure): %r",
                wordlist,
            )
        out_file = stage_dir / "raw.json"
        cmd = [
            self.binary,
            "-u", base_url,
            "-w", self.config.wordlist,
            "-o", str(out_file),
            "-of", "json",
            "-ac",           # Auto-calibrate baseline responses
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-s",
        ]
        cmd.extend(self.config.extra_args)
        return cmd

    def parse_output(self, tool_result: ToolResult, stage_dir: Path) -> list[dict]:
        raw_file = stage_dir / "raw.json"
        if raw_file.exists() and raw_file.stat().st_size > 0:
            try:
                data = json.loads(raw_file.read_text(encoding="utf-8"))
                return data.get("results", [])
            except json.JSONDecodeError:
                _log.warning("ffuf raw.json is malformed")
        # Fallback: try stdout
        if tool_result.stdout.strip():
            try:
                data = json.loads(tool_result.stdout)
                return data.get("results", [])
            except json.JSONDecodeError:
                pass
        return []

    def normalize_output(self, parsed: list[dict], job: StageJob) -> NormalizedOutput:
        out = NormalizedOutput()
        seen: set[str] = set()
        for result in parsed:
            url = result.get("url", "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            status = result.get("status", 0)
            path = result.get("input", {}).get("FUZZ", "")
            out.endpoints.append(
                Endpoint(
                    url=url,
                    path=path,
                    status_code=status,
                    target_id=job.target_id,
                    source="ffuf",
                )
            )
        out.raw_count = len(parsed)
        return out
