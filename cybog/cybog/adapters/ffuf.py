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
        self.binary = config.resolve_binary()

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
            return ValidationResult(valid=False, reason="No live URLs from httpx — nothing to fuzz")
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
            return ValidationResult(
                valid=False,
                reason=(
                    f"config.wordlist '{wordlist}' is not a safe path "
                    f"(path traversal / control characters rejected)"
                ),
            )
        if not Path(wordlist).exists():
            _log.warning(
                "ffuf wordlist not found on disk (tool will report failure at runtime): %r",
                wordlist,
            )
        else:
            try:
                wl_lines = sum(1 for _ in open(wordlist, "rb"))
                _log.info("ffuf wordlist contains %d lines: %r", wl_lines, wordlist)
            except OSError:
                pass
        return ValidationResult(valid=True, reason=f"{len(live_urls)} URLs to fuzz")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        cmds = self.build_commands(job, stage_dir, context)
        return cmds[0] if cmds else []

    def build_commands(self, job: StageJob, stage_dir: Path, context: dict) -> list[list[str]]:
        live_urls = context.get("httpx_urls", [f"https://{job.target_domain}"])
        valid, rejected = validate_url_list(live_urls)
        if rejected:
            _log.warning(
                "ffuf.build_commands rejected %d hostile URL(s): %r",
                len(rejected), rejected,
            )
            raise ToolAdapterError(
                f"Refusing to build ffuf commands: {len(rejected)} URL(s) failed "
                f"validation (argument injection / scope escape): {rejected}"
            )
        if not valid:
            raise ToolAdapterError("No valid URLs to fuzz")

        capped = valid[: self.config.max_targets]
        if len(valid) > self.config.max_targets:
            _log.warning(
                "ffuf truncating target list from %d to max_targets=%d",
                len(valid), self.config.max_targets,
            )

        wordlist = self.config.wordlist
        if not is_safe_path_value(wordlist):
            _log.warning("ffuf.build_commands rejected unsafe wordlist path: %r", wordlist)
            raise ToolAdapterError(
                f"Refusing to build ffuf command: config.wordlist '{wordlist}' "
                f"is not a safe path (path traversal / control characters rejected)"
            )
        if not Path(wordlist).exists():
            _log.warning(
                "ffuf wordlist not found on disk (tool will report failure): %r",
                wordlist,
            )

        commands: list[list[str]] = []
        for idx, url in enumerate(capped):
            base_url = url.rstrip("/") + "/FUZZ"
            out_file = stage_dir / f"raw.{idx}.json"
            cmd = [
                self.binary,
                "-u", base_url,
                "-w", self.config.wordlist,
                "-o", str(out_file),
                "-of", "json",
                "-ac",
                "-mc", "200,201,204,301,302,307,401,403,405",
                "-s",
            ]
            cmd.extend(self.config.extra_args)
            commands.append(cmd)
        return commands

    def parse_output(self, tool_result: ToolResult, stage_dir: Path) -> list[dict]:
        raw_files = sorted(stage_dir.glob("raw.*.json"))
        results: list[dict] = []
        for raw_file in raw_files:
            if raw_file.exists() and raw_file.stat().st_size > 0:
                try:
                    data = json.loads(raw_file.read_text(encoding="utf-8"))
                    batch = data.get("results", [])
                    if isinstance(batch, list):
                        results.extend(batch)
                except json.JSONDecodeError:
                    _log.warning("ffuf %s is malformed", raw_file)
        if results:
            return results
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
