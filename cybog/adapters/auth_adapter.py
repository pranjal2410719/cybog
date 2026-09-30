"""
cybog/adapters/auth_adapter.py

AuthAdapter — authenticated session testing for the human-assisted validation plane.
Input: live URLs from httpx + authentication credentials.
Output: Finding entities for authentication validation results.
"""
from __future__ import annotations

from pathlib import Path

from cybog.adapters.base import ToolAdapter, NormalizedOutput, HealthCheckResult, ValidationResult
from cybog.config.models import AuthToolConfig
from cybog.models.execution import ToolResult
from cybog.models.finding import Finding, Evidence, Severity, ValidationStatus
from cybog.models.job import StageJob
from cybog.models.target import URL
from cybog.logging_setup import get_logger

_log = get_logger("adapters.auth")


class AuthAdapter(ToolAdapter):
    def __init__(self, config: AuthToolConfig):
        self.config = config
        self.binary = config.binary

    def metadata(self) -> dict:
        return {
            "name": "auth",
            "description": "Authenticated session testing — validates HTTP access with credentials",
            "output_format": "jsonl",
            "stage": "auth",
        }

    def health_check(self) -> HealthCheckResult:
        return self._check_binary(self.binary)

    def validate_input(self, job: StageJob, context: dict) -> ValidationResult:
        live_urls = context.get("httpx_urls", [])
        if not live_urls:
            return ValidationResult(
                valid=False, reason="No live URLs from httpx — nothing to authenticate against"
            )
        if not self.config.credentials:
            return ValidationResult(
                valid=False, reason="No credentials configured for auth validation"
            )
        return ValidationResult(valid=True, reason=f"{len(live_urls)} URLs to authenticate")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        urls = context.get("httpx_urls", [f"https://{job.target_domain}"])
        # Use first live URL as the base for auth testing
        base_url = urls[0].rstrip("/")
        cmd = [
            self.binary,
            "-u", base_url,
            "-auth-type", self.config.auth_method,
            "-auth-credentials", self.config.credentials,
            "-o", str(stage_dir / "raw.jsonl"),
            "-silent",
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
        for record in parsed:
            url = record.get("url", "").strip()
            if not url:
                continue
            status_code = record.get("status_code", record.get("status", 0))
            title = record.get("title", "")
            # Determine if authentication succeeded based on response
            auth_success = record.get("auth_success", False)
            severity = Severity.INFO if auth_success else Severity.LOW
            finding = Finding(
                finding_type="auth-validation",
                title=f"Authentication validation: {url}",
                severity=severity,
                target_id=job.target_id,
                target_domain=job.target_domain,
                url=url,
                source_tool="auth",
                validation_status=ValidationStatus.NEEDS_VALIDATION,
                description=f"Authentication test against {url}",
            )
            # Basic evidence capture
            evidence = Evidence(
                finding_id=finding.finding_id,
                tool="auth",
                raw_output=str(record)[:2000],
                request=self.config.credentials,
                response=str(record.get("response", "")),
            )
            finding.evidence = [evidence]
            out.findings.append(finding)
        out.raw_count = len(parsed)
        return out