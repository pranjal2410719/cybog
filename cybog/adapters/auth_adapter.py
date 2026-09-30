"""
cybog/adapters/auth_adapter.py

AuthAdapter — authenticated session testing for the human-assisted validation plane.
Input: live URLs from httpx + authentication credentials.
Output: Finding entities for authentication validation results.
"""
from __future__ import annotations

from pathlib import Path

from cybog.adapters.base import (
    ToolAdapter,
    NormalizedOutput,
    HealthCheckResult,
    ValidationResult,
    ValidationOutcome,
)
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

    def secrets(self) -> list[str]:
        """Credentials are passed on the command line, so they must be redacted."""
        return [self.config.credentials] if self.config.credentials else []

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

    async def validate_finding(
        self,
        finding: Finding,
        live_urls: list[str],
        stage_dir: Path,
    ) -> ValidationOutcome:
        """
        Validate an EXISTING finding using authenticated access.

        This never creates a new Finding. It returns a verdict for the finding
        it is given, plus evidence to attach. When the adapter cannot reach a
        verdict it returns validated=None so the caller keeps the finding
        pending instead of guessing.
        """
        target_url = finding.url or (live_urls[0] if live_urls else None)
        if not target_url:
            return ValidationOutcome(
                applicable=False,
                reason="Finding has no URL and no live URLs are available",
            )
        if not self.config.credentials:
            return ValidationOutcome(
                applicable=False,
                reason=(
                    "Authentication validation is not configured. "
                    "Set CYBOG_AUTH_CREDENTIALS to enable it."
                ),
            )
        if not self.config.enabled:
            return ValidationOutcome(
                applicable=False,
                reason="Auth validation is disabled in configuration (tools.auth.enabled)",
            )

        stage_dir.mkdir(parents=True, exist_ok=True)
        job = StageJob(
            assessment_id="validation",
            target_id=finding.target_id,
            target_domain=finding.target_domain,
            stage="auth-validation",
        )
        command = self._build_validation_command(target_url, stage_dir)
        result = await self.execute(
            command=command,
            stage_dir=stage_dir,
            timeout=self.config.timeout,
        )

        # A crashed/timed-out tool yields no verdict. Do not invent one.
        if result.exit_code != 0 or result.timed_out:
            return ValidationOutcome(
                applicable=True,
                reason=(
                    f"Auth validation could not complete "
                    f"(exit={result.exit_code}, timed_out={result.timed_out})"
                ),
                validated=None,
            )

        raw_file = stage_dir / "raw.jsonl"
        text = raw_file.read_text(encoding="utf-8") if raw_file.exists() else result.stdout
        records = self._parse_jsonl(text, _log) if text.strip() else []

        auth_succeeded = self._interpret_auth_records(records)
        if auth_succeeded is None:
            return ValidationOutcome(
                applicable=True,
                reason="Auth tool returned no interpretable result",
                validated=None,
            )

        verdict = "authenticated access confirmed" if auth_succeeded else \
                  "authenticated access denied"
        evidence = Evidence(
            finding_id=finding.finding_id,
            tool="auth",
            raw_output=str(records)[:2000],
            request=f"<redacted:{self.config.auth_method}>",
            validation_result=f"Auth validation: {verdict}",
            reproduction=f"Re-ran authenticated request against {target_url}: {verdict}",
        )
        return ValidationOutcome(
            applicable=True,
            reason=verdict,
            validated=auth_succeeded,
            evidence=evidence,
        )

    def _build_validation_command(self, target_url: str, stage_dir: Path) -> list[str]:
        base = target_url.rstrip("/")
        cmd = [
            self.binary,
            "-u", base,
            "-auth-type", self.config.auth_method,
            "-auth-credentials", self.config.credentials,
            "-o", str(stage_dir / "raw.jsonl"),
            "-silent",
        ]
        cmd.extend(self.config.extra_args)
        return cmd

    @staticmethod
    def _interpret_auth_records(records: list[dict]) -> Optional[bool]:
        """Reduce parsed auth records to a single verdict, or None if unclear."""
        if not records:
            return None
        for record in records:
            if "auth_success" in record:
                return bool(record["auth_success"])
        # Fall back to HTTP status: 401/403 means credentials were rejected.
        statuses = [
            r.get("status_code", r.get("status")) for r in records
            if r.get("status_code", r.get("status")) is not None
        ]
        if not statuses:
            return None
        return not any(int(s) in (401, 403) for s in statuses)

    def normalize_output(self, parsed: list[dict], job: StageJob) -> NormalizedOutput:
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
            # Basic evidence capture.
            # NOTE: credentials are deliberately NOT recorded here — evidence is
            # persisted into state and rendered into reports. A redacted marker
            # is stored instead so the shape of the attempt stays auditable
            # without leaking the secret.
            evidence = Evidence(
                finding_id=finding.finding_id,
                tool="auth",
                raw_output=str(record)[:2000],
                request=f"<redacted:{self.config.auth_method}>" if self.config.credentials else None,
                response=str(record.get("response", "")),
            )
            finding.evidence = [evidence]
            out.findings.append(finding)
        out.raw_count = len(parsed)
        return out