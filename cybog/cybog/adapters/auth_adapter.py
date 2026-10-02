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
    ToolAdapterError,
)
from cybog.adapters.validation import (
    is_valid_credentials,
    is_valid_url,
    validate_url_list,
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
        _valid, rejected = validate_url_list(live_urls)
        if rejected:
            # A newline/control-char/leading-dash URL is a scope-escape or
            # argument-injection vector: fail rather than authenticate an
            # unauthorized target.
            _log.warning(
                "auth.validate_input rejected %d hostile URL(s): %r",
                len(rejected), rejected,
            )
            return ValidationResult(
                valid=False,
                reason=(
                    f"{len(rejected)} URL(s) rejected by validation "
                    f"(argument injection / scope escape): {rejected}"
                ),
            )
        if not self.config.credentials:
            return ValidationResult(
                valid=False, reason="No credentials configured for auth validation"
            )
        if not is_valid_credentials(self.config.credentials, self.config.auth_method):
            # Credentials with control chars (NUL/newline) could corrupt the
            # redacted logs/state that record them.
            _log.warning("auth.validate_input rejected invalid credentials format")
            return ValidationResult(
                valid=False,
                reason="Configured credentials contain control characters or an "
                       "invalid format for the configured auth method",
            )
        return ValidationResult(valid=True, reason=f"{len(live_urls)} URLs to authenticate")

    def _validate_auth_inputs(self, target_url: str, context_desc: str) -> None:
        """Hard gate: validate the URL and credentials before they hit argv.

        Raises ToolAdapterError if either is unsafe.  This is invoked by
        build_command and _build_validation_command so a hostile target_domain /
        URL can never reach the tool.
        """
        if not is_valid_url(target_url):
            raise ToolAdapterError(
                f"Refusing to build auth command [{context_desc}]: URL "
                f"'{target_url}' is not a valid http(s) URL "
                f"(argument injection / scope-escape guard)"
            )
        if not is_valid_credentials(self.config.credentials, self.config.auth_method):
            raise ToolAdapterError(
                f"Refusing to build auth command [{context_desc}]: configured "
                f"credentials contain control characters or an invalid format "
                f"for auth method '{self.config.auth_method}'"
            )

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        urls = context.get("httpx_urls", [f"https://{job.target_domain}"])
        if not urls:
            raise ToolAdapterError("No live URLs available for auth command")
        base_url = urls[0].rstrip("/")
        self._validate_auth_inputs(base_url, "build_command")
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
        # Defense in depth for the human-assisted validation plane: a finding URL
        # that is not a valid http(s) URL must never reach argv.
        self._validate_auth_inputs(base, "_build_validation_command")
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