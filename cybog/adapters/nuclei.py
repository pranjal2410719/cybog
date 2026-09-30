"""
cybog/adapters/nuclei.py

NucleiAdapter — template-based vulnerability scanning.
Input: merged URLs from katana + ffuf.
Output: Finding entities. Scanner alerts are DISCOVERED (candidates), not confirmed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from cybog.adapters.base import ToolAdapter, NormalizedOutput, HealthCheckResult, ValidationResult
from cybog.config.models import NucleiToolConfig
from cybog.models.execution import ToolResult
from cybog.models.finding import Finding, Severity, ValidationStatus, Evidence
from cybog.models.job import StageJob
from cybog.logging_setup import get_logger

_log = get_logger("adapters.nuclei")

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}


class NucleiAdapter(ToolAdapter):
    def __init__(self, config: NucleiToolConfig):
        self.config = config
        self.binary = config.binary

    def metadata(self) -> dict:
        return {
            "name": "nuclei",
            "description": "Template-based vulnerability scanner",
            "output_format": "jsonl",
            "stage": "nuclei",
        }

    def health_check(self) -> HealthCheckResult:
        return self._check_binary(self.binary)

    def validate_input(self, job: StageJob, context: dict) -> ValidationResult:
        all_urls = context.get("all_urls", [])
        if not all_urls:
            return ValidationResult(
                valid=False,
                reason="No URLs to scan — katana + ffuf produced 0 endpoints"
            )
        return ValidationResult(valid=True, reason=f"{len(all_urls)} URLs to scan")

    def build_command(self, job: StageJob, stage_dir: Path, context: dict) -> list[str]:
        all_urls = context.get("all_urls", [f"https://{job.target_domain}"])
        input_file = stage_dir / "input_urls.txt"
        self._write_input_file(input_file, all_urls)

        out_file = stage_dir / "raw.jsonl"
        cmd = [
            self.binary,
            "-l", str(input_file),
            "-o", str(out_file),
            "-jsonl",
            "-silent",
            "-severity", self.config.severity,
            "-no-color",
        ]
        if self.config.templates:
            cmd.extend(["-t", self.config.templates])
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
            finding = self._normalize_nuclei_record(record, job)
            if finding:
                out.findings.append(finding)
        out.raw_count = len(parsed)
        return out

    def _normalize_nuclei_record(self, record: dict, job: StageJob) -> Optional[Finding]:
        """
        Nuclei JSON output fields:
            template-id, info.name, info.severity, matched-at, host,
            info.description, matcher-name, curl-command, extracted-results
        """
        try:
            info = record.get("info", {})
            template_id = record.get("template-id", record.get("templateID", ""))
            title = info.get("name", template_id or "Unknown Finding")
            severity_raw = info.get("severity", "unknown").lower()
            severity = _SEVERITY_MAP.get(severity_raw, Severity.UNKNOWN)
            url = record.get("matched-at", record.get("matched-at", record.get("host", "")))
            description = info.get("description", "")
            matcher_name = record.get("matcher-name", "")

            raw_output = str(record)
            finding_id_seed = f"{job.target_id}:{template_id}:{url}"

            evidence = Evidence(
                finding_id=finding_id_seed,  # Will be updated after Finding created
                tool="nuclei",
                raw_output=raw_output[:2000],  # Truncate for state storage
                request=record.get("curl-command", ""),
                response=str(record.get("extracted-results", "")),
            )

            finding = Finding(
                finding_type=template_id or "nuclei-finding",
                title=title,
                severity=severity,
                target_id=job.target_id,
                target_domain=job.target_domain,
                url=url,
                source_tool="nuclei",
                template_id=template_id,
                description=description,
                matcher_name=matcher_name,
                validation_status=ValidationStatus.DISCOVERED,
                evidence=[],
            )
            # Fix evidence finding_id after Finding is created
            evidence.finding_id = finding.finding_id
            finding.evidence = [evidence]
            return finding

        except Exception as exc:
            _log.warning(f"Failed to normalize nuclei record: {exc} | record={str(record)[:200]}")
            return None
