"""
cybog/workflow/router.py

Deterministic conditional routing logic.
All routing decisions are explicit and testable.
No routing logic inside tool adapters.
"""
from __future__ import annotations

from cybog.models.job import JobStatus
from cybog.state.assessment_state import AssessmentState


class PipelineRouter:
    """
    Evaluates conditions to determine which stages to run next.
    All decisions based solely on AssessmentState — no tool-specific knowledge.
    """

    @staticmethod
    def should_run_dnsx(state: AssessmentState, target_id: str) -> tuple[bool, str]:
        """Run dnsx only if subfinder produced at least one host."""
        hosts = state.hosts.get(target_id, [])
        if not hosts:
            return False, "subfinder produced 0 subdomains — skipping DNS resolution"
        return True, f"{len(hosts)} subdomains to resolve"

    @staticmethod
    def should_run_httpx(state: AssessmentState, target_id: str) -> tuple[bool, str]:
        """Run httpx if dnsx resolved at least one host."""
        hosts = state.hosts.get(target_id, [])
        # After dnsx, hosts have IPs. If hosts list is empty, skip.
        if not hosts:
            return False, "dnsx resolved 0 hosts — skipping HTTP probing"
        return True, f"{len(hosts)} resolved hosts to probe"

    @staticmethod
    def should_run_naabu(state: AssessmentState, target_id: str) -> tuple[bool, str]:
        """Run naabu if dnsx resolved at least one host. Parallel with httpx."""
        hosts = state.hosts.get(target_id, [])
        if not hosts:
            return False, "dnsx resolved 0 hosts — skipping port scan"
        return True, f"{len(hosts)} resolved hosts to port scan"

    @staticmethod
    def should_run_katana(state: AssessmentState, target_id: str) -> tuple[bool, str]:
        """Run katana if httpx found at least one live service."""
        services = state.services.get(target_id, [])
        if not services:
            return False, "httpx found 0 live services — skipping web crawl"
        return True, f"{len(services)} live services to crawl"

    @staticmethod
    def should_run_ffuf(state: AssessmentState, target_id: str) -> tuple[bool, str]:
        """Run ffuf if httpx found at least one live service."""
        services = state.services.get(target_id, [])
        if not services:
            return False, "httpx found 0 live services — skipping fuzzing"
        return True, f"{len(services)} live services to fuzz"

    @staticmethod
    def should_run_nuclei(state: AssessmentState, target_id: str) -> tuple[bool, str]:
        """Run nuclei if there are any URLs to scan."""
        all_urls = state.get_all_urls_for_target(target_id)
        if not all_urls:
            return False, "No endpoints discovered — skipping vulnerability scan"
        return True, f"{len(all_urls)} URLs to scan"

    @staticmethod
    def should_run_auth_validation(state: AssessmentState, target_id: str) -> tuple[bool, str]:
        """Run auth validation if there are findings in NEEDS_VALIDATION state."""
        findings = state.get_findings_for_target(target_id)
        needing_auth = [f for f in findings if f.validation_status == ValidationStatus.NEEDS_VALIDATION]
        if not needing_auth:
            return False, "No findings needing authentication validation"
        return True, f"{len(needing_auth)} findings need auth validation"

    @staticmethod
    def is_finding_validated(state: AssessmentState, target_id: str, finding: object) -> bool:
        """Check if a finding has been validated."""
        findings = state.get_findings_for_target(target_id)
        for f in findings:
            if f.url == finding.url and f.target_id == target_id:
                return f.validation_status in (ValidationStatus.VALIDATED, ValidationStatus.REPORTABLE)
        return False

    @staticmethod
    def has_unvalidated_findings(state: AssessmentState, target_id: str) -> bool:
        """Check if there are any unvalidated findings for a target."""
        findings = state.get_findings_for_target(target_id)
        return any(
            f.validation_status in (ValidationStatus.DISCOVERED, ValidationStatus.NEEDS_VALIDATION)
            for f in findings
        )
