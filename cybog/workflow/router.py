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
