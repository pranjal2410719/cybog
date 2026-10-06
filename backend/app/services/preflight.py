"""
Preflight checks (T7: mandatory pre-execution boundary).

Every check is a pure function over explicit inputs so each is unit
testable without a running pipeline — except ``check_toolchain``, which
probes real binaries and is monkeypatched in tests via ``_stage_adapters``.

A preflight passes only when ALL checks pass; the integration layer then
moves the assessment CREATED -> READY. Execution starts exclusively from
READY, which eliminates the false-"running" class: an assessment the
operator sees as started has proven it *can* start.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from cybog.models.assessment import AuthorizationStatus
from cybog.models.target import TargetStatus
from cybog.profiles import PROFILES

# Profiles with defined pipeline behavior (single source: cybog.profiles).
KNOWN_PROFILES = tuple(sorted(PROFILES))

# The seven MVP stage tools, in pipeline order (frozen tool boundary).
STAGE_TOOLS = ("subfinder", "dnsx", "httpx", "naabu", "katana", "ffuf", "nuclei")


@dataclass
class PreflightCheck:
    name: str
    ok: bool
    detail: str = ""


def check_target(state: Any) -> PreflightCheck:
    targets = list(state.targets.values())
    if not targets:
        return PreflightCheck("target", False, "no targets admitted")
    admitted = [t for t in targets if t.status == TargetStatus.IN_SCOPE]
    if not admitted:
        return PreflightCheck("target", False, "no IN_SCOPE targets")
    domains = sorted(t.domain for t in admitted)
    return PreflightCheck("target", True, f"{len(admitted)} target(s): {', '.join(domains[:3])}")


def check_scope(state: Any) -> PreflightCheck:
    scope = state.assessment.scope
    patterns = list(scope.patterns) if scope else []
    if not patterns:
        return PreflightCheck("scope", False, "no scope patterns")
    return PreflightCheck("scope", True, f"{len(patterns)} pattern(s)")


def check_authorization(state: Any) -> PreflightCheck:
    auth = state.assessment.authorization
    if not auth or auth.status != AuthorizationStatus.AUTHORIZED:
        return PreflightCheck("authorization", False, "not human-authorized")
    if not auth.scope_sha256:
        return PreflightCheck(
            "authorization", False,
            "no pinned scope snapshot; confirm authorization again",
        )
    if not auth.authorized_by_user_id:
        return PreflightCheck("authorization", False, "no attributable confirmer")
    return PreflightCheck(
        "authorization", True,
        f"confirmed by {auth.authorized_by_user_id}",
    )


def check_profile(state: Any) -> PreflightCheck:
    profile = state.assessment.profile
    if profile not in KNOWN_PROFILES:
        return PreflightCheck(
            "profile", False,
            f"unknown profile {profile!r} (known: {', '.join(KNOWN_PROFILES)})",
        )
    return PreflightCheck("profile", True, profile)


def check_worker(is_running: bool) -> PreflightCheck:
    if is_running:
        return PreflightCheck("worker", False, "a pipeline is already running")
    return PreflightCheck("worker", True, "available")


def check_storage(config: Any) -> PreflightCheck:
    root = Path(str(config.output.root)).expanduser()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return PreflightCheck("artifact_storage", False, f"cannot create {root}: {exc}")
    if not os.access(root, os.W_OK):
        return PreflightCheck("artifact_storage", False, f"{root} is not writable")
    return PreflightCheck("artifact_storage", True, str(root))


def check_scope_compiler(state: Any) -> PreflightCheck:
    """The stored scope re-derives cleanly (round-trip integrity)."""
    from cybog.services.assessment_service import AssessmentService
    snapshot, digest = AssessmentService.scope_snapshot(
        state.assessment.scope, state)
    if not snapshot["include"]:
        return PreflightCheck("scope_compiler", False, "scope compiles to nothing")
    auth = state.assessment.authorization
    if auth and auth.status == AuthorizationStatus.AUTHORIZED:
        if auth.scope_sha256 != digest:
            return PreflightCheck(
                "scope_compiler", False,
                "current scope differs from the pinned snapshot; "
                "confirm authorization again",
            )
    return PreflightCheck("scope_compiler", True, f"sha256: {digest[:16]}…")


def _stage_adapters(config: Any) -> List[Any]:
    """Construct the seven stage adapters (seam for tests)."""
    from cybog.adapters.dnsx import DnsxAdapter
    from cybog.adapters.ffuf import FfufAdapter
    from cybog.adapters.httpx import HttpxAdapter
    from cybog.adapters.katana import KatanaAdapter
    from cybog.adapters.naabu import NaabuAdapter
    from cybog.adapters.nuclei import NucleiAdapter
    from cybog.adapters.subfinder import SubfinderAdapter
    tools = config.tools
    return [
        ("subfinder", SubfinderAdapter(tools.subfinder)),
        ("dnsx", DnsxAdapter(tools.dnsx)),
        ("httpx", HttpxAdapter(tools.httpx)),
        ("naabu", NaabuAdapter(tools.naabu)),
        ("katana", KatanaAdapter(tools.katana)),
        ("ffuf", FfufAdapter(tools.ffuf)),
        ("nuclei", NucleiAdapter(tools.nuclei)),
    ]


async def check_toolchain(config: Any, timeout_seconds: float = 90.0) -> PreflightCheck:
    """
    Probe every stage binary via the adapters' own health checks.

    Runs concurrently in threads (health_check is blocking subprocess work)
    under one overall timeout so a hanging probe cannot stall preflight.
    """
    adapters = _stage_adapters(config)
    loop = asyncio.get_running_loop()

    async def _probe(name: str, adapter: Any) -> str | None:
        try:
            result = await loop.run_in_executor(None, adapter.health_check)
        except Exception as exc:  # misconfigured adapter: report, don't crash
            return f"{name}: health check errored ({exc})"
        if result.available:
            return None
        reason = result.error or "binary unavailable"
        return f"{name}: {reason}"

    try:
        problems = await asyncio.wait_for(
            asyncio.gather(*[_probe(n, a) for n, a in adapters]),
            timeout=timeout_seconds,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return PreflightCheck("toolchain", False, "health checks timed out")
    missing = sorted(p for p in problems if p)
    if missing:
        return PreflightCheck(
            "toolchain", False,
            "unavailable: " + "; ".join(missing),
        )
    return PreflightCheck("toolchain", True, f"{len(adapters)}/7 binaries available")


def as_dict(check: PreflightCheck) -> Dict[str, Any]:
    return {"name": check.name, "ok": check.ok, "detail": check.detail}
