"""
Pipeline profiles (T8): workflow configuration, not labels.

Before T8 the profile was a string the scheduler never read. Now each
profile resolves to an explicit stage set plus optional tool overrides:

- quick:    subfinder -> dnsx -> httpx -> nuclei (no port scan, no crawl,
  no fuzzing). Fast discovery + vulnerability signal.
- standard: all seven stages (current behavior, unchanged).
- full:     all seven stages + auth-validation attempt + deeper katana
  crawl + longer nuclei timeout.

Full's template set and wordlist need no overrides: the shipped config
already runs nuclei's default (full) template bundle and the 43k-line
wordlist. Those are documented here so a future restriction has a place
to live.

Config overrides are applied to a deep copy (see apply_profile) — the
shared loaded config is never mutated, which matters because the backend
reuses one config object across assessments.
"""
from __future__ import annotations

from typing import Dict, Tuple

QUICK_STAGES: Tuple[str, ...] = ("subfinder", "dnsx", "httpx", "nuclei")
STANDARD_STAGES: Tuple[str, ...] = (
    "subfinder", "dnsx", "httpx", "naabu", "katana", "ffuf", "nuclei",
)
FULL_STAGES: Tuple[str, ...] = STANDARD_STAGES

PROFILES: Dict[str, Tuple[str, ...]] = {
    "quick": QUICK_STAGES,
    "standard": STANDARD_STAGES,
    "full": FULL_STAGES,
}

# Full-profile tool overrides (applied to a config copy).
FULL_KATANA_EXTRA_ARGS = ["-ct", "120s", "-c", "10", "-d", "3"]
FULL_NUCLEI_TIMEOUT = 1800


def validate_profile(profile: str) -> str:
    """Return the profile, or raise ValueError for unknown names."""
    if profile not in PROFILES:
        raise ValueError(
            f"Unknown profile {profile!r} "
            f"(known: {', '.join(sorted(PROFILES))})"
        )
    return profile


def stages_for(profile: str) -> Tuple[str, ...]:
    """Stage set for a profile (validates the name)."""
    return PROFILES[validate_profile(profile)]


def apply_profile(config, profile: str):
    """
    Return an independent config copy with the profile's tool overrides.

    Only ``full`` changes tool behavior today (auth-validation attempt +
    deeper crawl + longer nuclei budget). quick/standard get a clean copy
    with identical values. The input config is never mutated.
    """
    from cybog.config.models import CybogConfig

    validate_profile(profile)
    run_config: CybogConfig = config.model_copy(deep=True)
    if profile == "full":
        run_config.tools.auth.enabled = True
        run_config.tools.katana.extra_args = list(FULL_KATANA_EXTRA_ARGS)
        run_config.tools.nuclei.timeout = FULL_NUCLEI_TIMEOUT
    return run_config
