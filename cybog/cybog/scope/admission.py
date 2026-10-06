"""
Per-host scope admission (T9).

The create-time scope gate admits seed targets, but downstream stages
consume *discovered* data (dnsx eats subfinder hosts, httpx eats resolved
hosts, katana/ffuf/nuclei eat crawled URLs) without re-validation — a
CNAME to an out-of-scope domain or a crawled off-site link would be
scanned. This module classifies every discovered value before it may
enter a stage's input:

- IN_SCOPE:     matches an include pattern and no exclusion → scannable.
- OUT_OF_SCOPE: matches an exclusion, or matches nothing (fail-closed).
- AMBIGUOUS:    narrowly defined — an IP literal against a domain-only
  scope (no IP/CIDR include to decide membership). Recorded, never
  scanned, flagged for operator review.
- INVALID:      syntactically unusable (empty, overlong, control chars,
  inner whitespace). Never scanned.

Matching reuses ScopeValidator._matches (the exact create-time rule), so
admission can never disagree with the gate. Refused values are recorded
on the assessment (state.out_of_scope) for transparency; the workspace
shows "N discovered — M in scope, K out of scope" without ever scanning
the K.
"""
from __future__ import annotations

import ipaddress
from enum import Enum
from urllib.parse import urlsplit

from cybog.adapters.validation import has_control_chars
from cybog.models.assessment import Scope
from cybog.scope.validator import ScopeValidator


class AssetClass(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    AMBIGUOUS = "AMBIGUOUS"
    INVALID = "INVALID"


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _scope_has_ip_patterns(scope: Scope) -> bool:
    for pattern in list(scope.patterns):
        body = pattern.removeprefix("*.")
        try:
            ipaddress.ip_network(body, strict=False)
            return True
        except ValueError:
            continue
    return False


def classify_asset(value: str, scope: Scope) -> tuple[AssetClass, str]:
    """
    Classify a discovered hostname, IP literal, or URL host.

    Returns (classification, reason). Pure function: no I/O, no state.
    """
    candidate = (value or "").strip().lower()
    if not candidate:
        return AssetClass.INVALID, "empty value"
    if len(candidate) > 253:
        return AssetClass.INVALID, "exceeds 253 characters"
    if has_control_chars(candidate) or any(ch.isspace() for ch in candidate):
        return AssetClass.INVALID, "illegal characters"

    # Exclusions win over everything (same precedence as the gate).
    for exclude in scope.explicit_excludes:
        if ScopeValidator._matches(candidate, exclude.lower()):
            return AssetClass.OUT_OF_SCOPE, f"matches exclusion '{exclude}'"

    for pattern in scope.patterns:
        if ScopeValidator._matches(candidate, pattern.lower()):
            return AssetClass.IN_SCOPE, f"matches pattern '{pattern}'"

    # Valid syntax, no decision possible: IP literal against a scope that
    # cannot express IP membership. Never scan; flag for review.
    if _is_ip_literal(candidate) and not _scope_has_ip_patterns(scope):
        return AssetClass.AMBIGUOUS, "IP literal against a domain-only scope"

    # Fail closed: valid but unmatched.
    return AssetClass.OUT_OF_SCOPE, "matches no include pattern"


def host_of_url(url: str) -> str:
    """Extract the host part of a URL for classification ("" if unparseable)."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def partition(values: list[str], scope: Scope) -> tuple[list[str], list[tuple[str, AssetClass, str]]]:
    """
    Split values into (admitted, refused).

    Refused entries are (value, classification, reason) triples for the
    out_of_scope record. Order-preserving on both sides.
    """
    admitted: list[str] = []
    refused: list[tuple[str, AssetClass, str]] = []
    for value in values:
        classification, reason = classify_asset(value, scope)
        if classification == AssetClass.IN_SCOPE:
            admitted.append(value)
        else:
            refused.append((value, classification, reason))
    return admitted, refused
