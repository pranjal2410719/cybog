"""
Server-side scope compiler (T6).

The wizard-era contract: operators submit structured scope
(``scope_include[]`` / ``scope_exclude[]``) and the backend compiles it to
the canonical scope-file text the engine consumes. Compilation is
authoritative and deterministic:

- normalize: strip, lowercase (DNS is case-insensitive; IP/CIDR literals
  are unaffected), drop blanks.
- reject: control characters, inner whitespace, ``!`` prefixes (file
  syntax has no place in structured input), empty patterns, anything that
  is not a hostname/domain, IP literal, CIDR range, or a leading-``*.``
  wildcard over one of those.
- dedupe, preserving first-seen order.
- canonical text: includes first, then excludes as ``!``-lines — the same
  file syntax the engine's ScopeValidator parses, so the legacy ``.txt``
  path and the structured path converge on one representation.
- sha256 over the canonical text for preview display. (The binding
  snapshot hash pinned at authorization time is computed independently
  from admitted state — see AssessmentService.scope_snapshot.)

The engine still fail-closed validates the compiled file; the compiler
never weakens that gate, it only rejects malformed input early with a
clear 400.
"""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional

from cybog.adapters.validation import (
    has_control_chars,
    is_valid_hostname,
    is_valid_ip_or_host,
)


class ScopeCompileError(ValueError):
    """A scope input cannot be compiled; surfaces as HTTP 400."""


@dataclass
class CompiledScope:
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    compiled: str = ""
    sha256: str = ""
    warnings: List[str] = field(default_factory=list)


def _normalize_pattern(raw: str, *, where: str) -> str:
    value = raw.strip().lower()
    if not value:
        raise ScopeCompileError(f"{where}: empty scope pattern")
    if value.startswith("!"):
        raise ScopeCompileError(
            f"{where}: {raw!r} must not use '!' file syntax; "
            f"put exclusions in scope_exclude"
        )
    if has_control_chars(value) or any(ch.isspace() for ch in value):
        raise ScopeCompileError(f"{where}: {raw!r} contains illegal characters")
    if len(value) > 253:
        raise ScopeCompileError(f"{where}: {raw!r} exceeds 253 characters")
    body = value[2:] if value.startswith("*.") else value
    if not body or body.startswith("*."):
        raise ScopeCompileError(f"{where}: {raw!r} is not a valid scope pattern")
    if not _is_host_ip_cidr_or_name(body):
        raise ScopeCompileError(f"{where}: {raw!r} is not a valid scope pattern")
    return value


def _is_host_ip_cidr_or_name(body: str) -> bool:
    # IP literal or CIDR range (stdlib, strict=False accepts bare addresses).
    try:
        ipaddress.ip_network(body, strict=False)
        return True
    except ValueError:
        pass
    # Hostname / domain per the engine's own validator.
    return bool(is_valid_hostname(body) or is_valid_ip_or_host(body))


def _dedupe(values: List[str]) -> List[str]:
    seen = set()
    out = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def compile_scope(
    scope_file: Optional[str] = None,
    scope_include: Optional[List[str]] = None,
    scope_exclude: Optional[List[str]] = None,
) -> CompiledScope:
    """
    Compile operator scope input to canonical scope-file text.

    Exactly one source must be provided: legacy ``scope_file`` text, or
    structured ``scope_include``/``scope_exclude`` arrays (both may be
    given together; at least one must be non-empty).
    """
    structured = scope_include is not None or scope_exclude is not None
    if structured and scope_file is not None:
        raise ScopeCompileError(
            "Provide either scope_file or scope_include/scope_exclude, not both"
        )
    if not structured:
        if scope_file is None:
            raise ScopeCompileError("No scope provided")
        # Legacy path: still normalize so both paths converge. Comment and
        # blank lines are dropped; '!' lines become exclusions.
        include, exclude = [], []
        for line in scope_file.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("!"):
                exclude.append(_normalize_pattern(stripped[1:], where="scope_file"))
            else:
                include.append(_normalize_pattern(stripped, where="scope_file"))
    else:
        include = [_normalize_pattern(p, where="scope_include")
                   for p in (scope_include or [])]
        exclude = [_normalize_pattern(p, where="scope_exclude")
                   for p in (scope_exclude or [])]

    include, exclude = _dedupe(include), _dedupe(exclude)
    if not include:
        raise ScopeCompileError("Scope must include at least one pattern")

    warnings = [f"{p} is excluded by scope_exclude" for p in include if p in exclude]
    lines = include + [f"!{p}" for p in exclude]
    compiled = "\n".join(lines) + "\n"
    digest = hashlib.sha256(compiled.encode("utf-8")).hexdigest()
    return CompiledScope(include=include, exclude=exclude, compiled=compiled,
                         sha256=digest, warnings=warnings)
