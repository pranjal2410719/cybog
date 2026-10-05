"""
cybog/scope/validator.py

Authorization is a HARD GATE.
Never infer authorization from DNS resolution, HTTP accessibility,
public exposure, or ownership assumptions.
The scope file is the sole source of truth.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from cybog.models.assessment import Authorization, AuthorizationStatus, Scope
from cybog.models.target import Target
from cybog.logging_setup import get_logger

_log = get_logger("scope.validator")


class ScopeValidationError(Exception):
    """Raised when scope cannot be loaded or is misconfigured."""


class ScopeValidator:
    def __init__(self, scope_file: str):
        self.scope_file = Path(scope_file)

    def load_scope(self) -> Scope:
        """Load authorized scope patterns from file. Fails closed if missing."""
        if not self.scope_file.exists():
            raise ScopeValidationError(
                f"Scope file not found: {self.scope_file.resolve()}. "
                "Cannot proceed without explicit authorization."
            )
        lines = self.scope_file.read_text(encoding="utf-8").splitlines()
        patterns: list[str] = []
        excludes: list[str] = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("!"):
                excludes.append(stripped[1:].strip())
            else:
                patterns.append(stripped)
        if not patterns:
            raise ScopeValidationError(
                "Scope file contains no valid patterns. "
                "Add at least one authorized domain/wildcard."
            )
        return Scope(patterns=patterns, explicit_excludes=excludes)

    def build_authorization(self, scope: Scope) -> Authorization:
        return Authorization(
            required=True,
            scope_file=str(self.scope_file),
            status=AuthorizationStatus.AUTHORIZED,
            authorized_patterns=scope.patterns,
        )

    def is_authorized(self, domain: str, scope: Scope) -> bool:
        """
        Returns True only if domain matches at least one scope pattern
        AND is not in explicit_excludes.
        Fails CLOSED: any doubt = not authorized.
        """
        domain = domain.strip().lower()
        # Check explicit excludes first
        for exclude in scope.explicit_excludes:
            if self._matches(domain, exclude.lower()):
                _log.warning(f"EXCLUDED: {domain} matched exclude pattern '{exclude}'")
                return False
        # Check authorized patterns
        for pattern in scope.patterns:
            if self._matches(domain, pattern.lower()):
                return True
        return False

    def validate_target(self, target: Target, scope: Scope) -> tuple[bool, str]:
        """
        Returns (authorized: bool, reason: str).
        Caller must respect the result — never override authorization.
        """
        if self.is_authorized(target.domain, scope):
            return True, f"IN_SCOPE: matched authorized pattern"
        return False, f"OUT_OF_SCOPE: '{target.domain}' has no match in authorized scope"

    @staticmethod
    def _matches(domain: str, pattern: str) -> bool:
        """Glob match. *.example.com matches sub.example.com but NOT example.com."""
        # Exact match
        if domain == pattern:
            return True
        # Wildcard glob
        if "*" in pattern:
            return fnmatch.fnmatch(domain, pattern)
        # Subdomain check: pattern=example.com, domain=sub.example.com
        if domain.endswith("." + pattern):
            return True
        return False

    @staticmethod
    def validate_domain_format(domain: str) -> bool:
        """Basic domain format validation. Does not imply authorization."""
        pattern = re.compile(
            r"^(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}$"
        )
        return bool(pattern.match(domain.strip()))
