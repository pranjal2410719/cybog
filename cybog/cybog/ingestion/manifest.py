"""
cybog/ingestion/manifest.py

TargetManifestLoader — read, validate, deduplicate, and create Target objects.
A .txt file is an INPUT MANIFEST, not a batch execution unit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from cybog.models.target import Target
from cybog.logging_setup import get_logger

_log = get_logger("ingestion.manifest")

# Basic domain regex: allows labels with hyphens, requires TLD
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}$"
)


class ManifestLoadError(Exception):
    pass


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def normalize_domain(raw: str) -> str:
    """
    Reduce one manifest line to a bare lowercase domain.

    A manifest is a list of hosts, but users routinely paste the URLs they have
    in a browser bookmark or a scan result. Without this, ``https://example.org/
    path`` failed the domain regex and was dropped by validate_domains() with
    only a log warning — the run succeeded while silently scanning fewer hosts
    than the operator asked for. Normalizing here makes the CLI and the HTTP API
    agree with what the web form previews.

    Applied in order: trim, strip scheme, strip userinfo, strip path, strip
    query/fragment, strip port, strip trailing dot, lowercase.
    """
    value = raw.strip()
    if not value:
        return ""

    scheme = _SCHEME_RE.match(value)
    if scheme:
        value = value[scheme.end():]

    at = value.find("@")
    slash = value.find("/")
    if at > -1 and (slash == -1 or at < slash):
        value = value[at + 1:]

    slash = value.find("/")
    if slash > -1:
        value = value[:slash]

    for sep in ("?", "#"):
        idx = value.find(sep)
        if idx > -1:
            value = value[:idx]

    # Strip a port, but only a trailing :digits so an IPv6 literal is not cut.
    port = re.search(r":(\d+)$", value)
    if port:
        value = value[: port.start()]

    if value.endswith("."):
        value = value[:-1]

    return value.lower()


class TargetManifestLoader:
    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)

    def load_raw_domains(self) -> list[str]:
        """
        Read file, normalize each line to a bare domain, drop comments and
        blanks, and deduplicate.

        Normalization happens BEFORE dedup so that ``example.com`` and
        ``https://example.com/`` collapse to a single target rather than
        producing one valid host and one rejected line.
        """
        if not self.file_path.exists():
            raise ManifestLoadError(
                f"Target file not found: {self.file_path.resolve()}"
            )
        lines = self.file_path.read_text(encoding="utf-8").splitlines()
        seen: set[str] = set()
        domains: list[str] = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            domain = normalize_domain(stripped)
            if not domain:
                continue
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)
        return domains

    def validate_domains(self, domains: list[str]) -> tuple[list[str], list[str]]:
        """
        Returns (valid_domains, invalid_domains).
        Invalid domains are logged but do NOT stop the pipeline.
        """
        valid: list[str] = []
        invalid: list[str] = []
        for d in domains:
            if _DOMAIN_RE.match(d):
                valid.append(d)
            else:
                _log.warning(f"Invalid domain format, skipping: '{d}'")
                invalid.append(d)
        return valid, invalid

    def create_targets(
        self,
        domains: list[str],
        batch_name: Optional[str] = None,
    ) -> list[Target]:
        """Create Target objects from validated domain list."""
        return [
            Target(domain=d, source_batch=batch_name)
            for d in domains
        ]

    def load(self, batch_name: Optional[str] = None) -> list[Target]:
        """Full load pipeline: read -> validate format -> deduplicate -> create Targets."""
        raw = self.load_raw_domains()
        _log.info(f"Loaded {len(raw)} raw domains from {self.file_path.name}")
        valid, invalid = self.validate_domains(raw)
        _log.info(
            f"Format validation: {len(valid)} valid, {len(invalid)} invalid"
        )
        targets = self.create_targets(valid, batch_name)
        return targets
