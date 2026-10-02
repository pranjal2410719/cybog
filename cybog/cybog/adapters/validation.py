"""
cybog/adapters/validation.py

Shared, dependency-free input-validation helpers for the tool adapters.

These helpers exist because every adapter builds ``list[str]`` commands that are
passed straight to ``asyncio.create_subprocess_exec`` (NO shell is invoked).  The
relevant threats are therefore *not* classic shell metacharacter injection, but:

* **Argument injection** — a value beginning with ``-`` is parsed by the tool as a
  flag rather than a value (e.g. a target domain of ``-o`` or ``--config``
  hijacks the command).
* **Newline / NUL injection into input files** — ``dnsx``, ``httpx``, ``naabu``,
  ``katana`` and ``nuclei`` write derived data to a one-value-per-line input file
  joined with ``\\n``.  A hostname containing a newline silently injects EXTRA
  lines = extra hosts scanned OUTSIDE the authorized scope (scope escape).
* **Path traversal / control characters** in path-valued config
  (ffuf wordlist, nuclei templates).
* **Unvalidated URLs** used to build commands / input files.

All functions are pure and side-effect free so they can be unit-tested in
isolation.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

# Any C0 control character (0x00-0x1f) or DEL (0x7f).  Covers NUL, LF, CR, TAB,
# ESC, etc.  These corrupt one-value-per-line input files and argv boundaries.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# An RFC-1123 label: 1..63 chars, alnum + internal hyphen, must NOT start or end
# with a hyphen.  Enforced by anchoring alnum at both ends.
_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# Shell metacharacters that have no legitimate place in a file-system path.  No
# shell is invoked by the adapters, but we reject them defensively: a path that
# later reaches any shell-adjacent context would otherwise be dangerous.
_PATH_METACHARS = (";", "|", "&", "`", "$(")

_KNOWN_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "informational",
    "unknown",
}

_ALLOWED_URL_SCHEMES = {"http", "https"}


def has_control_chars(value: str) -> bool:
    """True if ``value`` contains any character with ord < 0x20 or ord == 0x7f.

    Threat: NUL / newline / CR / tab (and other C0 controls) corrupt parsing of
    one-value-per-line input files and can cause argv field terminators (NUL)
    when interpolated into argv.  Newline in particular is a scope-escape
    vector.
    """
    if not isinstance(value, str):
        return True
    return _CONTROL_CHARS_RE.search(value) is not None


def is_valid_hostname(host: str) -> bool:
    """Validate an RFC-1123-ish hostname.

    Threat: a value such as ``-o``, ``--config``, ``example.com\\nevil.com`` or
    ``../../../etc/passwd`` must never reach an argv slot or an input file.  This
    rejects leading dashes (argument injection), control characters / embedded
    newlines (scope escape via input files), path separators and over-length
    labels.
    """
    if not isinstance(host, str):
        return False
    candidate = host.strip()
    # Leading dash on the whole value is the core argument-injection vector.
    if candidate.startswith("-"):
        return False
    if has_control_chars(candidate):
        return False
    # Optional single trailing dot is legal DNS syntax; tolerate & strip it.
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if not candidate or len(candidate) > 253:
        return False
    labels = candidate.split(".")
    if not labels or any(label == "" for label in labels):
        return False  # empty labels (e.g. "a..b") are invalid
    for label in labels:
        if len(label) < 1 or len(label) > 63:
            return False
        if not _HOSTNAME_LABEL_RE.match(label):
            return False
    return True


def is_valid_domain(domain: str) -> bool:
    """A domain is a hostname for our purposes — apply the same rules."""
    return is_valid_hostname(domain)


def is_valid_ip_or_host(value: str) -> bool:
    """Accept an IPv4/IPv6 literal OR a hostname.

    Threat: host lists (dnsx, httpx, naabu) may legitimately contain IP literals;
    we must not reject those while still rejecting the argument-injection /
    control-char / newline vectors that ``is_valid_hostname`` already blocks.
    """
    if not isinstance(value, str):
        return False
    if has_control_chars(value):
        return False
    candidate = value.strip()
    if candidate.startswith("-"):
        return False
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return is_valid_hostname(value)


def is_valid_url(url: str) -> bool:
    """Validate a URL before it is placed on the command line or in an input file.

    Threat: URLs are used verbatim by ffuf, katana, nuclei and the auth adapter.
    A URL with a missing or non-http scheme, or containing control chars /
    whitespace, could be mis-parsed or — if it began with ``-`` — treated as a
    flag by the tool.
    """
    if not isinstance(url, str):
        return False
    candidate = url.strip()
    if not candidate:
        return False
    if candidate.startswith("-"):
        return False
    if has_control_chars(candidate):
        return False
    if " " in candidate or "\t" in candidate:
        return False
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        return False
    if not parsed.netloc:
        return False
    return True


def is_safe_path_value(value: str) -> bool:
    """Validate a path-valued config field (ffuf wordlist, nuclei templates).

    Threat: path traversal (``..``) or control characters / NUL could redirect a
    tool to read an unintended file (e.g. ``../../../etc/passwd``) or corrupt the
    argv/file path.  Shell metacharacters are rejected defensively even though
    no shell is invoked.
    """
    if not isinstance(value, str):
        return False
    if not value:
        return False
    if has_control_chars(value):
        return False
    if value.startswith("-"):
        return False
    for bad in _PATH_METACHARS:
        if bad in value:
            return False
    parts = value.replace("\\", "/").split("/")
    if any(part == ".." for part in parts):
        return False
    return True


def is_valid_credentials(credentials: str, auth_method: str = "basic") -> bool:
    """Validate a credentials string before it is placed on a command line.

    Threat: credentials with control characters could corrupt logs/state that
    persist them (redacted).  For ``basic``/``digest`` the value must carry a
    ``user:password`` separator to be usable by the tool; a bare token is
    accepted for ``bearer``/``custom``.
    """
    if not isinstance(credentials, str):
        return False
    if not credentials.strip():
        return False
    if has_control_chars(credentials):
        return False
    method = (auth_method or "").strip().lower()
    if method in ("basic", "digest") and ":" not in credentials:
        return False
    return True


def sanitize_line_value(value: str) -> Optional[str]:
    """Return a cleaned single-line string for an input file, or None.

    Threat: input files are one-value-per-line.  Any value containing a control
    character (notably newline) would inject extra lines — a scope-escape
    vector.  Callers MUST treat the return value ``None`` as "drop this value"
    and must NOT write it to the input file.
    """
    if not isinstance(value, str):
        return None
    if has_control_chars(value):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned


def validate_host_list(hosts: list[str]) -> tuple[list[str], list[str]]:
    """Split a host list into ``(valid, rejected)`` single-token entries.

    Threat: each entry that reaches an input file becomes an authoritative scan
    target.  A newline-bearing entry is a scope-escape; a leading-dash entry is
    argument injection.  Both are REJECTED here (returned in ``rejected``) and
    **never** silently passed through.  Valid entries are stripped and lowercased
    (DNS is case-insensitive).
    """
    valid: list[str] = []
    rejected: list[str] = []
    if not hosts:
        return valid, rejected
    for entry in hosts:
        if not isinstance(entry, str):
            rejected.append(str(entry))
            continue
        cleaned = entry.strip()
        if not cleaned:
            rejected.append(entry)
            continue
        if is_valid_ip_or_host(cleaned):
            valid.append(cleaned.lower())
        else:
            rejected.append(entry)
    return valid, rejected


def validate_url_list(urls: list[str]) -> tuple[list[str], list[str]]:
    """Split a URL list into ``(valid, rejected)`` entries.

    Threat: same scope-escape / argument-injection reasoning as
    ``validate_host_list`` but for the URLs consumed by katana, nuclei and the
    auth adapter.
    """
    valid: list[str] = []
    rejected: list[str] = []
    if not urls:
        return valid, rejected
    for entry in urls:
        if not isinstance(entry, str):
            rejected.append(str(entry))
            continue
        if is_valid_url(entry):
            valid.append(entry.strip())
        else:
            rejected.append(entry)
    return valid, rejected


def validate_severity(value: str) -> bool:
    """Validate nuclei ``-severity`` (comma-separated list of known severities).

    Threat: an attacker-controlled severity string could attempt to inject
    flags; we only accept the documented severity tokens.  An empty string is
    allowed (semantics: scan at all severities).
    """
    if not isinstance(value, str):
        return False
    if has_control_chars(value):
        return False
    if value == "":
        return True
    for token in value.split(","):
        token = token.strip().lower()
        if token not in _KNOWN_SEVERITIES:
            return False
    return True
