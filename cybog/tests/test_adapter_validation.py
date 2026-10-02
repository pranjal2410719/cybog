"""
Unit + integration tests for cybog/adapters/validation.py and the per-adapter
hard gates in build_command.

Covers:
  * Each validator function with accept/reject cases, including the documented
    attack inputs (argument injection, newline scope-escape, control chars,
    path traversal, shell metacharacters).
  * validate_host_list / validate_url_list scope-escape partitioning.
  * sanitize_line_value null-on-control-char contract.
  * validate_severity allow-list.
  * For ALL 8 adapters: build_command raises ToolAdapterError on hostile input
    and SUCCEEDS on a legitimate value.
  * For the 5 input-file writers (dnsx, httpx, naabu, katana, nuclei): a
    newline-bearing host/url list entry is REJECTED (raises) rather than
    silently written to the input file.
"""
from __future__ import annotations

import pytest

from cybog.adapters.base import ToolAdapterError
from cybog.adapters.validation import (
    has_control_chars,
    is_valid_hostname,
    is_valid_domain,
    is_valid_ip_or_host,
    is_valid_url,
    is_safe_path_value,
    is_valid_credentials,
    sanitize_line_value,
    validate_host_list,
    validate_url_list,
    validate_severity,
)
from cybog.config.models import CybogConfig, ToolConfig, AuthToolConfig
from cybog.models.job import StageJob

# ---------------------------------------------------------------------- #
# Helpers / fixtures
# ---------------------------------------------------------------------- #
HOSTILE_HOSTS = (
    "-o",
    "--config",
    "example.com\nevil.com",
    "example.com\r\nX",
    "a\x00b",
    "../../../etc/passwd",
    "foo;rm -rf /",
    "a|b",
    "a`b",
    "a$(b)",
    "-example.com",
    "a..b",
    "",
)


def _job(target_domain: str, stage: str) -> StageJob:
    return StageJob(
        assessment_id="a1",
        target_id="t1",
        target_domain=target_domain,
        stage=stage,
    )


def _cfg() -> CybogConfig:
    return CybogConfig()


# ---------------------------------------------------------------------- #
# has_control_chars
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("value,expected", [
    ("a\x00b", True),
    ("example.com\nevil.com", True),
    ("example.com\r\nX", True),
    ("a\tb", True),
    ("a\x1fb", True),
    ("DEL\x7fchar", True),
    ("example.com", False),
    ("10.0.0.1", False),
    ("", False),
    (123, True),
])
def test_has_control_chars(value, expected):
    assert has_control_chars(value) is expected


# ---------------------------------------------------------------------- #
# is_valid_hostname / is_valid_domain
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("host", HOSTILE_HOSTS)
def test_hostname_rejects_hostile(host):
    assert is_valid_hostname(host) is False


@pytest.mark.parametrize("host,expected", [
    ("example.com", True),
    ("sub.example.com", True),
    ("a.example.com.", True),  # trailing dot -> VALID
    ("a-1.example.com", True),  # internal hyphen is fine
    ("10.0.0.1", True),         # hostname-shaped, digits allowed in labels
    ("a", True),
    ("A.B.C", True),            # case-insensitive labels
])
def test_hostname_accepts_legit(host, expected):
    assert is_valid_hostname(host) is expected


@pytest.mark.parametrize("domain", HOSTILE_HOSTS)
def test_domain_rejects_hostile(domain):
    assert is_valid_domain(domain) is False


@pytest.mark.parametrize("domain", ["example.com", "sub.example.com", "a.example.com."])
def test_domain_accepts_legit(domain):
    assert is_valid_domain(domain) is True


def test_hostname_rejects_oversized():
    # 64-char label is over the 63-char RFC-1123 limit.
    label = "a" * 64
    assert is_valid_hostname(f"{label}.example.com") is False
    # A full 300-char name exceeds the 253-char total limit.
    long_name = ".".join(["b" * 40] * 8)  # 8*40 + 7 = 327 chars
    assert len(long_name) > 253
    assert is_valid_hostname(long_name) is False


def test_hostname_rejects_trailing_dot_only_or_leading_dash_with_dot():
    assert is_valid_hostname(".") is False
    assert is_valid_hostname("-x.") is False


# ---------------------------------------------------------------------- #
# is_valid_ip_or_host
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("value,expected", [
    ("2001:db8::1", True),
    ("10.0.0.1", True),
    ("2606:4700:4700::1111", True),
    ("example.com", True),
    ("::1", True),
    ("-o", False),
    ("example.com\nevil.com", False),
    ("a\x00b", False),
    ("", False),
])
def test_ip_or_host(value, expected):
    assert is_valid_ip_or_host(value) is expected


# ---------------------------------------------------------------------- #
# is_valid_url
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("url", [
    "http://x.com/a b",
])
def test_url_rejects_hostile(url):
    assert is_valid_url(url) is False


@pytest.mark.parametrize("url,expected", [
    ("https://api.example.com", True),
    ("https://api.example.com/admin", True),
    ("http://x.com", True),
    ("http://x.com:8080/path?q=1", True),
    ("ftp://x.com", False),
    ("", False),
    ("not a url", False),
    ("http://x.com/a b", False),
    ("-o", False),
    ("https://x.com/evil\ninjected.com", False),
])
def test_url_accept_reject(url, expected):
    assert is_valid_url(url) is expected


# ---------------------------------------------------------------------- #
# is_safe_path_value
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("path,expected", [
    ("../../../etc/passwd", False),
    ("foo;rm -rf /", False),
    ("a|b", False),
    ("a&b", False),
    ("a`b", False),
    ("a$(b)", False),
    ("a\x00b", False),
    ("-o", False),
    ("../etc/passwd", False),
    ("", False),
    (123, False),
])
def test_safe_path_rejects(path, expected):
    assert is_safe_path_value(path) is False


@pytest.mark.parametrize("path", [
    "config/wordlists/common.txt",
    "/opt/cybog/wordlists/common.txt",
    "wordlist.txt",
    "./config/wordlists/common.txt",
])
def test_safe_path_accepts(path):
    assert is_safe_path_value(path) is True


# ---------------------------------------------------------------------- #
# is_valid_credentials
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("creds,expected", [
    ("u:p", True),
    ("user:password-with-dash", True),
    ("badtoken", False),               # basic requires a colon
    ("u:p\x00", False),                # control char
    ("", False),
    ("   ", False),
    ("123", False),
    (None, False),
])
def test_credentials(creds, expected):
    assert is_valid_credentials(creds, auth_method="basic") is expected


def test_credentials_bearer_accepts_bare_token():
    assert is_valid_credentials("sometoken", auth_method="bearer") is True


# ---------------------------------------------------------------------- #
# sanitize_line_value
# ---------------------------------------------------------------------- #
def test_sanitize_returns_none_for_control_chars():
    assert sanitize_line_value("a\nb") is None
    assert sanitize_line_value("a\x00b") is None
    assert sanitize_line_value("a\r\nb") is None


def test_sanitize_strips_and_returns_value():
    assert sanitize_line_value("  a  ") == "a"
    assert sanitize_line_value("example.com") == "example.com"


def test_sanitize_drops_empty():
    assert sanitize_line_value("") is None
    assert sanitize_line_value("   ") is None
    assert sanitize_line_value("\t") is None


# ---------------------------------------------------------------------- #
# validate_host_list — scope-escape property
# ---------------------------------------------------------------------- #
def test_validate_host_list_splits_valid_and_rejected():
    valid, rejected = validate_host_list(["example.com", "10.0.0.1"])
    assert valid == ["example.com", "10.0.0.1"]
    assert rejected == []


def test_validate_host_list_newline_entry_lands_in_rejected():
    hosts = ["example.com", "evil.com\ninjected.com"]
    valid, rejected = validate_host_list(hosts)
    # SCOPE-ESCAPE PROPERTY: newline-bearing entry must be rejected, not valid.
    assert "evil.com\ninjected.com" in rejected
    assert "evil.com\ninjected.com" not in valid
    assert "evil.com\ninjected.com" not in valid
    assert "evil.com\ninjected.com" not in valid
    assert valid == ["example.com"]


def test_validate_host_list_rejects_leading_dash():
    valid, rejected = validate_host_list(["-o", "example.com"])
    assert "-o" in rejected
    assert valid == ["example.com"]


def test_validate_host_list_empty():
    assert validate_host_list([]) == ([], [])


def test_validate_host_list_strips_and_lowercases():
    valid, _ = validate_host_list(["  EXAMPLE.Com  "])
    assert valid == ["example.com"]


# ---------------------------------------------------------------------- #
# validate_url_list
# ---------------------------------------------------------------------- #
def test_validate_url_list_splits():
    urls = ["https://a.com", "https://b.com\ninjected"]
    valid, rejected = validate_url_list(urls)
    assert valid == ["https://a.com"]
    assert "https://b.com\ninjected" in rejected
    assert "https://b.com\ninjected" not in valid


def test_validate_url_list_empty():
    assert validate_url_list([]) == ([], [])


# ---------------------------------------------------------------------- #
# validate_severity
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("value,expected", [
    ("", True),
    ("critical,high", True),
    ("critical,bogus", False),
    ("low,medium,high,critical", True),
    ("info", True),
    ("INFORMATIONAL", True),        # case-insensitive
    ("critical,", False),           # empty token -> not in known set
    ("critical\nbogus", False),     # control char / unknown token
    ("-o", False),                  # argument-injection value
])
def test_validate_severity(value, expected):
    assert validate_severity(value) is expected


# ---------------------------------------------------------------------- #
# Per-adapter build_command tests: ALL 8 adapters
# ---------------------------------------------------------------------- #
ADAPTER_FACTORIES = {}


def _register(name):
    def deco(fn):
        ADAPTER_FACTORIES[name] = fn
        return fn
    return deco


@_register("subfinder")
def _subfinder(config):
    from cybog.adapters.subfinder import SubfinderAdapter
    return SubfinderAdapter(config.tools.subfinder)


@_register("dnsx")
def _dnsx(config):
    from cybog.adapters.dnsx import DnsxAdapter
    return DnsxAdapter(config.tools.dnsx)


@_register("httpx")
def _httpx(config):
    from cybog.adapters.httpx import HttpxAdapter
    return HttpxAdapter(config.tools.httpx)


@_register("naabu")
def _naabu(config):
    from cybog.adapters.naabu import NaabuAdapter
    return NaabuAdapter(config.tools.naabu)


@_register("katana")
def _katana(config):
    from cybog.adapters.katana import KatanaAdapter
    return KatanaAdapter(config.tools.katana)


@_register("ffuf")
def _ffuf(config):
    from cybog.adapters.ffuf import FfufAdapter
    return FfufAdapter(config.tools.ffuf)


@_register("nuclei")
def _nuclei(config):
    from cybog.adapters.nuclei import NucleiAdapter
    return NucleiAdapter(config.tools.nuclei)


@_register("auth")
def _auth(config):
    from cybog.adapters.auth_adapter import AuthAdapter
    cfg = AuthToolConfig(binary="httpx", credentials="u:p")
    return AuthAdapter(cfg)


# Each entry: (adapter_name, stage, context_for_legit, context_for_hostile, hostile_value)
# The hostile value is placed into the adapter's relevant input list so that
# build_command's validate_* call rejects it.
HOSTILE_MATRIX = [
    ("subfinder", "subfinder", {}, {"target_domain": "-o"}),
    ("dnsx", "dnsx", {"subfinder_hosts": ["example.com"]},
     {"subfinder_hosts": ["example.com\ninjected.com"]}),
    ("httpx", "httpx", {"dnsx_hosts": ["example.com"]},
     {"dnsx_hosts": ["example.com\ninjected.com"]}),
    ("naabu", "naabu", {"dnsx_hosts": ["example.com"]},
     {"dnsx_hosts": ["example.com\ninjected.com"]}),
    ("katana", "katana", {"httpx_urls": ["https://api.example.com"]},
     {"httpx_urls": ["https://api.example.com\nevil.com"]}),
    ("ffuf", "ffuf", {"httpx_urls": ["https://api.example.com"]},
     {"httpx_urls": ["https://api.example.com\nevil.com"]}),
    ("nuclei", "nuclei", {"all_urls": ["https://api.example.com"]},
     {"all_urls": ["https://api.example.com\nevil.com"]}),
    ("auth", "auth",
     {"httpx_urls": ["https://api.example.com"]},
     {"httpx_urls": ["https://api.example.com\nevil.com"]}),
]


@pytest.mark.parametrize("name,stage,legit_ctx,hostile", HOSTILE_MATRIX)
def test_build_command_rejects_hostile_input(name, stage, legit_ctx, hostile, tmp_path):
    config = _cfg()
    adapter = ADAPTER_FACTORIES[name](config)

    # Build a job whose target_domain is the hostile value where the host is
    # sourced from the job (subfinder / auth fallback path). For list-based
    # adapters, the hostile value travels in the context list.
    hostile_job_domain = hostile.get("target_domain", "example.com")
    job = _job(hostile_job_domain, stage)

    with pytest.raises(ToolAdapterError):
        adapter.build_command(job, tmp_path, hostile)


@pytest.mark.parametrize("name,stage,legit_ctx,hostile", HOSTILE_MATRIX)
def test_build_command_succeeds_on_legit(name, stage, legit_ctx, hostile, tmp_path):
    config = _cfg()
    adapter = ADAPTER_FACTORIES[name](config)
    job = _job("example.com", stage)
    cmd = adapter.build_command(job, tmp_path, legit_ctx)
    assert isinstance(cmd, list) and len(cmd) >= 1
    assert all(isinstance(part, str) for part in cmd)


# Input-file writers must reject a newline-bearing entry in the context list.
INPUT_FILE_WRITERS = ["dnsx", "httpx", "naabu", "katana", "nuclei"]
INPUT_FILE_CTX = {
    "dnsx": "subfinder_hosts",
    "httpx": "dnsx_hosts",
    "naabu": "dnsx_hosts",
    "katana": "httpx_urls",
    "nuclei": "all_urls",
}


@pytest.mark.parametrize("name", INPUT_FILE_WRITERS)
def test_input_file_writer_rejects_newline_in_context(name, tmp_path):
    config = _cfg()
    adapter = ADAPTER_FACTORIES[name](config)
    stage = name
    job = _job("example.com", stage)
    key = INPUT_FILE_CTX[name]
    context = {key: ["evil.com\ninjected.com"]}
    with pytest.raises(ToolAdapterError):
        adapter.build_command(job, tmp_path, context)
    # The input file must not have been written with the injected content.
    for written in tmp_path.iterdir():
        if written.is_file() and "input" in written.name:
            assert "injected.com" not in written.read_text(encoding="utf-8")


def test_subfinder_rejects_argument_injection_target_domain(tmp_path):
    adapter = ADAPTER_FACTORIES["subfinder"](_cfg())
    job = _job("-o", "subfinder")
    with pytest.raises(ToolAdapterError):
        adapter.build_command(job, tmp_path, {})


def test_subfinder_accepts_ordinary_domain(tmp_path):
    adapter = ADAPTER_FACTORIES["subfinder"](_cfg())
    job = _job("example.com", "subfinder")
    cmd = adapter.build_command(job, tmp_path, {})
    assert cmd[cmd.index("-d") + 1] == "example.com"


# ---------------------------------------------------------------------- #
# Sanity: subfinder still accepts an ordinary domain (over-strictness guard)
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("domain", [
    "example.com",
    "sub.example.com",
    "a.example.com.",      # trailing dot must still be accepted
    "api.example.com",
])
def test_is_valid_hostname_accepts_pipeline_realistic_values(domain):
    assert is_valid_hostname(domain) is True


def test_validate_host_list_accepts_resolved_hosts_for_target():
    # Mirror what AssessmentState.get_resolved_hosts_for_target() would produce:
    # hostnames discovered by dnsx, lowercased hostnames.
    realistic = ["api.example.com", "10.0.0.1", "2001:db8::1", "dev.example.com"]
    valid, rejected = validate_host_list(realistic)
    assert rejected == []
    assert valid == [h.lower() for h in realistic]


def test_validate_url_list_accepts_live_urls_for_target():
    realistic = ["https://api.example.com", "http://api.example.com:8080"]
    valid, rejected = validate_url_list(realistic)
    assert rejected == []
    assert valid == realistic
