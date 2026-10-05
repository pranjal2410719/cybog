"""
Tests for binary resolution (A1/A2/A3) and the strengthened healthcheck.
"""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from cybog.adapters.base import ToolAdapter, HealthCheckResult
from cybog.config.models import ToolConfig, ToolsConfig, CybogConfig
from cybog.adapters.httpx import HttpxAdapter


class _StubAdapter(ToolAdapter):
    def __init__(self, cfg):
        self.config = cfg
        self.binary = cfg.resolve_binary()

    def metadata(self):
        return {"name": "stub"}

    def health_check(self):
        return self._check_binary(self.binary)

    def validate_input(self, job, context):
        from cybog.adapters.base import ValidationResult
        return ValidationResult(valid=True, reason="ok")

    def build_command(self, job, stage_dir, context):
        return [self.binary]

    def parse_output(self, tool_result, stage_dir):
        return []

    def normalize_output(self, parsed, job):
        from cybog.adapters.base import NormalizedOutput
        return NormalizedOutput()


def test_resolve_binary_prefers_bin_dirs(tmp_path: Path):
    fake_bin = tmp_path / "httpx"
    fake_bin.write_bytes(b"\x7fELF" + b"\x00" * 100)
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)

    cfg = ToolConfig(binary="httpx", bin_dirs=[str(tmp_path)])
    assert cfg.resolve_binary() == str(fake_bin)


def test_resolve_binary_falls_back_to_shutil_which():
    cfg = ToolConfig(binary="cat", bin_dirs=[])
    assert cfg.resolve_binary() == os.path.realpath("/bin/cat") or cfg.resolve_binary().endswith("/cat")


def test_resolve_binary_path_separator_used_as_is():
    cfg = ToolConfig(binary="/usr/bin/true", bin_dirs=[])
    assert cfg.resolve_binary() == "/usr/bin/true"


def test_resolve_binary_returns_original_when_not_found():
    cfg = ToolConfig(binary="nonexistent_tool_xyz", bin_dirs=[])
    assert cfg.resolve_binary() == "nonexistent_tool_xyz"


def test_bin_dirs_propagated_to_children():
    cfg = ToolsConfig(bin_dirs=["~/go/bin"])
    assert cfg.subfinder.bin_dirs == ["~/go/bin"]
    assert cfg.httpx.bin_dirs == ["~/go/bin"]
    assert cfg.auth.bin_dirs == ["~/go/bin"]


def test_looks_like_compiled_binary_rejects_shebang(tmp_path: Path):
    script = tmp_path / "script.py"
    script.write_text("#!/usr/bin/env python3\nprint(1)\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    assert ToolAdapter.looks_like_compiled_binary(str(script)) is False


def test_looks_like_compiled_binary_accepts_elf(tmp_path: Path):
    elf = tmp_path / "fake.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 100)
    elf.chmod(elf.stat().st_mode | stat.S_IEXEC)
    assert ToolAdapter.looks_like_compiled_binary(str(elf)) is True


def test_healthcheck_rejects_shadowed_script(monkeypatch, tmp_path: Path):
    shadow = tmp_path / "httpx"
    shadow.write_text("#!/bin/sh\necho 'Usage: httpx [OPTIONS] URL'\n")
    shadow.chmod(shadow.stat().st_mode | stat.S_IEXEC)

    cfg = ToolConfig(binary="httpx", bin_dirs=[str(tmp_path)])
    adapter = _StubAdapter(cfg)
    hc = adapter.health_check()
    assert hc.available is False
    assert "script" in hc.error.lower() or "python" in hc.error.lower() or "click" in hc.error.lower() or "not a compiled" in hc.error.lower()


def test_healthcheck_reports_resolved_path(tmp_path: Path):
    elf = tmp_path / "httpx"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 100)
    elf.chmod(elf.stat().st_mode | stat.S_IEXEC)

    cfg = ToolConfig(binary="httpx", bin_dirs=[str(tmp_path)])
    adapter = _StubAdapter(cfg)
    hc = adapter.health_check()
    assert hc.available is True
    assert hc.error is None
