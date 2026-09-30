import pytest
from pathlib import Path
from cybog.config.models import ToolConfig, FfufToolConfig, NucleiToolConfig
from cybog.models.job import StageJob
from cybog.models.execution import ToolResult
from cybog.adapters import (
    SubfinderAdapter, DnsxAdapter, HttpxAdapter,
    NaabuAdapter, KatanaAdapter, FfufAdapter, NucleiAdapter
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"

def test_subfinder_adapter_normalization(tmp_path):
    adapter = SubfinderAdapter(ToolConfig(enabled=True, binary="subfinder"))
    job = StageJob(assessment_id="a1", target_id="t1", target_domain="example.com", stage="subfinder")
    
    # Simulate parsed output directly or via raw file
    raw_content = (FIXTURES_DIR / "subfinder_output.jsonl").read_text()
    (tmp_path / "raw.jsonl").write_text(raw_content)
    
    dummy_res = ToolResult(
        tool="subfinder", binary="subfinder", command="subfinder", exit_code=0,
        stdout="", stderr="", duration_seconds=1.0
    )
    parsed = adapter.parse_output(dummy_res, tmp_path)
    norm = adapter.normalize_output(parsed, job)

    assert len(norm.hosts) == 4
    hostnames = [h.hostname for h in norm.hosts]
    assert "api.example.com" in hostnames
    assert "dev.example.com" in hostnames
    assert "example.com" in hostnames

def test_dnsx_adapter_normalization(tmp_path):
    adapter = DnsxAdapter(ToolConfig(enabled=True, binary="dnsx"))
    job = StageJob(assessment_id="a1", target_id="t1", target_domain="example.com", stage="dnsx")
    
    raw_content = (FIXTURES_DIR / "dnsx_output.jsonl").read_text()
    (tmp_path / "raw.jsonl").write_text(raw_content)
    
    dummy_res = ToolResult(
        tool="dnsx", binary="dnsx", command="dnsx", exit_code=0,
        stdout="", stderr="", duration_seconds=1.0
    )
    parsed = adapter.parse_output(dummy_res, tmp_path)
    norm = adapter.normalize_output(parsed, job)

    assert len(norm.hosts) == 2
    assert len(norm.ips) == 2
    assert norm.hosts[0].ips == ["93.184.216.34"]

def test_httpx_adapter_normalization(tmp_path):
    adapter = HttpxAdapter(ToolConfig(enabled=True, binary="httpx"))
    job = StageJob(assessment_id="a1", target_id="t1", target_domain="example.com", stage="httpx")
    
    raw_content = (FIXTURES_DIR / "httpx_output.jsonl").read_text()
    (tmp_path / "raw.jsonl").write_text(raw_content)
    
    dummy_res = ToolResult(
        tool="httpx", binary="httpx", command="httpx", exit_code=0,
        stdout="", stderr="", duration_seconds=1.0
    )
    parsed = adapter.parse_output(dummy_res, tmp_path)
    norm = adapter.normalize_output(parsed, job)

    assert len(norm.services) == 2
    assert len(norm.urls) == 2
    assert norm.services[0].title == "API Gateway"
    assert "Nginx" in norm.services[0].technology

def test_nuclei_adapter_normalization(tmp_path):
    adapter = NucleiAdapter(NucleiToolConfig(enabled=True, binary="nuclei"))
    job = StageJob(assessment_id="a1", target_id="t1", target_domain="example.com", stage="nuclei")
    
    raw_content = (FIXTURES_DIR / "nuclei_output.jsonl").read_text()
    (tmp_path / "raw.jsonl").write_text(raw_content)
    
    dummy_res = ToolResult(
        tool="nuclei", binary="nuclei", command="nuclei", exit_code=0,
        stdout="", stderr="", duration_seconds=1.0
    )
    parsed = adapter.parse_output(dummy_res, tmp_path)
    norm = adapter.normalize_output(parsed, job)

    assert len(norm.findings) == 2
    f1 = norm.findings[0]
    assert f1.severity.value == "critical"
    assert f1.template_id == "cve-2021-44228"
    assert len(f1.evidence) > 0
