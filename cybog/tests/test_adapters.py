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


def test_katana_command_has_exactly_one_depth_flag(tmp_path):
    adapter = KatanaAdapter(ToolConfig(
        enabled=True, binary="katana",
        extra_args=["-ct", "60s"],
    ))
    job = StageJob(assessment_id="a1", target_id="t1", target_domain="example.com", stage="katana")
    cmd = adapter.build_command(job, tmp_path, {"httpx_urls": ["https://example.com"]})
    depth_occurs = sum(1 for i, v in enumerate(cmd) if v == "-d")
    assert depth_occurs == 0, f"katana command should have zero hardcoded -d flags, got: {cmd}"


def test_ffuf_build_commands_fans_out_per_url(tmp_path):
    adapter = FfufAdapter(FfufToolConfig(
        enabled=True, binary="ffuf",
        wordlist=str(tmp_path / "w.txt"),
        max_targets=5,
    ))
    (tmp_path / "w.txt").write_text("admin\napi\nlogin\n")
    job = StageJob(assessment_id="a1", target_id="t1", target_domain="example.com", stage="ffuf")
    urls = ["https://a.example.com", "https://b.example.com", "https://c.example.com"]
    cmds = adapter.build_commands(job, tmp_path, {"httpx_urls": urls})
    assert len(cmds) == 3
    for idx, cmd in enumerate(cmds):
        assert "-u" in cmd
        assert any("FUZZ" in v for v in cmd)
        assert any(str(tmp_path / f"raw.{idx}.json") == v for v in cmd)


def test_ffuf_parse_output_merges_indexed_files(tmp_path):
    adapter = FfufAdapter(FfufToolConfig(
        enabled=True, binary="ffuf",
        wordlist=str(tmp_path / "w.txt"),
    ))
    (tmp_path / "w.txt").write_text("admin\n")
    (tmp_path / "raw.0.json").write_text('{"results": [{"url": "https://a.example.com/admin", "status": 200, "input": {"FUZZ": "admin"}}]}')
    (tmp_path / "raw.1.json").write_text('{"results": [{"url": "https://b.example.com/login", "status": 403, "input": {"FUZZ": "login"}}]}')
    dummy_res = ToolResult(tool="ffuf", binary="ffuf", command="ffuf", exit_code=0, stdout="", stderr="", duration_seconds=1.0)
    parsed = adapter.parse_output(dummy_res, tmp_path)
    assert len(parsed) == 2
    assert parsed[0]["url"] == "https://a.example.com/admin"
