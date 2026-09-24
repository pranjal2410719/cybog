import pytest
from cybog.models.target import Target, TargetStatus, Host, IP, Service, Port, URL, Endpoint
from cybog.models.finding import Finding, Severity, ValidationStatus, Evidence
from cybog.models.job import StageJob, JobStatus
from cybog.models.assessment import Assessment, Authorization, Scope, AssessmentStatus

def test_target_creation():
    t = Target(domain="example.com")
    assert t.domain == "example.com"
    assert t.status == TargetStatus.PENDING
    assert t.target_id.startswith("target-")

def test_finding_dedup_key():
    f1 = Finding(
        finding_type="sqli",
        title="SQL Injection",
        severity=Severity.HIGH,
        target_id="t1",
        target_domain="example.com",
        url="https://example.com/api?id=1",
        source_tool="nuclei",
    )
    f2 = Finding(
        finding_type="sqli",
        title="SQL Injection",
        severity=Severity.HIGH,
        target_id="t1",
        target_domain="example.com",
        url="https://example.com/api?id=1",
        source_tool="nuclei",
    )
    assert f1.dedup_key == f2.dedup_key
    assert len(f1.dedup_key) == 32

def test_job_status():
    j = StageJob(
        assessment_id="a1",
        target_id="t1",
        target_domain="example.com",
        stage="subfinder"
    )
    assert j.status == JobStatus.PENDING
    assert j.attempt == 1
