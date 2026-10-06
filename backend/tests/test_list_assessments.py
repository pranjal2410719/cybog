"""
Tests for GET /api/v1/assessments — listing persisted assessments from disk.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter

from cybog.config.loader import load_config
from cybog.models.assessment import Assessment, AssessmentStatus
from cybog.models.finding import Finding, Severity, ValidationStatus
from cybog.models.job import JobStatus, StageJob
from cybog.models.target import Target, TargetStatus
from cybog.state.assessment_state import AssessmentState

from app.api import routes
from app.config import settings as backend_settings
from app.models.api import AssessmentResponse
from app.services.cybog_integration import CybogIntegrationService

from app.main import app as fastapi_app


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _make_finding(
    finding_id: str,
    target_id: str,
    domain: str,
    validation_status: ValidationStatus = ValidationStatus.VALIDATED,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        finding_type="misconfiguration",
        title=f"Finding {finding_id}",
        severity=Severity.HIGH,
        target_id=target_id,
        target_domain=domain,
        url=f"https://{domain}/admin",
        source_tool="nuclei",
        template_id="exposed-admin",
        description="Exposed admin panel.",
        validation_status=validation_status,
    )


def _make_job(
    assessment_id: str,
    target_id: str,
    domain: str,
    stage: str,
    status: JobStatus = JobStatus.COMPLETED,
) -> StageJob:
    return StageJob(
        assessment_id=assessment_id, owner_id="test-internal-id",
        target_id=target_id,
        target_domain=domain,
        stage=stage,
        status=status,
    )


def _write_state(
    root: Path,
    assessment_id: str,
    status: AssessmentStatus = AssessmentStatus.RUNNING,
    created_at: datetime | None = None,
    targets: list[Target] | None = None,
    jobs: list[StageJob] | None = None,
    findings: list[Finding] | None = None,
) -> AssessmentState:
    """Create and persist an AssessmentState at <root>/<assessment_id>/state.json."""
    assessment = Assessment(
        assessment_id=assessment_id, owner_id="test-internal-id",
        profile="standard",
        target_input_file="targets.txt",
        scope_file="authorized_scope.txt",
        status=status,
        created_at=created_at or datetime(2026, 1, 1, 12, 0, 0),
        started_at=datetime(2026, 1, 1, 12, 0, 5),
        artifact_root=str(root / assessment_id),
        config_snapshot={},
    )
    state = AssessmentState.create_new(assessment)
    for target in targets or []:
        state.add_target(target)
    for job in jobs or []:
        state.add_job(job)
    for finding in findings or []:
        state.add_finding(finding)
    state.save(root / assessment_id / "state.json")
    return state


def _make_service(output_root: Path) -> CybogIntegrationService:
    config = load_config(backend_settings.CYBOG_CONFIG_PATH)
    config.output.root = str(output_root)
    return CybogIntegrationService(config)


@pytest.fixture
def output_root(tmp_path: Path) -> Path:
    root = tmp_path / "artifacts"
    root.mkdir()
    return root


@pytest.fixture
def client(output_root: Path):
    svc = _make_service(output_root)
    fastapi_app.dependency_overrides[routes.get_cybog_service] = lambda: svc
    try:
        yield TestClient(fastapi_app)
    finally:
        fastapi_app.dependency_overrides.pop(routes.get_cybog_service, None)


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------
def test_list_returns_persisted_assessments_newest_first(
    client: TestClient, output_root: Path
):
    """Two real assessments on disk are returned, sorted newest-first."""
    # Assessment A — older
    a_targets = [
        Target(target_id="t-a-1", domain="a.example.com", status=TargetStatus.COMPLETED),
        Target(target_id="t-a-2", domain="a2.example.com", status=TargetStatus.IN_SCOPE),
    ]
    a_jobs = [
        _make_job("assess-a", "t-a-1", "a.example.com", "nuclei", JobStatus.COMPLETED),
        _make_job("assess-a", "t-a-1", "a.example.com", "katana", JobStatus.SKIPPED),
        _make_job("assess-a", "t-a-2", "a2.example.com", "nuclei", JobStatus.FAILED),
        _make_job("assess-a", "t-a-2", "a2.example.com", "katana", JobStatus.COMPLETED),
    ]
    a_findings = [
        _make_finding("f-a-1", "t-a-1", "a.example.com", ValidationStatus.REPORTABLE),
        _make_finding("f-a-2", "t-a-1", "a.example.com", ValidationStatus.NEEDS_VALIDATION),
    ]
    _write_state(
        output_root,
        "assess-a",
        status=AssessmentStatus.AWAITING_VALIDATION,
        created_at=datetime(2026, 1, 1, 12, 0, 0),
        targets=a_targets,
        jobs=a_jobs,
        findings=a_findings,
    )

    # Assessment B — newer
    b_targets = [
        Target(target_id="t-b-1", domain="b.example.com", status=TargetStatus.COMPLETED),
    ]
    b_jobs = [
        _make_job("assess-b", "t-b-1", "b.example.com", "nuclei", JobStatus.COMPLETED),
        _make_job("assess-b", "t-b-1", "b.example.com", "katana", JobStatus.COMPLETED),
    ]
    b_findings = [
        _make_finding("f-b-1", "t-b-1", "b.example.com", ValidationStatus.REPORTABLE),
    ]
    _write_state(
        output_root,
        "assess-b",
        status=AssessmentStatus.COMPLETED,
        created_at=datetime(2026, 6, 1, 9, 0, 0),
        targets=b_targets,
        jobs=b_jobs,
        findings=b_findings,
    )

    response = client.get("/api/v1/assessments")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2

    # Newest first
    assert data[0]["assessment_id"] == "assess-b"
    assert data[1]["assessment_id"] == "assess-a"

    # Correct ids, statuses, and counts
    b = data[0]
    assert b["status"] == "COMPLETED"
    assert b["findings_count"] == 1
    assert b["pending_validation_count"] == 0
    assert b["progress"]["total_targets"] == 1
    assert b["progress"]["completed_targets"] == 1
    assert b["progress"]["total_jobs"] == 2
    assert b["progress"]["completed_jobs"] == 2
    assert b["progress"]["failed_jobs"] == 0
    assert b["progress"]["completion_percentage"] == 100.0

    a = data[1]
    assert a["status"] == "AWAITING_VALIDATION"
    assert a["findings_count"] == 2
    assert a["pending_validation_count"] == 1
    assert a["progress"]["total_targets"] == 2
    assert a["progress"]["completed_targets"] == 1
    assert a["progress"]["total_jobs"] == 4
    assert a["progress"]["completed_jobs"] == 3  # 2 COMPLETED + 1 SKIPPED
    assert a["progress"]["failed_jobs"] == 1
    assert a["progress"]["completion_percentage"] == 75.0

    # name falls back to assessment_id (Assessment model has no name field)
    assert a["name"] == "assess-a"
    assert b["name"] == "assess-b"


def test_list_excludes_directories_without_state_json(
    client: TestClient, output_root: Path
):
    """A directory without state.json (e.g. temp_uploads/) is silently excluded."""
    # A non-assessment directory
    temp_uploads = output_root / "temp_uploads"
    temp_uploads.mkdir()
    (temp_uploads / "junk.txt").write_text("not an assessment", encoding="utf-8")

    # A real assessment
    _write_state(
        output_root,
        "real-assessment",
        created_at=datetime(2026, 3, 1, 10, 0, 0),
        targets=[Target(target_id="t-1", domain="example.com", status=TargetStatus.IN_SCOPE)],
    )

    response = client.get("/api/v1/assessments")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["assessment_id"] == "real-assessment"

    # Also exclude the exports directory
    exports = output_root / "exports"
    exports.mkdir()
    (exports / "status.json").write_text("{}", encoding="utf-8")

    response = client.get("/api/v1/assessments")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["assessment_id"] == "real-assessment"


def test_list_skips_corrupt_state_and_returns_others(
    client: TestClient, output_root: Path
):
    """A corrupt state.json is skipped; other assessments still return (no 500)."""
    # Valid assessment
    _write_state(
        output_root,
        "good-1",
        created_at=datetime(2026, 2, 1, 10, 0, 0),
        targets=[Target(target_id="t-1", domain="good.com", status=TargetStatus.COMPLETED)],
    )

    # Corrupt state.json (partially written / invalid JSON)
    corrupt_dir = output_root / "corrupt-assessment"
    corrupt_dir.mkdir()
    (corrupt_dir / "state.json").write_text("{not valid json", encoding="utf-8")

    # Another valid assessment
    _write_state(
        output_root,
        "good-2",
        created_at=datetime(2026, 2, 2, 10, 0, 0),
        targets=[Target(target_id="t-2", domain="good2.com", status=TargetStatus.COMPLETED)],
    )

    response = client.get("/api/v1/assessments")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    ids = {d["assessment_id"] for d in data}
    assert ids == {"good-1", "good-2"}
    assert "corrupt-assessment" not in ids


def test_list_missing_output_root_returns_empty(tmp_path: Path):
    """A missing output.root returns [] rather than raising."""
    svc = _make_service(tmp_path / "does-not-exist")
    fastapi_app.dependency_overrides[routes.get_cybog_service] = lambda: svc
    try:
        response = TestClient(fastapi_app).get("/api/v1/assessments")
        assert response.status_code == 200
        assert response.json() == []
    finally:
        fastapi_app.dependency_overrides.pop(routes.get_cybog_service, None)


def test_list_response_validates_against_assessment_response(
    client: TestClient, output_root: Path
):
    """Every returned entry conforms to the AssessmentResponse model."""
    _write_state(
        output_root,
        "valid-1",
        status=AssessmentStatus.COMPLETED,
        created_at=datetime(2026, 4, 1, 8, 0, 0),
        targets=[
            Target(target_id="t-1", domain="a.test", status=TargetStatus.COMPLETED),
            Target(target_id="t-2", domain="b.test", status=TargetStatus.FAILED),
        ],
        jobs=[
            _make_job("valid-1", "t-1", "a.test", "nuclei", JobStatus.COMPLETED),
            _make_job("valid-1", "t-2", "b.test", "nuclei", JobStatus.FAILED),
        ],
        findings=[
            Finding(
                finding_id="f-1",
                finding_type="misconfiguration",
                title="Issue",
                severity=Severity.CRITICAL,
                target_id="t-1",
                target_domain="a.test",
                url="https://a.test/x",
                source_tool="nuclei",
                template_id="tmpl",
                description="desc",
                validation_status=ValidationStatus.REPORTABLE,
            ),
        ],
    )

    response = client.get("/api/v1/assessments")
    assert response.status_code == 200

    adapter = TypeAdapter(list[AssessmentResponse])
    validated = adapter.validate_python(response.json())
    assert len(validated) == 1
    item = validated[0]
    assert item.assessment_id == "valid-1"
    assert item.status == "COMPLETED"
    assert item.findings_count == 1
    assert item.progress["total_targets"] == 2
    assert item.progress["completed_targets"] == 1
    assert item.progress["completed_jobs"] == 1
    assert item.progress["failed_jobs"] == 1
    assert item.progress["completion_percentage"] == 50.0


def test_list_empty_when_no_assessments(client: TestClient, output_root: Path):
    """An existing but empty output root returns an empty list."""
    response = client.get("/api/v1/assessments")
    assert response.status_code == 200
    assert response.json() == []
