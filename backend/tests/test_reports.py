"""
Tests for report file serving endpoints.

Covers:
- GET /api/v1/assessments/{id}/reports (listing)
- GET /api/v1/assessments/{id}/reports/{filename} (download)
- GET /api/v1/assessments/{id}/reports/{filename}/inline (hardened inline HTML)
- Path traversal defenses
- Symlink escape protection
- Cross-assessment isolation
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cybog.config.loader import load_config
from cybog.models.assessment import Assessment, AssessmentStatus
from cybog.models.finding import Finding, Severity, ValidationStatus
from cybog.models.job import JobStatus, StageJob
from cybog.models.target import Target, TargetStatus
from cybog.state.assessment_state import AssessmentState

from app.api import routes
from app.config import settings as backend_settings
from app.main import app as fastapi_app
from app.services.cybog_integration import CybogIntegrationService


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _write_state(
    root: Path,
    assessment_id: str,
    status: AssessmentStatus = AssessmentStatus.COMPLETED,
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
        created_at=datetime(2026, 1, 1, 12, 0, 0),
        started_at=datetime(2026, 1, 1, 12, 0, 5),
        completed_at=datetime(2026, 1, 1, 12, 30, 0),
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


def _write_reports(root: Path, assessment_id: str) -> None:
    """Write the three standard report files to the aggregate directory."""
    aggregate = root / assessment_id / "aggregate"
    aggregate.mkdir(parents=True, exist_ok=True)

    # report.json
    (aggregate / "report.json").write_text(
        json.dumps({"assessment_id": assessment_id, "summary": "test"}, indent=2),
        encoding="utf-8",
    )

    # findings.jsonl
    (aggregate / "findings.jsonl").write_text(
        '{"finding_id": "f-1", "title": "Test"}\n{"finding_id": "f-2", "title": "Test2"}\n',
        encoding="utf-8",
    )

    # report.html
    (aggregate / "report.html").write_text(
        "<!DOCTYPE html><html><body><h1>Report</h1></body></html>",
        encoding="utf-8",
    )


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


@pytest.fixture
def assessment_with_reports(output_root: Path) -> str:
    """Create an assessment with all three report files on disk."""
    aid = "assess-reports-1"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.COMPLETED,
        targets=[Target(target_id="t-1", domain="example.com", status=TargetStatus.COMPLETED)],
        jobs=[StageJob(
            assessment_id=aid, target_id="t-1", target_domain="example.com",
            stage="nuclei", status=JobStatus.COMPLETED
        )],
        findings=[Finding(
            finding_id="f-1", finding_type="misconfig", title="Test Finding",
            severity=Severity.HIGH, target_id="t-1", target_domain="example.com",
            url="https://example.com", source_tool="nuclei",
            template_id="test", description="Test",
            validation_status=ValidationStatus.VALIDATED
        )],
    )
    _write_reports(output_root, aid)
    return aid


@pytest.fixture
def assessment_without_reports(output_root: Path) -> str:
    """Create an assessment WITHOUT report files (incomplete run)."""
    aid = "assess-no-reports"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.RUNNING,
        targets=[Target(target_id="t-1", domain="example.com", status=TargetStatus.RUNNING)],
    )
    return aid


# ----------------------------------------------------------------------
# 1. Listing endpoint
# ----------------------------------------------------------------------
def test_reports_listing_returns_all_three_formats(client, assessment_with_reports):
    """GET /reports returns metadata for all three report files."""
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports")
    assert response.status_code == 200
    data = response.json()
    assert data["assessment_id"] == assessment_with_reports
    reports = data["reports"]
    assert len(reports) == 3

    by_name = {r["filename"]: r for r in reports}
    assert set(by_name.keys()) == {"report.json", "findings.jsonl", "report.html"}

    for name, r in by_name.items():
        assert r["type"] == name.split(".")[-1]
        assert r["size_bytes"] > 0
        assert r["created_at"]
        assert r["path"].endswith(f"aggregate/{name}")


def test_reports_listing_empty_when_no_aggregate_dir(client, assessment_without_reports):
    """Assessment that never reached reporting returns empty list, not 404."""
    response = client.get(f"/api/v1/assessments/{assessment_without_reports}/reports")
    assert response.status_code == 200
    data = response.json()
    assert data["assessment_id"] == assessment_without_reports
    assert data["reports"] == []


def test_reports_listing_missing_assessment_returns_404(client):
    response = client.get("/api/v1/assessments/does-not-exist/reports")
    assert response.status_code == 404


# ----------------------------------------------------------------------
# 2. Download endpoint - valid requests
# ----------------------------------------------------------------------
@pytest.mark.parametrize("filename,expected_media_type", [
    ("report.json", "application/json"),
    ("findings.jsonl", "application/jsonl"),
    ("report.html", "text/html; charset=utf-8"),
])
def test_download_report_returns_correct_bytes_and_content_type(
    client, assessment_with_reports, filename, expected_media_type
):
    """Each report downloads with correct Content-Type and exact bytes round-trip."""
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/{filename}")
    assert response.status_code == 200
    assert response.headers["content-type"] == expected_media_type
    assert f'attachment; filename="{filename}"' in response.headers.get("content-disposition", "")
    assert "Content-Length" in response.headers
    assert "ETag" in response.headers
    assert "Last-Modified" in response.headers

    # Verify exact bytes round-trip
    from pathlib import Path
    aggregate = Path(client.app.dependency_overrides[routes.get_cybog_service]().config.output.root) / assessment_with_reports / "aggregate"
    expected_content = (aggregate / filename).read_bytes()
    assert response.content == expected_content


def test_download_html_report_is_attachment_by_default(client, assessment_with_reports):
    """HTML report defaults to attachment (download), not inline."""
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/report.html")
    assert response.status_code == 200
    assert 'attachment; filename="report.html"' in response.headers.get("content-disposition", "")


# ----------------------------------------------------------------------
# 3. Inline HTML endpoint - hardened
# ----------------------------------------------------------------------
def test_inline_html_carries_csp_and_nosniff(client, assessment_with_reports):
    """Inline HTML route returns strict CSP, nosniff, and inline disposition."""
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/report.html/inline")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert 'inline; filename="report.html"' in response.headers.get("content-disposition", "")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "style-src 'unsafe-inline'" in csp
    assert "img-src data:" in csp
    assert "script-src" not in csp  # No script execution allowed


def test_inline_non_html_returns_404(client, assessment_with_reports):
    """Inline route only works for HTML files."""
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/report.json/inline")
    assert response.status_code == 404
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/findings.jsonl/inline")
    assert response.status_code == 404


# ----------------------------------------------------------------------
# 4. Missing/unknown reports
# ----------------------------------------------------------------------
def test_download_unknown_filename_returns_404(client, assessment_with_reports):
    """A well-formed filename the pipeline never emits is a missing resource.

    404 rather than 400 on purpose: it keeps the endpoint from acting as an
    oracle for which filenames are allowlisted.
    """
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/unknown.pdf")
    assert response.status_code == 404
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/report.md")
    assert response.status_code == 404  # no Markdown reporter exists
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/unknown.pdf/inline")
    assert response.status_code == 404


def test_download_missing_report_returns_404(client, assessment_without_reports):
    """Assessment that never generated reports returns 404 for any report."""
    response = client.get(f"/api/v1/assessments/{assessment_without_reports}/reports/report.json")
    assert response.status_code == 404


# ----------------------------------------------------------------------
# 5. Path traversal defenses
# ----------------------------------------------------------------------
# These filenames are already URL-encoded and are used verbatim in the request
# path: the route uses {filename:path} and the ASGI server hands the app the
# decoded path, so the literal malicious string reaches the validator.
# A bare ".." cannot be used here because HTTP clients normalise dot segments
# away before the request is sent - "%2E%2E" survives client normalisation and
# is decoded back to ".." server-side, which is what we actually want to test.
# Every one of these must be rejected with 400 - never 500, never 200.
_TRAVERSAL_TEST_CASES = [
    ("../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"),
    ("..", "%2E%2E"),
    ("../report.json", "..%2Freport.json"),
    ("report.json/../../etc/passwd", "report.json%2F..%2F..%2Fetc%2Fpasswd"),
    ("/etc/passwd", "%2Fetc%2Fpasswd"),
    ("report.json\\..\\..\\windows\\system32", "report.json%5C..%5C..%5Cwindows%5Csystem32"),
    ("a" * 129, "a" * 129),
    ("", ""),
]


@pytest.mark.parametrize("bad_filename,encoded", _TRAVERSAL_TEST_CASES)
def test_download_rejects_path_traversal(client, assessment_with_reports, bad_filename, encoded):
    """All path traversal attempts return 400, never 500 or 200."""
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/{encoded}")
    assert response.status_code == 400, f"Failed for {bad_filename!r}: got {response.status_code}, body={response.text}"
    assert response.status_code != 500


@pytest.mark.parametrize("bad_filename,encoded", _TRAVERSAL_TEST_CASES)
def test_inline_rejects_path_traversal(client, assessment_with_reports, bad_filename, encoded):
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/{encoded}/inline")
    assert response.status_code == 400, f"Failed for {bad_filename!r}: got {response.status_code}"
    assert response.status_code != 500


# ----------------------------------------------------------------------
# 6. Symlink escape protection
# ----------------------------------------------------------------------
def test_symlink_outside_aggregate_is_rejected(client, output_root, tmp_path):
    """A symlink planted in aggregate/ pointing outside is rejected."""
    aid = "assess-symlink"
    _write_state(
        output_root, aid,
        targets=[Target(target_id="t-1", domain="example.com", status=TargetStatus.COMPLETED)],
    )
    _write_reports(output_root, aid)

    # Plant a symlink: aggregate/evil.json -> /tmp/secret.txt
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    aggregate = output_root / aid / "aggregate"
    evil_link = aggregate / "evil.json"
    try:
        evil_link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this filesystem")

    # The symlink filename is not in the known allowlist, so it should 404
    # But also test with a known filename that's a symlink
    known_link = aggregate / "report.json"
    known_link.unlink()  # Remove the real file
    known_link.symlink_to(secret)

    response = client.get(f"/api/v1/assessments/{aid}/reports/report.json")
    # Should be 400 (InvalidExportRequest) because symlink target escapes
    assert response.status_code == 400
    assert response.status_code != 500
    assert response.status_code != 200


# ----------------------------------------------------------------------
# 7. Cross-assessment isolation
# ----------------------------------------------------------------------
def test_cross_assessment_isolation_enforced_by_service(output_root):
    """Direct service call with assessment_id A cannot read assessment B's files."""
    aid_a = "assess-iso-a"
    aid_b = "assess-iso-b"
    for aid in (aid_a, aid_b):
        _write_state(
            output_root, aid,
            targets=[Target(target_id=f"t-{aid}", domain=f"{aid}.com", status=TargetStatus.COMPLETED)],
        )
        _write_reports(output_root, aid)

    svc = _make_service(output_root)

    # Service method should only resolve within the given assessment's aggregate dir
    import asyncio
    path_a = asyncio.run(svc.get_assessment_report_file(aid_a, "report.json"))
    path_b = asyncio.run(svc.get_assessment_report_file(aid_b, "report.json"))

    assert path_a is not None
    assert path_b is not None
    assert aid_a in str(path_a)
    assert aid_b in str(path_b)
    assert path_a != path_b


def test_cross_assessment_filename_isolation(client, output_root):
    """Each assessment only sees its own aggregate directory."""
    aid_a = "assess-iso-a2"
    aid_b = "assess-iso-b2"
    for aid in (aid_a, aid_b):
        _write_state(
            output_root, aid,
            targets=[Target(target_id=f"t-{aid}", domain=f"{aid}.com", status=TargetStatus.COMPLETED)],
        )
        _write_reports(output_root, aid)

    # Both should succeed and return their own files
    response_a = client.get(f"/api/v1/assessments/{aid_a}/reports/report.json")
    response_b = client.get(f"/api/v1/assessments/{aid_b}/reports/report.json")
    assert response_a.status_code == 200
    assert response_b.status_code == 200

    # Listing should only show files from that assessment's aggregate dir
    list_a = client.get(f"/api/v1/assessments/{aid_a}/reports")
    list_b = client.get(f"/api/v1/assessments/{aid_b}/reports")
    assert list_a.status_code == 200
    assert list_b.status_code == 200
    assert len(list_a.json()["reports"]) == 3
    assert len(list_b.json()["reports"]) == 3


# ----------------------------------------------------------------------
# 8. Listing reflects only files that actually exist
# ----------------------------------------------------------------------
def test_listing_reflects_only_existing_files(client, output_root):
    """If only report.json exists, listing shows only report.json."""
    aid = "assess-partial"
    _write_state(
        output_root, aid,
        targets=[Target(target_id="t-1", domain="example.com", status=TargetStatus.COMPLETED)],
    )
    aggregate = output_root / aid / "aggregate"
    aggregate.mkdir(parents=True)
    (aggregate / "report.json").write_text('{"test": true}', encoding="utf-8")
    # findings.jsonl and report.html do NOT exist

    response = client.get(f"/api/v1/assessments/{aid}/reports")
    assert response.status_code == 200
    data = response.json()
    reports = data["reports"]
    assert len(reports) == 1
    assert reports[0]["filename"] == "report.json"
    assert reports[0]["type"] == "json"


# ----------------------------------------------------------------------
# 9. Conditional request headers (ETag, Last-Modified, Content-Length)
# ----------------------------------------------------------------------
def test_download_includes_conditional_headers(client, assessment_with_reports):
    response = client.get(f"/api/v1/assessments/{assessment_with_reports}/reports/report.json")
    assert response.status_code == 200
    assert "Content-Length" in response.headers
    assert "ETag" in response.headers
    assert "Last-Modified" in response.headers

    # ETag should be a quoted hash
    etag = response.headers["ETag"]
    assert etag.startswith('"') and etag.endswith('"')
    assert len(etag) == 34  # " + 32 hex chars + "

    # Last-Modified should be valid HTTP date
    last_mod = response.headers["Last-Modified"]
    assert "GMT" in last_mod


# ----------------------------------------------------------------------
# 10. Invalid assessment ID (traversal in assessment_id)
# ----------------------------------------------------------------------
def test_assessment_id_traversal_rejected(client):
    response = client.get("/api/v1/assessments/..%2F..%2Fetc/reports/report.json")
    # FastAPI path parameter validation or service should reject
    assert response.status_code in (400, 404, 422)
    assert response.status_code != 500


# ----------------------------------------------------------------------
# 11. Service layer: get_assessment_reports returns correct metadata
# ----------------------------------------------------------------------
async def test_service_get_assessment_reports_returns_metadata(output_root, assessment_with_reports):
    svc = _make_service(output_root)
    reports = await svc.get_assessment_reports(assessment_with_reports)
    assert len(reports) == 3
    for r in reports:
        assert "filename" in r
        assert "type" in r
        assert "size_bytes" in r
        assert "created_at" in r
        assert "path" in r
        assert r["size_bytes"] > 0


# ----------------------------------------------------------------------
# 12. Service layer: get_assessment_report_file returns None for missing
# ----------------------------------------------------------------------
async def test_service_get_report_file_returns_none_for_missing(output_root, assessment_without_reports):
    svc = _make_service(output_root)
    path = await svc.get_assessment_report_file(assessment_without_reports, "report.json")
    assert path is None


# ----------------------------------------------------------------------
# 13. Service layer: traversal in filename raises InvalidExportRequest
# ----------------------------------------------------------------------
async def test_service_get_report_file_rejects_traversal(output_root, assessment_with_reports):
    svc = _make_service(output_root)
    from app.services.export_service import InvalidExportRequest
    with pytest.raises(InvalidExportRequest):
        await svc.get_assessment_report_file(assessment_with_reports, "../../../etc/passwd")


# ----------------------------------------------------------------------
# 14. Service layer: symlink escape raises InvalidExportRequest
# ----------------------------------------------------------------------
async def test_service_get_report_file_rejects_symlink_escape(output_root, tmp_path):
    aid = "assess-svc-symlink"
    _write_state(
        output_root, aid,
        targets=[Target(target_id="t-1", domain="example.com", status=TargetStatus.COMPLETED)],
    )
    _write_reports(output_root, aid)

    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    aggregate = output_root / aid / "aggregate"
    real_file = aggregate / "report.json"
    real_file.unlink()
    real_file.symlink_to(secret)

    svc = _make_service(output_root)
    from app.services.export_service import InvalidExportRequest
    with pytest.raises(InvalidExportRequest):
        await svc.get_assessment_report_file(aid, "report.json")


# ----------------------------------------------------------------------
# 15. Service layer: inline method only returns HTML
# ----------------------------------------------------------------------
async def test_service_inline_only_allows_html(output_root, assessment_with_reports):
    svc = _make_service(output_root)
    path = await svc.get_assessment_report_file_inline(assessment_with_reports, "report.json")
    assert path is None
    path = await svc.get_assessment_report_file_inline(assessment_with_reports, "report.html")
    assert path is not None


# ----------------------------------------------------------------------
# 16. Service layer: traversal in assessment_id
# ----------------------------------------------------------------------
async def test_service_get_report_file_rejects_assessment_id_traversal(output_root):
    svc = _make_service(output_root)
    from app.services.export_service import InvalidExportRequest
    # The service validates assessment_id itself rather than relying on the
    # directory simply not existing - relying on that would let a crafted id
    # escape the output root as soon as a matching directory appears.
    for bad_id in ("../../../etc", "..", "..%2F..", "a/b", "x\x00y", "a" * 129):
        with pytest.raises(InvalidExportRequest):
            await svc.get_assessment_report_file(bad_id, "report.json")


# ----------------------------------------------------------------------
# 17. Service layer validation function unit tests
# ----------------------------------------------------------------------
def test_validate_report_filename_allowlist():
    """Unit test for the filename validation function."""
    from app.api.routes import _validate_report_filename
    from app.services.export_service import InvalidExportRequest

    # Valid filenames
    for valid in ["report.json", "findings.jsonl", "report.html"]:
        _validate_report_filename(valid)  # Should not raise

    # Invalid: not in known files
    with pytest.raises(InvalidExportRequest, match="Unknown report file"):
        _validate_report_filename("unknown.pdf")

    # Invalid: path traversal
    for invalid in ["../report.json", "report.json/../etc/passwd", "..", "../../../etc/passwd"]:
        with pytest.raises(InvalidExportRequest, match="Path traversal"):
            _validate_report_filename(invalid)

    # Invalid: null byte
    with pytest.raises(InvalidExportRequest, match="Path traversal"):
        _validate_report_filename("report.json\x00")

    # Invalid: too long
    with pytest.raises(InvalidExportRequest, match="Invalid report filename"):
        _validate_report_filename("a" * 129)

    # Invalid: empty
    with pytest.raises(InvalidExportRequest, match="Invalid report filename"):
        _validate_report_filename("")

