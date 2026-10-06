"""
Tests for the assessment ZIP export service.

No real scanners are invoked: a fake assessment artifact tree is written to
``tmp_path`` using the real cybog models and state container.
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cybog.models.assessment import Assessment, AssessmentStatus
from cybog.models.finding import Evidence, Finding, Severity, ValidationStatus
from cybog.models.job import JobStatus, StageJob
from cybog.models.target import Target, TargetStatus
from cybog.state.assessment_state import AssessmentState

from app.services.export_service import (
    EXPORT_MANIFEST_ARC,
    MANIFEST_FILES,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING,
    ExportService,
    InvalidExportRequest,
    sanitize_component,
)


# ----------------------------------------------------------------------
# Fixtures: build a fake assessment on disk
# ----------------------------------------------------------------------
def _write_state(root: Path, assessment_id: str) -> AssessmentState:
    """Create ``<root>/<assessment_id>/state.json`` with two targets."""
    assessment = Assessment(
        assessment_id=assessment_id,
        profile="standard",
        target_input_file="targets.txt",
        scope_file="authorized_scope.txt",
        status=AssessmentStatus.COMPLETED,
        created_at=datetime(2026, 1, 1, 12, 0, 0),
        started_at=datetime(2026, 1, 1, 12, 0, 5),
        completed_at=datetime(2026, 1, 1, 12, 30, 0),
        artifact_root=str(root / assessment_id),
        config_snapshot={"workers": {"max_workers": 4}},
    )
    state = AssessmentState.create_new(assessment)

    t1 = Target(target_id="target-aaa", domain="example.com", status=TargetStatus.COMPLETED)
    t2 = Target(target_id="target-bbb", domain="evil.test", status=TargetStatus.IN_SCOPE)
    state.add_target(t1)
    state.add_target(t2)

    validated = Finding(
        finding_id="find0001",
        finding_type="misconfiguration",
        title="Exposed admin panel",
        severity=Severity.HIGH,
        target_id=t1.target_id,
        target_domain=t1.domain,
        url="https://example.com/admin",
        source_tool="nuclei",
        template_id="exposed-admin",
        description="Admin panel reachable without auth.",
        validation_status=ValidationStatus.VALIDATED,
        evidence=[
            Evidence(
                evidence_id="ev-0001",
                finding_id="find0001",
                tool="nuclei",
                raw_output="matched: exposed-admin",
            )
        ],
    )
    discovered = Finding(
        finding_id="find0002",
        finding_type="technology",
        title="Nginx detected",
        severity=Severity.INFO,
        target_id=t1.target_id,
        target_domain=t1.domain,
        url="https://example.com",
        source_tool="httpx",
        validation_status=ValidationStatus.DISCOVERED,
        evidence=[
            Evidence(
                evidence_id="ev-0002",
                finding_id="find0002",
                tool="httpx",
                raw_output="nginx",
            )
        ],
    )
    false_positive = Finding(
        finding_id="find0003",
        finding_type="open_port",
        title="Port 22 open",
        severity=Severity.LOW,
        target_id=t2.target_id,
        target_domain=t2.domain,
        url="evil.test:22",
        source_tool="naabu",
        validation_status=ValidationStatus.FALSE_POSITIVE,
    )
    reportable = Finding(
        finding_id="find0004",
        finding_type="exposure",
        title="Directory listing",
        severity=Severity.MEDIUM,
        target_id=t2.target_id,
        target_domain=t2.domain,
        url="https://evil.test/backup/",
        source_tool="nuclei",
        validation_status=ValidationStatus.REPORTABLE,
        evidence=[
            Evidence(
                evidence_id="ev-0003",
                finding_id="find0004",
                tool="nuclei",
                raw_output="dir listing",
            )
        ],
    )
    for finding in (validated, discovered, false_positive, reportable):
        state.add_finding(finding)

    for target in (t1, t2):
        for stage in ("subfinder", "httpx", "nuclei"):
            state.add_job(
                StageJob(
                    assessment_id=assessment_id,
                    target_id=target.target_id,
                    target_domain=target.domain,
                    stage=stage,
                    status=JobStatus.COMPLETED,
                )
            )
        state.add_job(
            StageJob(
                assessment_id=assessment_id,
                target_id=target.target_id,
                target_domain=target.domain,
                stage="katana",
                status=JobStatus.FAILED,
            )
        )

    state.save(root / assessment_id / "state.json")
    return state


def _write_artifacts(root: Path, assessment_id: str, targets) -> None:
    """Write the per-target stage artifacts and the aggregate report."""
    assessment_dir = root / assessment_id

    stages = {
        "subfinder": ("jsonl", '{"host":"example.com"}\n'),
        "httpx": ("jsonl", '{"url":"https://example.com","status_code":200}\n'),
        "nuclei": ("json", '{"template-id":"exposed-admin"}'),
        "katana": ("jsonl", '{"url":"https://example.com/admin"}\n'),
    }
    for target in targets:
        target_dir = assessment_dir / "targets" / target.target_id
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "metadata.json").write_text(
            json.dumps({"domain": target.domain}), encoding="utf-8"
        )
        for stage, (ext, content) in stages.items():
            attempt = target_dir / stage / "attempt_2"
            attempt.mkdir(parents=True, exist_ok=True)
            (attempt / f"raw.{ext}").write_text(content, encoding="utf-8")
            (attempt / "stdout.log").write_text(f"{stage} stdout\n", encoding="utf-8")
            (attempt / "stderr.log").write_text("", encoding="utf-8")
            (attempt / "normalized.json").write_text(
                json.dumps({"stage": stage, "results": 1}), encoding="utf-8"
            )
            (attempt / "execution.json").write_text(
                json.dumps({"success": True, "stage": stage}), encoding="utf-8"
            )
            # An older attempt that must NOT win over attempt_2.
            stale = target_dir / stage / "attempt_1"
            stale.mkdir(parents=True, exist_ok=True)
            (stale / f"raw.{ext}").write_text("STALE\n", encoding="utf-8")

    aggregate = assessment_dir / "aggregate"
    aggregate.mkdir(parents=True, exist_ok=True)
    (aggregate / "report.html").write_text("<html>report</html>", encoding="utf-8")
    (aggregate / "summary.json").write_text(json.dumps({"ok": True}), encoding="utf-8")


@pytest.fixture
def output_root(tmp_path: Path) -> Path:
    root = tmp_path / "artifacts"
    root.mkdir()
    return root


@pytest.fixture
def assessment_id() -> str:
    return "assessment-20260101-000000-deadbeef"


@pytest.fixture
def fake_assessment(output_root: Path, assessment_id: str) -> AssessmentState:
    state = _write_state(output_root, assessment_id)
    _write_artifacts(output_root, assessment_id, list(state.targets.values()))
    return state


@pytest.fixture
def service(output_root: Path) -> ExportService:
    return ExportService(output_root)


async def _export_and_wait(service: ExportService, assessment_id: str, **kwargs) -> dict:
    created = await service.create_export(assessment_id, **kwargs)
    final = await service.wait_for_completion(created["export_id"], timeout=30.0)
    assert final is not None
    return final


# ----------------------------------------------------------------------
# Happy path
# ----------------------------------------------------------------------
async def test_export_completes_and_archive_layout_is_correct(
    service: ExportService, fake_assessment: AssessmentState, assessment_id: str
):
    final = await _export_and_wait(service, assessment_id)

    assert final["status"] == "completed", final.get("error")
    assert final["error"] is None
    assert final["file_size_bytes"] > 0

    archive = service.get_export_path(final["export_id"])
    assert archive is not None and archive.is_file()

    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
        bad = zf.testzip()
        assert bad is None, f"corrupt entry: {bad}"

        # Per-target directories named by domain.
        assert "example.com/report/report.html" in names
        assert "example.com/report/findings.json" in names
        assert "evil.test/report/report.html" in names

        # Findings / evidence, raw stage output and metadata.
        assert "example.com/findings/finding-find0001.json" in names
        assert "example.com/findings/finding-find0002.json" in names
        assert "evil.test/findings/finding-find0004.json" in names
        assert "example.com/evidence/nuclei-find0001.json" in names
        assert "example.com/evidence/httpx-find0002.json" in names
        assert "example.com/recon/subfinder-raw.jsonl" in names
        assert "example.com/discovery/httpx-raw.jsonl" in names
        assert "example.com/crawl/katana-raw.jsonl" in names
        assert "example.com/scanning/nuclei-raw.json" in names
        assert "example.com/artifacts/metadata.json" in names
        assert "example.com/artifacts/nuclei/execution.json" in names
        assert "example.com/artifacts/nuclei/stdout.log" in names

        # Highest attempt wins: attempt_2 content, never "STALE".
        raw = zf.read("example.com/recon/subfinder-raw.jsonl").decode()
        assert "STALE" not in raw
        assert "example.com" in raw

        # All four manifests present.
        for manifest in MANIFEST_FILES:
            assert manifest in names, f"missing {manifest}"

        manifests = {m: json.loads(zf.read(m)) for m in MANIFEST_FILES}
        namelist = zf.namelist()

    # assessment.json
    am = manifests["_manifest/assessment.json"]
    for key in (
        "assessment_id", "profile", "status", "status_message", "created_at",
        "started_at", "completed_at", "total_targets", "completed_targets",
        "total_findings", "validated_findings", "false_positive_findings",
        "pending_validation_findings", "artifact_root", "config_snapshot",
        "exported_at", "export_version",
    ):
        assert key in am, f"assessment.json missing {key}"
    assert am["assessment_id"] == assessment_id
    assert am["total_targets"] == 2
    assert am["total_findings"] == 4
    assert am["validated_findings"] == 2
    assert am["false_positive_findings"] == 1
    assert am["export_version"] == "1.0"

    # targets.json
    tm = manifests["_manifest/targets.json"]
    for key in ("assessment_id", "targets_file", "targets", "in_scope", "out_of_scope"):
        assert key in tm, f"targets.json missing {key}"
    assert {t["target_id"] for t in tm["targets"]} == {"target-aaa", "target-bbb"}
    assert {t["domain"] for t in tm["in_scope"]} == {"example.com", "evil.test"}

    # execution-summary.json
    es = manifests["_manifest/execution-summary.json"]
    for key in (
        "assessment_id", "total_jobs", "completed_jobs", "failed_jobs",
        "skipped_jobs", "total_findings", "findings_by_severity",
        "findings_by_validation_status", "per_target_summary", "export_summary",
    ):
        assert key in es, f"execution-summary.json missing {key}"
    assert es["total_jobs"] == 8
    assert es["completed_jobs"] == 6
    assert es["failed_jobs"] == 2
    assert len(es["per_target_summary"]) == 2
    entry = next(t for t in es["per_target_summary"] if t["target_id"] == "target-aaa")
    assert entry["domain"] == "example.com"
    assert entry["jobs_total"] == 4
    assert entry["findings_count"] == 2

    # export-manifest.json
    xm = manifests[EXPORT_MANIFEST_ARC]
    for key in (
        "export_id", "assessment_id", "format", "total_size_bytes",
        "total_files", "target_count", "created_at", "expires_at", "file_list",
    ):
        assert key in xm, f"export-manifest.json missing {key}"
    assert xm["export_id"] == final["export_id"]
    assert xm["format"] == "zip"
    assert xm["target_count"] == 2
    assert xm["total_size_bytes"] > 0
    # The recorded size is the real, final archive size.
    assert xm["total_size_bytes"] == archive.stat().st_size
    # file_list is every arcname in the zip, in write order.
    assert xm["file_list"] == namelist
    assert EXPORT_MANIFEST_ARC in names


async def test_report_findings_json_only_lists_that_targets_findings(
    service: ExportService, fake_assessment: AssessmentState, assessment_id: str
):
    final = await _export_and_wait(service, assessment_id)
    archive = service.get_export_path(final["export_id"])
    with zipfile.ZipFile(archive) as zf:
        findings = json.loads(zf.read("example.com/report/findings.json"))
        ids = {f["finding_id"] for f in findings}
    assert ids == {"find0001", "find0002"}


# ----------------------------------------------------------------------
# include_validated_only
# ----------------------------------------------------------------------
async def test_include_validated_only_excludes_unvalidated_findings(
    service: ExportService, fake_assessment: AssessmentState, assessment_id: str
):
    final = await _export_and_wait(service, assessment_id, include_validated_only=True)
    assert final["status"] == "completed", final.get("error")
    archive = service.get_export_path(final["export_id"])

    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
        # VALIDATED (find0001) and REPORTABLE (find0004) survive.
        assert "example.com/findings/finding-find0001.json" in names
        assert "evil.test/findings/finding-find0004.json" in names
        # DISCOVERED (find0002) and FALSE_POSITIVE (find0003) do not.
        assert "example.com/findings/finding-find0002.json" not in names
        assert "evil.test/findings/finding-find0003.json" not in names
        # Evidence of excluded findings is dropped too.
        assert "example.com/evidence/httpx-find0002.json" not in names

        es = json.loads(zf.read("_manifest/execution-summary.json"))
        am = json.loads(zf.read("_manifest/assessment.json"))
        per_target = json.loads(zf.read("example.com/report/findings.json"))

    assert es["total_findings"] == 2
    assert am["total_findings"] == 2
    assert len(per_target) == 1
    assert per_target[0]["finding_id"] == "find0001"


async def test_include_raw_false_drops_raw_output(
    service: ExportService, fake_assessment: AssessmentState, assessment_id: str
):
    final = await _export_and_wait(service, assessment_id, include_raw=False)
    assert final["status"] == "completed", final.get("error")
    with zipfile.ZipFile(service.get_export_path(final["export_id"])) as zf:
        names = set(zf.namelist())
    assert not [n for n in names if "-raw." in n]
    # Sidecars still present so execution history is inspectable.
    assert "example.com/artifacts/nuclei/execution.json" in names


# ----------------------------------------------------------------------
# Security: path traversal
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_id",
    ["../../etc", "..", ".", "../foo", "a/b", "a\\b", "with\x00nul", "sp ace", "", "x" * 129],
)
def test_assessment_id_traversal_is_refused(service: ExportService, bad_id: str):
    with pytest.raises(InvalidExportRequest):
        service.assessment_dir(bad_id)


@pytest.mark.parametrize(
    "bad_id",
    ["../foo", "../../etc", "..", ".", "a/b", "nul\x00", "sp ace", "x" * 200],
)
def test_export_id_traversal_is_refused(service: ExportService, bad_id: str):
    with pytest.raises(InvalidExportRequest):
        service.export_dir(bad_id)


def test_traversal_does_not_escape_output_root(service: ExportService, output_root: Path):
    with pytest.raises(InvalidExportRequest):
        service._resolve_within(output_root, "..", "..", "etc")
    with pytest.raises(InvalidExportRequest):
        service._resolve_within(output_root, "../../etc/passwd")


async def test_create_export_rejects_traversal_assessment_id(
    service: ExportService, fake_assessment: AssessmentState
):
    with pytest.raises(InvalidExportRequest):
        await service.create_export("../../etc")


def test_sanitize_component_strips_separators_and_dots():
    assert "/" not in sanitize_component("../../etc/passwd")
    assert ".." not in sanitize_component("../../etc/passwd")
    assert sanitize_component("a\x00b") == "a-b"
    assert sanitize_component("") == "unnamed"
    assert sanitize_component("..") == "unnamed"


def test_symlink_out_of_tree_is_not_followed(
    service: ExportService,
    output_root: Path,
    fake_assessment: AssessmentState,
    assessment_id: str,
    tmp_path: Path,
):
    """A symlink planted in the artifact tree must not be packaged."""
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    target_dir = output_root / assessment_id / "targets" / "target-aaa"
    link = target_dir / "metadata_link.json"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported on this filesystem")

    export_id = "symlink-test"
    service.export_dir(export_id).mkdir(parents=True, exist_ok=True)
    result = service.build_archive(
        export_id,
        assessment_id,
        "zip",
        {"include_raw": True, "include_evidence": True, "include_validated_only": False},
    )
    with zipfile.ZipFile(result["archive_path"]) as zf:
        contents = b"".join(zf.read(n) for n in zf.namelist())
    assert b"TOP SECRET" not in contents


def test_colliding_domains_are_disambiguated(output_root: Path, tmp_path: Path):
    """Two domains that sanitise to the same directory name get unique dirs."""
    from app.services.export_service import AssessmentState as _S  # noqa: F401

    assessment = Assessment(
        assessment_id="collide",
        target_input_file="t.txt",
        scope_file="s.txt",
        status=AssessmentStatus.COMPLETED,
    )
    state = AssessmentState.create_new(assessment)
    state.add_target(Target(target_id="t-one", domain="a/b.com"))
    state.add_target(Target(target_id="t-two", domain="a\\b.com"))
    state.save(output_root / "collide" / "state.json")

    service = ExportService(output_root)
    result = service.build_archive("collide-export", "collide", "zip", {})
    with zipfile.ZipFile(result["archive_path"]) as zf:
        dirs = {n.split("/", 1)[0] for n in zf.namelist() if "/" in n}
    dirs.discard("_manifest")
    assert len(dirs) == 2, dirs


# ----------------------------------------------------------------------
# Status lookup
# ----------------------------------------------------------------------
def test_get_status_unknown_export_returns_none(service: ExportService):
    assert service.get_status("does-not-exist") is None
    assert service.get_status("11111111-2222-3333-4444-555555555555") is None
    assert service.get_export_path("does-not-exist") is None


async def test_status_is_persisted_and_visible_to_a_new_instance(
    output_root: Path, fake_assessment: AssessmentState, assessment_id: str
):
    """A separate ExportService instance must see the persisted status."""
    created = await ExportService(output_root).create_export(assessment_id)
    assert created["status"] in ("pending", "in_progress")

    other = ExportService(output_root)
    seen = other.get_status(created["export_id"])
    assert seen is not None and seen["assessment_id"] == assessment_id

    await ExportService(output_root).wait_for_completion(created["export_id"], timeout=30.0)
    final = other.get_status(created["export_id"])
    assert final["status"] == "completed"
    assert other.get_export_path(created["export_id"]).is_file()


async def test_get_export_path_none_until_completed(
    output_root: Path, fake_assessment: AssessmentState, assessment_id: str
):
    service = ExportService(output_root)
    created = await service.create_export(assessment_id)
    await service.wait_for_completion(created["export_id"], timeout=30.0)
    assert service.get_export_path(created["export_id"]) is not None

    status = service.get_status(created["export_id"])
    status["status"] = "in_progress"
    service._write_status(created["export_id"], status)
    assert service.get_export_path(created["export_id"]) is None


def test_cleanup_expired_removes_old_exports(service: ExportService, output_root: Path):
    fresh = service.export_dir("fresh-export")
    fresh.mkdir(parents=True, exist_ok=True)
    (fresh / "status.json").write_text("{}", encoding="utf-8")
    stale = service.export_dir("stale-export")
    stale.mkdir(parents=True, exist_ok=True)
    (stale / "status.json").write_text("{}", encoding="utf-8")

    old = (datetime.now(timezone.utc) - timedelta(hours=48)).timestamp()
    os.utime(stale, (old, old))

    removed = service.cleanup_expired(max_age_hours=24)
    assert removed == ["stale-export"]
    assert not stale.exists()
    assert fresh.exists()


# ----------------------------------------------------------------------
# Failure handling
# ----------------------------------------------------------------------
async def test_missing_state_records_failed_status(
    service: ExportService, output_root: Path
):
    final = await _export_and_wait(service, "assessment-that-does-not-exist")
    assert final["status"] == "failed"
    assert final["error"]
    assert "state.json" in final["error"]
    assert final["file_size_bytes"] is None
    assert service.get_export_path(final["export_id"]) is None


async def test_corrupt_state_records_failed_status(
    service: ExportService, output_root: Path
):
    root = output_root / "corrupt"
    root.mkdir(parents=True, exist_ok=True)
    (root / "state.json").write_text("{not json", encoding="utf-8")
    final = await _export_and_wait(service, "corrupt")
    assert final["status"] == "failed"
    assert final["error"]


async def test_unsupported_format_is_rejected(service: ExportService):
    with pytest.raises(InvalidExportRequest):
        await service.create_export("whatever", format="tar")


# ----------------------------------------------------------------------
# Route-level behaviour
# ----------------------------------------------------------------------
@pytest.fixture
def client(output_root: Path, assessment_id: str):
    """
    TestClient whose dependency-provided service points at tmp_path.

    ``create_export`` is overridden to build synchronously so route tests are
    deterministic; the production path (background asyncio task) is covered by
    the direct ExportService tests above.
    """
    from fastapi.testclient import TestClient

    from app.api import routes
    from app.main import app as fastapi_app

    class StubService:
        def __init__(self) -> None:
            self.exports = ExportService(output_root)

        def __getattr__(self, name):
            return getattr(self.exports, name)

        async def get_assessment(self, assessment_id: str):
            from cybog.models.assessment import Assessment, AssessmentStatus
            return {"assessment_id": assessment_id, "status": "COMPLETED", "owner_id": "test-internal-id"}

        def get_export_status(self, export_id):
            return self.exports.get_status(export_id)

        def get_export_download_info(self, export_id):
            status = self.exports.get_status(export_id)
            if status is None:
                return None
            path = self.exports.get_export_path(export_id)
            return {"ready": path is not None, "status": status.get("status"), "path": path}

        async def create_export(self, assessment_id, format="zip", **options):
            # Synchronous build so route assertions are deterministic; the
            # background-task path is covered by the ExportService tests.
            return self.exports.create_export_sync(assessment_id, format, **options)

    fastapi_app.dependency_overrides[routes.get_cybog_service] = lambda: StubService()
    try:
        yield TestClient(fastapi_app)
    finally:
        fastapi_app.dependency_overrides.pop(routes.get_cybog_service, None)


def test_route_status_unknown_export_returns_404(client, assessment_id):
    response = client.get(
        f"/api/v1/assessments/{assessment_id}/export/status",
        params={"export_id": "no-such-export"},
    )
    assert response.status_code == 404


def test_route_download_unknown_export_returns_404(client, assessment_id):
    response = client.get(
        f"/api/v1/assessments/{assessment_id}/export/download",
        params={"export_id": "no-such-export"},
    )
    assert response.status_code == 404


def test_route_status_and_download_after_completion(
    client, output_root: Path, fake_assessment, assessment_id: str
):
    created = client.post(
        f"/api/v1/assessments/{assessment_id}/export",
        json={"format": "zip", "include_raw": True, "include_evidence": True},
    )
    assert created.status_code == 200
    body = created.json()
    export_id = body["export_id"]
    assert body["assessment_id"] == assessment_id
    assert body["format"] == "zip"
    assert body["status"] == "completed"
    # estimated_completion must be present-or-null, never a 500.
    assert "estimated_completion" in body

    status_resp = client.get(
        f"/api/v1/assessments/{assessment_id}/export/status",
        params={"export_id": export_id},
    )
    assert status_resp.status_code == 200
    payload = status_resp.json()
    assert payload["status"] == "completed"
    assert payload["export_id"] == export_id
    assert payload["file_size_bytes"] > 0

    download = client.get(
        f"/api/v1/assessments/{assessment_id}/export/download",
        params={"export_id": export_id},
    )
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/zip"
    assert (
        f"assessment-{assessment_id}.zip" in download.headers.get("content-disposition", "")
    )
    with zipfile.ZipFile(io.BytesIO(download.content)) as zf:
        assert set(MANIFEST_FILES).issubset(set(zf.namelist()))


def test_route_rejects_traversal_export_id(client, assessment_id):
    response = client.get(
        f"/api/v1/assessments/{assessment_id}/export/status",
        params={"export_id": "../foo"},
    )
    assert response.status_code in (400, 404, 422)
    assert response.status_code != 500


def test_route_rejects_traversal_assessment_id(client):
    response = client.post(
        "/api/v1/assessments/..%2F..%2Fetc/export", json={"format": "zip"}
    )
    assert response.status_code != 500
    assert response.status_code in (400, 404, 422)


def test_route_failed_export_does_not_500(client, output_root: Path):
    response = client.post(
        "/api/v1/assessments/missing-assessment/export", json={"format": "zip"}
    )
    assert response.status_code == 200
    export_id = response.json()["export_id"]

    status_resp = client.get(
        "/api/v1/assessments/missing-assessment/export/status",
        params={"export_id": export_id},
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "failed"
    assert status_resp.json()["error"]

    download = client.get(
        "/api/v1/assessments/missing-assessment/export/download",
        params={"export_id": export_id},
    )
    assert download.status_code == 404


# ----------------------------------------------------------------------
# CybogIntegrationService delegation
# ----------------------------------------------------------------------
async def test_integration_service_delegates_to_export_service(
    output_root: Path, fake_assessment: AssessmentState, assessment_id: str
):
    """
    The real integration service must delegate export work to ExportService,
    and a freshly constructed instance (what get_cybog_service() does per
    request) must be able to read the persisted status back.
    """
    from cybog.config.loader import load_config

    from app.config import settings as backend_settings
    from app.services.cybog_integration import CybogIntegrationService

    config = load_config(backend_settings.CYBOG_CONFIG_PATH)
    config.output.root = str(output_root)
    service = CybogIntegrationService(config)

    created = await service.create_export(assessment_id)
    export_id = created["export_id"]
    assert created["assessment_id"] == assessment_id
    assert created["status"] == STATUS_PENDING

    status: dict = {}
    for _ in range(1000):
        status = service.get_export_status(export_id)
        if status and status["status"] in (STATUS_COMPLETED, STATUS_FAILED):
            break
        await asyncio.sleep(0.01)
    assert status["status"] == STATUS_COMPLETED, status.get("error")
    assert status["file_size_bytes"] > 0

    # A second instance sees the same persisted state.
    other = CybogIntegrationService(config)
    assert other.get_export_status(export_id)["status"] == STATUS_COMPLETED
    info = other.get_export_download_info(export_id)
    assert info["ready"] is True and info["path"].is_file()

    assert service.get_export_status("no-such-export") is None
    assert service.get_export_download_info("no-such-export") is None
    with pytest.raises(InvalidExportRequest):
        service.get_export_status("../foo")
    with pytest.raises(InvalidExportRequest):
        service.get_export_download_info("../../etc")