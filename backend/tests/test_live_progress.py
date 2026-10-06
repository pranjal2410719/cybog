"""
Tests for live assessment status: state-derived snapshots, the WebSocket
progress push loop, and the REST progress fallback.

Every assertion below is checked against a real AssessmentState persisted in
tmp_path -- no value in this file is fabricated by the code under test.
"""
from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.api.auth_routes import get_db as get_db_dep
from app.db.base import Base
from app.db.models import DBUser
from app.models.auth import Role
from cybog.config.loader import load_config
from cybog.models.assessment import (
    Assessment,
    AssessmentStatus,
    Authorization,
    AuthorizationStatus,
)
from cybog.models.finding import Finding, Severity, ValidationStatus
from cybog.models.job import JobStatus, StageJob
from cybog.models.target import Target, TargetStatus
from cybog.state.assessment_state import AssessmentState

from app.api import routes
from app.config import settings as backend_settings
from app.main import app as fastapi_app
from app.main import manager
from app.services.cybog_integration import CybogIntegrationService, _running_tasks
from app.services.progress_snapshot import (
    build_progress_snapshot,
    is_terminal_snapshot,
)

from app import main as main_module


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _make_finding(
    finding_id: str,
    target_id: str,
    domain: str,
    validation_status: ValidationStatus,
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
    status: JobStatus,
    result_count: int = 0,
) -> StageJob:
    job = StageJob(
        assessment_id=assessment_id, owner_id="test-internal-id",
        target_id=target_id,
        target_domain=domain,
        stage=stage,
        status=status,
        result_count=result_count,
    )
    if status in (JobStatus.RUNNING, JobStatus.COMPLETED, JobStatus.FAILED):
        job.started_at = datetime(2026, 1, 1, 12, 0, 10)
    if status in (JobStatus.COMPLETED, JobStatus.FAILED):
        job.finished_at = datetime(2026, 1, 1, 12, 0, 20)
    return job


def _write_state(
    root: Path,
    assessment_id: str,
    status: AssessmentStatus = AssessmentStatus.RUNNING,
    targets: List[Target] | None = None,
    jobs: List[StageJob] | None = None,
    findings: List[Finding] | None = None,
    authorized: bool = False,
) -> Path:
    """Persist a real AssessmentState at <root>/<assessment_id>/state.json."""
    assessment = Assessment(
        assessment_id=assessment_id, owner_id="test-internal-id",
        profile="standard",
        target_input_file="targets.txt",
        scope_file="authorized_scope.txt",
        status=status,
        created_at=datetime(2026, 1, 1, 12, 0, 0),
        started_at=datetime(2026, 1, 1, 12, 0, 5),
        artifact_root=str(root / assessment_id),
        config_snapshot={},
    )
    if authorized:
        # T5: execution requires a confirmed Authorization record.
        assessment.authorization = Authorization(
            required=True,
            scope_file="authorized_scope.txt",
            status=AuthorizationStatus.AUTHORIZED,
            authorized_at=datetime(2026, 1, 1, 12, 0, 6),
            authorized_by_user_id="test-internal-id",
            authorized_patterns=["one.example.com"],
            scope_snapshot={"include": ["one.example.com"], "exclude": [],
                            "targets": ["one.example.com"]},
            scope_sha256="f" * 64,
        )
    state = AssessmentState.create_new(assessment)
    for target in targets or []:
        state.add_target(target)
    for job in jobs or []:
        state.add_job(job)
    for finding in findings or []:
        state.add_finding(finding)
    path = root / assessment_id / "state.json"
    state.save(path)
    return path


def _make_service(output_root: Path) -> CybogIntegrationService:
    config = load_config(backend_settings.CYBOG_CONFIG_PATH)
    config.output.root = str(output_root)
    return CybogIntegrationService(config)


class FakeSocket:
    """Minimal WebSocket stand-in that records the pushed JSON messages."""

    def __init__(self) -> None:
        self.sent: List[Dict[str, Any]] = []

    async def send_text(self, data: str) -> None:
        self.sent.append(json.loads(data))


@pytest.fixture
def output_root(tmp_path: Path) -> Path:
    root = tmp_path / "artifacts"
    root.mkdir()
    return root


@pytest.fixture
def service(output_root: Path) -> CybogIntegrationService:
    return _make_service(output_root)


@pytest.fixture
def client(service: CybogIntegrationService):
    fastapi_app.dependency_overrides[routes.get_cybog_service] = lambda: service
    try:
        yield TestClient(fastapi_app)
    finally:
        fastapi_app.dependency_overrides.pop(routes.get_cybog_service, None)


@pytest.fixture
def ws_auth_db():
    """In-memory users DB containing the conftest mock identity.

    The WS handshake resolves the ticket's user_id against get_db, so
    tests that open real sockets need this override (scoped + restored).
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with maker() as session:
            session.add(DBUser(
                id="test-internal-id", uid="op_12345", name="Test User",
                role=Role.OPERATOR, active=True,
            ))
            await session.commit()

    asyncio.run(_setup())

    async def _override():
        async with maker() as session:
            yield session

    prev = fastapi_app.dependency_overrides.get(get_db_dep)
    fastapi_app.dependency_overrides[get_db_dep] = _override
    try:
        yield
    finally:
        if prev is not None:
            fastapi_app.dependency_overrides[get_db_dep] = prev
        else:
            fastapi_app.dependency_overrides.pop(get_db_dep, None)

        async def _teardown():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)

        asyncio.run(_teardown())


@pytest.fixture
def connected():
    """Register a fake socket for an assessment and clean it up afterwards."""
    registered: List[Any] = []

    def _connect(assessment_id: str) -> FakeSocket:
        socket = FakeSocket()
        manager.active_connections.setdefault(assessment_id, set()).add(socket)
        registered.append((assessment_id, socket))
        return socket

    yield _connect
    for assessment_id, socket in registered:
        manager.disconnect(assessment_id, socket)


@pytest.fixture(autouse=True)
def _clear_running_tasks():
    """Ensure background pipeline tasks from one test cannot leak into another."""
    yield
    _running_tasks.clear()


@pytest.fixture
def state_loader(monkeypatch, service: CybogIntegrationService):
    """Point main._load_snapshot at the service bound to tmp_path."""

    async def _loader(assessment_id: str) -> Dict[str, Any]:
        state = service.load_state(assessment_id)
        return build_progress_snapshot(state, assessment_id)

    monkeypatch.setattr(main_module, "_load_snapshot", _loader)
    return _loader


# ----------------------------------------------------------------------
# 1. Snapshot reflects true state
# ----------------------------------------------------------------------
def test_snapshot_reflects_real_persisted_state(service, output_root):
    """A snapshot built from a real AssessmentState reports the true values."""
    aid = "assess-live"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.RUNNING,
        targets=[
            Target(target_id="t-1", domain="one.example.com", status=TargetStatus.RUNNING),
            Target(target_id="t-2", domain="two.example.com", status=TargetStatus.IN_SCOPE),
        ],
        jobs=[
            _make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.COMPLETED, 3),
            _make_job(aid, "t-1", "one.example.com", "dnsx", JobStatus.RUNNING, 1),
            _make_job(aid, "t-2", "two.example.com", "subfinder", JobStatus.PENDING),
        ],
        findings=[
            _make_finding("f-1", "t-1", "one.example.com", ValidationStatus.VALIDATED),
            _make_finding("f-2", "t-1", "one.example.com", ValidationStatus.NEEDS_VALIDATION),
            _make_finding("f-3", "t-2", "two.example.com", ValidationStatus.DISCOVERED),
        ],
    )

    state = service.load_state(aid)
    snap = build_progress_snapshot(state, aid)

    assert snap["assessment_id"] == aid
    assert snap["status"] == "RUNNING"
    assert snap["is_terminal"] is False
    assert snap["timestamp"]

    # targets
    by_id = {t["target_id"]: t for t in snap["targets"]}
    assert by_id["t-1"]["status"] == "RUNNING"
    assert by_id["t-1"]["domain"] == "one.example.com"
    assert by_id["t-1"]["total_jobs"] == 2
    assert by_id["t-1"]["completed_jobs"] == 1
    assert by_id["t-1"]["completion_percentage"] == 50.0
    assert by_id["t-1"]["findings_count"] == 2
    assert by_id["t-2"]["status"] == "IN_SCOPE"
    assert by_id["t-2"]["findings_count"] == 1

    # jobs / stages
    assert snap["jobs_total"] == 3
    assert snap["jobs_completed"] == 1
    assert snap["completion_percentage"] == pytest.approx(33.33, abs=0.01)
    stages = {s["stage"]: s for s in snap["stages"]}
    # subfinder rolled up: one COMPLETED job + one still PENDING.
    assert stages["subfinder"]["status"] == "PENDING"
    assert stages["dnsx"]["status"] == "RUNNING"
    assert stages["subfinder"]["job_count"] == 2
    assert snap["running_stages"] == ["dnsx"]
    dnsx_job = next(j for j in snap["jobs"] if j["stage"] == "dnsx")
    assert dnsx_job["status"] == "RUNNING"
    assert dnsx_job["target_id"] == "t-1"
    assert dnsx_job["started_at"]

    # findings
    assert snap["findings_count"] == 3
    assert snap["pending_validation_count"] == 2


# ----------------------------------------------------------------------
# 2. Terminal assessment stops the push loop
# ----------------------------------------------------------------------
def test_terminal_assessment_stops_push_loop(output_root, connected, state_loader):
    """A COMPLETED assessment gets exactly one push and the loop returns."""
    aid = "assess-done"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.COMPLETED,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.COMPLETED)],
        jobs=[_make_job(aid, "t-1", "one.example.com", "nuclei", JobStatus.COMPLETED, 2)],
    )
    socket = connected(aid)

    async def drive():
        before = {t for t in asyncio.all_tasks()}
        # Would hang forever if the loop never exited on a terminal status.
        await asyncio.wait_for(
            main_module.push_progress_loop(aid, interval=0.01), timeout=10
        )
        await asyncio.sleep(0)
        return before, {t for t in asyncio.all_tasks()}

    before, after = asyncio.run(drive())

    assert len(socket.sent) == 1
    assert socket.sent[0]["assessment_id"] == aid
    assert socket.sent[0]["status"] == "COMPLETED"
    assert socket.sent[0]["is_terminal"] is True
    assert is_terminal_snapshot(socket.sent[0]) is True
    # No leaked push task.
    assert not (after - before)


def test_push_loop_exits_when_no_connections_remain(state_loader):
    """With no sockets registered the loop returns instead of spinning."""
    async def drive():
        await asyncio.wait_for(
            main_module.push_progress_loop("assess-nobody", interval=0.01), timeout=10
        )

    asyncio.run(drive())


def test_push_loop_stops_on_stop_event(output_root, connected, state_loader):
    """An explicit stop event ends the loop for a non-terminal assessment."""
    aid = "assess-stop"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.RUNNING,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.RUNNING)],
        jobs=[_make_job(aid, "t-1", "one.example.com", "dnsx", JobStatus.RUNNING, 0)],
    )
    socket = connected(aid)
    stop = asyncio.Event()

    async def drive():
        task = asyncio.create_task(
            main_module.push_progress_loop(aid, interval=0.01, stop_event=stop)
        )
        await asyncio.sleep(0.05)
        assert not task.done()
        stop.set()
        await asyncio.wait_for(task, timeout=10)

    asyncio.run(drive())
    assert len(socket.sent) >= 1
    assert socket.sent[0]["status"] == "RUNNING"


# ----------------------------------------------------------------------
# 3. REST: real snapshot, and a clean 404 for a missing assessment
# ----------------------------------------------------------------------
def test_progress_rest_endpoint_returns_real_snapshot(client, output_root):
    aid = "assess-rest"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.RUNNING,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.RUNNING)],
        jobs=[
            _make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.COMPLETED, 4),
            _make_job(aid, "t-1", "one.example.com", "dnsx", JobStatus.RUNNING, 0),
        ],
        findings=[_make_finding("f-1", "t-1", "one.example.com", ValidationStatus.NEEDS_VALIDATION)],
    )

    response = client.get(f"/api/v1/assessments/{aid}/progress")
    assert response.status_code == 200
    body = response.json()
    assert body["assessment_id"] == aid
    assert body["status"] == "RUNNING"
    assert body["jobs_total"] == 2
    assert body["jobs_completed"] == 1
    assert body["findings_count"] == 1
    assert body["pending_validation_count"] == 1
    assert body["targets"][0]["target_id"] == "t-1"
    assert "dnsx" in [s["stage"] for s in body["stages"]]

    # The pre-existing /status route keeps serving the same real snapshot.
    status_response = client.get(f"/api/v1/assessments/{aid}/status")
    assert status_response.status_code == 200
    assert status_response.json()["assessment_id"] == aid


def test_missing_assessment_returns_404_not_500(client):
    """A non-existent assessment yields a clean 404 over REST."""
    response = client.get("/api/v1/assessments/does-not-exist/progress")
    assert response.status_code == 404
    # Frozen R2: the detail omits the id so denied-but-existing and
    # genuinely-missing are indistinguishable (no existence oracle).
    assert response.json()["detail"] == "Assessment not found"

    status_response = client.get("/api/v1/assessments/does-not-exist/status")
    assert status_response.status_code == 404


# ----------------------------------------------------------------------
# 4. WebSocket delivery
# ----------------------------------------------------------------------
def test_websocket_client_receives_real_progress_message(
    monkeypatch, service, output_root, ws_auth_db
):
    """A connected client receives a progress message with the real id+status."""
    aid = "assess-ws"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.RUNNING,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.RUNNING)],
        jobs=[_make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.RUNNING, 0)],
    )
    monkeypatch.setattr(main_module, "get_cybog_service", lambda: service)
    fastapi_app.dependency_overrides[routes.get_cybog_service] = lambda: service
    try:
        # T3: the handshake needs a ticket minted over REST first.
        with TestClient(fastapi_app) as rest_client:
            resp = rest_client.post(f"/api/v1/assessments/{aid}/ws-ticket")
            assert resp.status_code == 200, resp.text
            ticket = resp.json()["ticket"]
    finally:
        fastapi_app.dependency_overrides.pop(routes.get_cybog_service, None)

    received: List[Dict[str, Any]] = []

    def interact() -> None:
        with TestClient(fastapi_app) as ws_client:
            with ws_client.websocket_connect(f"/ws/assessments/{aid}?ticket={ticket}") as ws:
                for _ in range(2):
                    received.append(ws.receive_json())

    # Guard against a hang if the push loop never emits.
    thread = threading.Thread(target=interact, daemon=True)
    thread.start()
    thread.join(timeout=20)
    assert not thread.is_alive(), "websocket push loop never sent a message"

    assert received[0]["type"] == "connected"
    progress = received[1]
    assert progress["type"] == "progress"
    assert progress["assessment_id"] == aid
    assert progress["status"] == "RUNNING"
    assert progress["targets"][0]["domain"] == "one.example.com"
    assert progress["jobs"][0]["stage"] == "subfinder"
    assert progress["jobs"][0]["status"] == "RUNNING"


# ----------------------------------------------------------------------
# 5. Pushed values come from state (real, not faked)
# ----------------------------------------------------------------------
def test_pushed_snapshot_tracks_state_changes(output_root, connected, state_loader):
    """Mutating the persisted state changes what the push loop emits."""
    aid = "assess-mutate"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.RUNNING,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.RUNNING)],
        jobs=[_make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.RUNNING, 0)],
    )
    socket = connected(aid)

    async def drive():
        async def mutate():
            await asyncio.sleep(0.08)
            _write_state(
                output_root,
                aid,
                status=AssessmentStatus.COMPLETED,
                targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.COMPLETED)],
                jobs=[
                    _make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.COMPLETED, 7),
                    _make_job(aid, "t-1", "one.example.com", "dnsx", JobStatus.COMPLETED, 2),
                ],
                findings=[_make_finding("f-1", "t-1", "one.example.com", ValidationStatus.VALIDATED)],
            )

        await asyncio.gather(
            mutate(),
            asyncio.wait_for(
                main_module.push_progress_loop(aid, interval=0.02), timeout=15
            ),
        )

    asyncio.run(drive())

    assert len(socket.sent) >= 2, "push loop did not re-read state"
    first, last = socket.sent[0], socket.sent[-1]

    assert first["status"] == "RUNNING"
    assert first["jobs_total"] == 1
    assert first["findings_count"] == 0
    assert first["is_terminal"] is False

    assert last["status"] == "COMPLETED"
    assert last["jobs_total"] == 2
    assert last["completion_percentage"] == 100.0
    assert last["findings_count"] == 1
    assert last["is_terminal"] is True
    assert last["targets"][0]["status"] == "COMPLETED"


def test_missing_assessment_over_ws_reports_not_found(
    monkeypatch, service, connected
):
    """A socket for an unknown assessment gets a NOT_FOUND snapshot, once."""
    socket = connected("assess-ghost")
    monkeypatch.setattr(main_module, "get_cybog_service", lambda: service)

    async def drive():
        await asyncio.wait_for(
            main_module.push_progress_loop("assess-ghost", interval=0.01), timeout=10
        )

    asyncio.run(drive())

    assert len(socket.sent) == 1
    assert socket.sent[0]["status"] == "NOT_FOUND"
    assert socket.sent[0]["assessment_id"] == "assess-ghost"
    assert socket.sent[0]["is_terminal"] is True


# ----------------------------------------------------------------------
# 6. Background start/resume: 202 acknowledgement and duplicate guard
# ----------------------------------------------------------------------
def test_start_returns_202_and_registers_task(client, output_root, service, monkeypatch):
    """POST /start returns 202 immediately and the task appears in the registry."""
    aid = "assess-start-202"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.READY,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.IN_SCOPE)],
        jobs=[_make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.PENDING)],
        authorized=True,
    )

    async def _fake_execute(execution_aid: str) -> AssessmentState:
        await asyncio.sleep(0.2)
        state = service.load_state(execution_aid)
        state.assessment.status = AssessmentStatus.RUNNING
        state.assessment.started_at = datetime(2026, 1, 1, 12, 0, 5)
        return state

    monkeypatch.setattr(service._service, "execute", _fake_execute)
    with TestClient(fastapi_app) as fresh_client:
        response = fresh_client.post(f"/api/v1/assessments/{aid}/start")
        assert response.status_code == 202
        body = response.json()
        assert body["assessment_id"] == aid
        assert body["status"] == "RUNNING"
        assert body["already_running"] is False
        task = _running_tasks.get(aid)
        assert task is not None
        assert not task.done()


def test_duplicate_start_returns_already_running(client, output_root, service, monkeypatch):
    """A second start for the same assessment returns already_running: true."""
    aid = "assess-dup-start"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.READY,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.IN_SCOPE)],
        jobs=[_make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.PENDING)],
        authorized=True,
    )

    async def _fake_execute(execution_aid: str) -> AssessmentState:
        await asyncio.sleep(0.2)
        state = service.load_state(execution_aid)
        state.assessment.status = AssessmentStatus.RUNNING
        state.assessment.started_at = datetime(2026, 1, 1, 12, 0, 5)
        return state

    monkeypatch.setattr(service._service, "execute", _fake_execute)
    with TestClient(fastapi_app) as fresh_client:
        first = fresh_client.post(f"/api/v1/assessments/{aid}/start")
        assert first.status_code == 202
        assert first.json()["already_running"] is False

        second = fresh_client.post(f"/api/v1/assessments/{aid}/start")
        assert second.status_code == 202
        assert second.json()["already_running"] is True
        # Only one background task was created.
        assert sum(1 for t in _running_tasks.values() if not t.done()) == 1


def test_resume_returns_202_and_registers_task(client, output_root, service, monkeypatch):
    """POST /resume returns 202 immediately for a resumable assessment."""
    aid = "assess-resume-202"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.FAILED,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.IN_SCOPE)],
        jobs=[
            _make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.FAILED),
            _make_job(aid, "t-1", "one.example.com", "dnsx", JobStatus.PENDING),
        ],
        authorized=True,
    )

    async def _fake_resume(execution_aid: str) -> AssessmentState:
        await asyncio.sleep(0.2)
        state = service.load_state(execution_aid)
        state.assessment.status = AssessmentStatus.RUNNING
        state.assessment.started_at = datetime(2026, 1, 1, 12, 0, 5)
        return state

    monkeypatch.setattr(service._service, "resume", _fake_resume)
    with TestClient(fastapi_app) as fresh_client:
        response = fresh_client.post(f"/api/v1/assessments/{aid}/resume")
        assert response.status_code == 202
        body = response.json()
        assert body["assessment_id"] == aid
        assert body["status"] == "RUNNING"
        assert body["already_running"] is False
        task = _running_tasks.get(aid)
        assert task is not None
        assert not task.done()


def test_start_missing_assessment_returns_404(client):
    """A start for a non-existent assessment yields 404."""
    with TestClient(fastapi_app) as fresh_client:
        response = fresh_client.post("/api/v1/assessments/does-not-exist/start")
    assert response.status_code == 404
    assert response.json()["detail"] == "Assessment not found"


def test_start_cancelled_assessment_returns_400(client, output_root):
    """A start for a CANCELLED assessment yields 400."""
    aid = "assess-cancelled-start"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.CANCELLED,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.IN_SCOPE)],
        jobs=[_make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.PENDING)],
    )

    with TestClient(fastapi_app) as fresh_client:
        response = fresh_client.post(f"/api/v1/assessments/{aid}/start")
    assert response.status_code == 400
    assert "CANCELLED" in response.json()["detail"]


def test_websocket_receives_progress_after_background_start(
    monkeypatch, service, output_root, connected, ws_auth_db
):
    """A WebSocket client receives real progress after a background start."""
    aid = "assess-ws-bg"
    _write_state(
        output_root,
        aid,
        status=AssessmentStatus.CREATED,
        targets=[Target(target_id="t-1", domain="one.example.com", status=TargetStatus.IN_SCOPE)],
        jobs=[_make_job(aid, "t-1", "one.example.com", "subfinder", JobStatus.PENDING)],
    )
    monkeypatch.setattr(main_module, "get_cybog_service", lambda: service)
    fastapi_app.dependency_overrides[routes.get_cybog_service] = lambda: service
    try:
        with TestClient(fastapi_app) as rest_client:
            resp = rest_client.post(f"/api/v1/assessments/{aid}/ws-ticket")
            assert resp.status_code == 200, resp.text
            ticket = resp.json()["ticket"]
    finally:
        fastapi_app.dependency_overrides.pop(routes.get_cybog_service, None)

    received: List[Dict[str, Any]] = []

    def interact() -> None:
        with TestClient(fastapi_app) as ws_client:
            with ws_client.websocket_connect(f"/ws/assessments/{aid}?ticket={ticket}") as ws:
                for _ in range(2):
                    received.append(ws.receive_json())

    thread = threading.Thread(target=interact, daemon=True)
    thread.start()
    thread.join(timeout=20)
    assert not thread.is_alive(), "websocket push loop never sent a message"

    assert received[0]["type"] == "connected"
    progress = received[1]
    assert progress["type"] == "progress"
    assert progress["assessment_id"] == aid
