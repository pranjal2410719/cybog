"""
T2: tenant-isolation authorization matrix.

Frozen policy (R2 + MVP validator policy):
- unauthenticated                    -> 401
- role violation (e.g. OPERATOR validating, MANAGEMENT resuming) -> 403
- cross-tenant access by authenticated non-owner non-manager -> 404
  (indistinguishable from "does not exist"; no existence oracle)
- owner / MANAGEMENT / VALIDATOR (MVP shared queue) -> allowed

Overrides are fixture-scoped (same pattern as test_auth.py) so module
import/execution order cannot leak state into other test modules.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from typing import AsyncGenerator

from app.main import app
from app.db.base import Base
from app.db.models import DBUser
from app.models.auth import Role
from app.api.auth_routes import get_db, get_current_user
from app.config import settings
from app.services.passwords import hash_password
from app.services.preflight import PreflightCheck
import app.services.preflight as preflight_module


ENGINE = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
Session = sessionmaker(ENGINE, class_=AsyncSession, expire_on_commit=False)

PASSWORDS = {
    "op_A": "matrix-op-a-password",
    "op_B": "matrix-op-b-password",
    "val_1": "matrix-val-password",
    "mg_1": "matrix-mg-password",
}


async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with Session() as session:
        yield session


@pytest.fixture
def matrix_client(tmp_path):
    prev_user = app.dependency_overrides.pop(get_current_user, None)
    prev_db = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = _override_get_db
    settings.CYBOG_OUTPUT_ROOT = str(tmp_path)
    try:
        async def _setup():
            async with ENGINE.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with Session() as session:
                session.add_all([
                    DBUser(id="a-uuid", uid="op_A", name="A",
                           role=Role.OPERATOR, active=True,
                           password_hash=hash_password(PASSWORDS["op_A"])),
                    DBUser(id="b-uuid", uid="op_B", name="B",
                           role=Role.OPERATOR, active=True,
                           password_hash=hash_password(PASSWORDS["op_B"])),
                    DBUser(id="v-uuid", uid="val_1", name="V",
                           role=Role.VALIDATOR, active=True,
                           password_hash=hash_password(PASSWORDS["val_1"])),
                    DBUser(id="m-uuid", uid="mg_1", name="M",
                           role=Role.MANAGEMENT, active=True,
                           password_hash=hash_password(PASSWORDS["mg_1"])),
                ])
                await session.commit()

        asyncio.run(_setup())
        with TestClient(app) as client:
            yield client
    finally:
        async def _teardown():
            async with ENGINE.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)

        asyncio.run(_teardown())
        if prev_db is not None:
            app.dependency_overrides[get_db] = prev_db
        else:
            app.dependency_overrides.pop(get_db, None)
        if prev_user is not None:
            app.dependency_overrides[get_current_user] = prev_user


def _login(client, uid):
    res = client.post("/api/v1/auth/login",
                      json={"uid": uid, "password": PASSWORDS[uid]})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['token']}"}


def _make_assessment(client, headers):
    res = client.post("/api/v1/assessments", json={
        "name": "Matrix",
        "targets_file": "example.com\n",
        "scope_file": "example.com\n",
        "profile": "quick",
    }, headers=headers)
    assert res.status_code == 200, res.text
    return res.json()["assessment_id"]


def test_cross_tenant_reads_are_404(matrix_client):
    op_a = _login(matrix_client, "op_A")
    op_b = _login(matrix_client, "op_B")
    aid = _make_assessment(matrix_client, op_a)

    assert matrix_client.get(f"/api/v1/assessments/{aid}", headers=op_b).status_code == 404
    assert matrix_client.get(f"/api/v1/assessments/{aid}/status", headers=op_b).status_code == 404
    assert matrix_client.get(f"/api/v1/assessments/{aid}/progress", headers=op_b).status_code == 404
    assert matrix_client.get(f"/api/v1/assessments/{aid}/findings", headers=op_b).status_code == 404
    assert matrix_client.get(f"/api/v1/assessments/{aid}/findings/nope", headers=op_b).status_code == 404
    assert matrix_client.get(f"/api/v1/assessments/{aid}/validation/pending", headers=op_b).status_code == 404
    assert matrix_client.get(f"/api/v1/assessments/{aid}/artifacts", headers=op_b).status_code == 404
    assert matrix_client.get(f"/api/v1/assessments/{aid}/reports", headers=op_b).status_code == 404
    # Owner still sees everything.
    assert matrix_client.get(f"/api/v1/assessments/{aid}", headers=op_a).status_code == 200
    assert matrix_client.get(f"/api/v1/assessments/{aid}/findings", headers=op_a).status_code == 200


def test_cross_tenant_mutations_are_404(matrix_client):
    op_a = _login(matrix_client, "op_A")
    op_b = _login(matrix_client, "op_B")
    aid = _make_assessment(matrix_client, op_a)

    assert matrix_client.post(f"/api/v1/assessments/{aid}/start", headers=op_b).status_code == 404
    assert matrix_client.post(f"/api/v1/assessments/{aid}/resume", headers=op_b).status_code == 404
    assert matrix_client.post(f"/api/v1/assessments/{aid}/cancel", headers=op_b).status_code == 404
    assert matrix_client.post(f"/api/v1/assessments/{aid}/export", json={}, headers=op_b).status_code == 404


def test_cross_tenant_export_status_and_download_are_404(matrix_client):
    op_a = _login(matrix_client, "op_A")
    op_b = _login(matrix_client, "op_B")
    aid = _make_assessment(matrix_client, op_a)

    res = matrix_client.post(f"/api/v1/assessments/{aid}/export", json={}, headers=op_a)
    assert res.status_code == 200, res.text
    export_id = res.json()["export_id"]

    assert matrix_client.get(
        f"/api/v1/assessments/{aid}/export/status",
        params={"export_id": export_id}, headers=op_b).status_code == 404
    assert matrix_client.get(
        f"/api/v1/assessments/{aid}/export/download",
        params={"export_id": export_id}, headers=op_b).status_code == 404


def test_export_id_bound_to_assessment(matrix_client):
    op_a = _login(matrix_client, "op_A")
    aid1 = _make_assessment(matrix_client, op_a)
    aid2 = _make_assessment(matrix_client, op_a)

    res = matrix_client.post(f"/api/v1/assessments/{aid1}/export", json={}, headers=op_a)
    assert res.status_code == 200, res.text
    export_id = res.json()["export_id"]

    # Same owner, but the export belongs to aid1: aid2 paths must 404.
    assert matrix_client.get(
        f"/api/v1/assessments/{aid2}/export/status",
        params={"export_id": export_id}, headers=op_a).status_code == 404
    assert matrix_client.get(
        f"/api/v1/assessments/{aid2}/export/download",
        params={"export_id": export_id}, headers=op_a).status_code == 404
    # And the right path resolves (pending or completed, never 404).
    assert matrix_client.get(
        f"/api/v1/assessments/{aid1}/export/status",
        params={"export_id": export_id}, headers=op_a).status_code == 200


def test_validator_mvp_policy(matrix_client):
    op_a = _login(matrix_client, "op_A")
    val = _login(matrix_client, "val_1")
    aid = _make_assessment(matrix_client, op_a)

    # Validators work the shared queue: reads allowed cross-tenant (MVP).
    assert matrix_client.get(f"/api/v1/assessments/{aid}", headers=val).status_code == 200
    assert matrix_client.get(f"/api/v1/assessments/{aid}/status", headers=val).status_code == 200
    assert matrix_client.get(f"/api/v1/assessments/{aid}/findings", headers=val).status_code == 200
    assert matrix_client.get(f"/api/v1/assessments/{aid}/validation/pending", headers=val).status_code == 200
    # Validator verdict path is reachable (unknown finding -> success:false, not 403/404).
    res = matrix_client.post(f"/api/v1/assessments/{aid}/findings/nope/validate",
                             json={"validation_type": "confirm"}, headers=val)
    assert res.status_code == 200
    # ...while operators are role-blocked from verdicts even on their own work.
    res = matrix_client.post(f"/api/v1/assessments/{aid}/findings/nope/validate",
                             json={"validation_type": "confirm"}, headers=op_a)
    assert res.status_code == 403


def test_management_reads_but_cannot_operate(matrix_client):
    op_a = _login(matrix_client, "op_A")
    mg = _login(matrix_client, "mg_1")
    aid = _make_assessment(matrix_client, op_a)

    assert matrix_client.get(f"/api/v1/assessments/{aid}", headers=mg).status_code == 200
    assert matrix_client.get(f"/api/v1/assessments/{aid}/findings", headers=mg).status_code == 200
    # Management is read-only oversight: operational routes are role-gated.
    assert matrix_client.post(f"/api/v1/assessments/{aid}/resume", headers=mg).status_code == 403
    assert matrix_client.post(f"/api/v1/assessments/{aid}/start", headers=mg).status_code == 403
    assert matrix_client.post(f"/api/v1/assessments/{aid}/cancel", headers=mg).status_code == 403


def test_unauthenticated_is_401(matrix_client):
    op_a = _login(matrix_client, "op_A")
    aid = _make_assessment(matrix_client, op_a)

    assert matrix_client.get(f"/api/v1/assessments/{aid}/status").status_code == 401
    assert matrix_client.get(f"/api/v1/assessments/{aid}/findings").status_code == 401
    assert matrix_client.post(f"/api/v1/assessments/{aid}/start").status_code == 401


def test_target_id_is_tenant_bound(matrix_client):
    op_a = _login(matrix_client, "op_A")
    op_b = _login(matrix_client, "op_B")

    res = matrix_client.post("/api/v1/targets", json={
        "name": "A target", "domain": "example.com",
    }, headers=op_a)
    assert res.status_code == 200, res.text
    target_id = res.json()["id"]

    # Operator B referencing A's target: 404, no assessment created.
    res = matrix_client.post("/api/v1/assessments", json={
        "name": "Theft", "target_id": target_id, "profile": "quick",
    }, headers=op_b)
    assert res.status_code == 404

    # Owner can use it.
    res = matrix_client.post("/api/v1/assessments", json={
        "name": "Legit", "target_id": target_id, "profile": "quick",
    }, headers=op_a)
    assert res.status_code == 200, res.text


def test_list_visibility(matrix_client):
    op_a = _login(matrix_client, "op_A")
    op_b = _login(matrix_client, "op_B")
    val = _login(matrix_client, "val_1")
    mg = _login(matrix_client, "mg_1")
    aid = _make_assessment(matrix_client, op_a)
    ids = lambda r: [a["assessment_id"] for a in r.json()]

    assert aid in ids(matrix_client.get("/api/v1/assessments", headers=op_a))
    assert aid not in ids(matrix_client.get("/api/v1/assessments", headers=op_b))
    # MVP validator policy: the shared queue is visible.
    assert aid in ids(matrix_client.get("/api/v1/assessments", headers=val))
    assert aid in ids(matrix_client.get("/api/v1/assessments", headers=mg))


# --- T5: explicit human authorization ---

def test_authorize_owner_records_attribution(matrix_client):
    op_a = _login(matrix_client, "op_A")
    aid = _make_assessment(matrix_client, op_a)

    res = matrix_client.post(f"/api/v1/assessments/{aid}/authorize", headers=op_a)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["authorized"] is True
    assert body["authorized_by_user_id"] == "a-uuid"
    assert body["authorized_at"]
    assert len(body["scope_sha256"]) == 64

    # Idempotent retry.
    res2 = matrix_client.post(f"/api/v1/assessments/{aid}/authorize", headers=op_a)
    assert res2.status_code == 200
    assert res2.json()["scope_sha256"] == body["scope_sha256"]

    # The assessment response now carries the record.
    detail = matrix_client.get(f"/api/v1/assessments/{aid}", headers=op_a).json()
    assert detail["authorization"]["status"] == "AUTHORIZED"
    assert detail["authorization"]["confirmed"] is True


def test_authorize_cross_tenant_and_validator_denied(matrix_client):
    op_a = _login(matrix_client, "op_A")
    op_b = _login(matrix_client, "op_B")
    val = _login(matrix_client, "val_1")
    aid = _make_assessment(matrix_client, op_a)

    assert matrix_client.post(f"/api/v1/assessments/{aid}/authorize", headers=op_b).status_code == 404
    # Validators cannot self-authorize their queue.
    assert matrix_client.post(f"/api/v1/assessments/{aid}/authorize", headers=val).status_code == 404
    assert matrix_client.post(f"/api/v1/assessments/{aid}/authorize").status_code == 401


def _mock_toolchain_ok(monkeypatch):
    async def _fake(config, timeout_seconds=90.0):
        return PreflightCheck("toolchain", True, "mocked 7/7 available")
    monkeypatch.setattr(preflight_module, "check_toolchain", _fake)


def test_start_and_resume_require_authorization(matrix_client):
    op_a = _login(matrix_client, "op_A")
    aid = _make_assessment(matrix_client, op_a)

    res = matrix_client.post(f"/api/v1/assessments/{aid}/start", headers=op_a)
    assert res.status_code == 400
    assert "human-authorized" in res.json()["detail"]

    res = matrix_client.post(f"/api/v1/assessments/{aid}/resume", headers=op_a)
    assert res.status_code == 400

    matrix_client.post(f"/api/v1/assessments/{aid}/authorize", headers=op_a)
    # Authorized but not preflighted: the READY gate refuses.
    res = matrix_client.post(f"/api/v1/assessments/{aid}/start", headers=op_a)
    assert res.status_code == 400
    assert "preflight" in res.json()["detail"].lower()


def test_authorize_frozen_after_execution_begins(matrix_client, monkeypatch):
    _mock_toolchain_ok(monkeypatch)
    op_a = _login(matrix_client, "op_A")
    aid = _make_assessment(matrix_client, op_a)
    matrix_client.post(f"/api/v1/assessments/{aid}/authorize", headers=op_a)
    pre = matrix_client.post(f"/api/v1/assessments/{aid}/preflight", headers=op_a)
    assert pre.status_code == 200, pre.text
    assert pre.json()["ready"] is True
    assert matrix_client.post(f"/api/v1/assessments/{aid}/start", headers=op_a).status_code == 202

    res = matrix_client.post(f"/api/v1/assessments/{aid}/authorize", headers=op_a)
    assert res.status_code == 409
    assert "frozen" in res.json()["detail"]


# --- T7: preflight boundary ---

def test_preflight_unconfirmed_reports_not_ready(matrix_client):
    op_a = _login(matrix_client, "op_A")
    aid = _make_assessment(matrix_client, op_a)

    res = matrix_client.post(f"/api/v1/assessments/{aid}/preflight", headers=op_a)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ready"] is False
    assert body["status"] == "CREATED"
    failed = {c["name"] for c in body["checks"] if not c["ok"]}
    assert "authorization" in failed
    # Nothing mutated by a failed preflight.
    detail = matrix_client.get(f"/api/v1/assessments/{aid}", headers=op_a).json()
    assert detail["status"] == "CREATED"


def test_preflight_pass_sets_ready(matrix_client, monkeypatch):
    _mock_toolchain_ok(monkeypatch)
    op_a = _login(matrix_client, "op_A")
    aid = _make_assessment(matrix_client, op_a)
    matrix_client.post(f"/api/v1/assessments/{aid}/authorize", headers=op_a)

    res = matrix_client.post(f"/api/v1/assessments/{aid}/preflight", headers=op_a)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ready"] is True, body["checks"]
    assert body["status"] == "READY"
    assert all(c["ok"] for c in body["checks"])
    assert {c["name"] for c in body["checks"]} == {
        "target", "scope", "authorization", "profile",
        "worker", "artifact_storage", "scope_compiler", "toolchain",
    }

    # Re-running on READY re-verifies idempotently.
    res2 = matrix_client.post(f"/api/v1/assessments/{aid}/preflight", headers=op_a)
    assert res2.status_code == 200
    assert res2.json()["ready"] is True

    # Full chain: authorized + preflighted starts.
    assert matrix_client.post(f"/api/v1/assessments/{aid}/start", headers=op_a).status_code == 202


def test_preflight_access_policy(matrix_client):
    op_a = _login(matrix_client, "op_A")
    op_b = _login(matrix_client, "op_B")
    val = _login(matrix_client, "val_1")
    aid = _make_assessment(matrix_client, op_a)

    # Mutation-class endpoint: owner or MANAGEMENT only.
    assert matrix_client.post(f"/api/v1/assessments/{aid}/preflight", headers=op_b).status_code == 404
    assert matrix_client.post(f"/api/v1/assessments/{aid}/preflight", headers=val).status_code == 404
    assert matrix_client.post(f"/api/v1/assessments/{aid}/preflight").status_code == 401


def test_preflight_rejected_after_execution_begins(matrix_client, monkeypatch):
    _mock_toolchain_ok(monkeypatch)
    op_a = _login(matrix_client, "op_A")
    aid = _make_assessment(matrix_client, op_a)
    matrix_client.post(f"/api/v1/assessments/{aid}/authorize", headers=op_a)
    matrix_client.post(f"/api/v1/assessments/{aid}/preflight", headers=op_a)
    assert matrix_client.post(f"/api/v1/assessments/{aid}/start", headers=op_a).status_code == 202

    res = matrix_client.post(f"/api/v1/assessments/{aid}/preflight", headers=op_a)
    assert res.status_code == 409
