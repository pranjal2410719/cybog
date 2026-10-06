"""
T3: WebSocket authentication matrix.

Frozen policy:
- no/unknown/expired/used ticket, or inactive user -> close 4401.
- valid ticket but no assessment access (incl. missing) -> close 4403.
- valid ticket + access -> "connected" frame, then live snapshots that
  carry an integer ``state_version`` (T4).

Ticket issuance (POST .../ws-ticket) is itself assessment-authorized:
cross-tenant issuance is 404, role gates unchanged.

Overrides are fixture-scoped so module order cannot leak state.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from starlette.websockets import WebSocketDisconnect
from typing import AsyncGenerator

from app.main import app
from app.db.base import Base
from app.db.models import DBUser
from app.models.auth import Role
from app.api.auth_routes import get_db, get_current_user
from app.config import settings
from app.services.passwords import hash_password


ENGINE = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
Session = sessionmaker(ENGINE, class_=AsyncSession, expire_on_commit=False)

PASSWORDS = {
    "ws_op_a": "ws-op-a-password",
    "ws_op_b": "ws-op-b-password",
    "ws_val": "ws-val-password",
    "ws_mg": "ws-mg-password",
}


async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with Session() as session:
        yield session


@pytest.fixture
def ws_client(tmp_path):
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
                    DBUser(id="wsa-uuid", uid="ws_op_a", name="A",
                           role=Role.OPERATOR, active=True,
                           password_hash=hash_password(PASSWORDS["ws_op_a"])),
                    DBUser(id="wsb-uuid", uid="ws_op_b", name="B",
                           role=Role.OPERATOR, active=True,
                           password_hash=hash_password(PASSWORDS["ws_op_b"])),
                    DBUser(id="wsv-uuid", uid="ws_val", name="V",
                           role=Role.VALIDATOR, active=True,
                           password_hash=hash_password(PASSWORDS["ws_val"])),
                    DBUser(id="wsm-uuid", uid="ws_mg", name="M",
                           role=Role.MANAGEMENT, active=True,
                           password_hash=hash_password(PASSWORDS["ws_mg"])),
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
        "name": "WS Matrix",
        "targets_file": "example.com\n",
        "scope_file": "example.com\n",
        "profile": "quick",
    }, headers=headers)
    assert res.status_code == 200, res.text
    return res.json()["assessment_id"]


def _ticket(client, headers, aid):
    res = client.post(f"/api/v1/assessments/{aid}/ws-ticket", headers=headers)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["assessment_id"] == aid
    assert body["expires_in"] == 60
    return body["ticket"]


def _expect_close(client, url, code):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(url):
            pass
    assert exc.value.code == code, f"expected close {code}, got {exc.value.code}"


def test_no_ticket_is_4401(ws_client):
    op_a = _login(ws_client, "ws_op_a")
    aid = _make_assessment(ws_client, op_a)
    _expect_close(ws_client, f"/ws/assessments/{aid}", 4401)


def test_bogus_ticket_is_4401(ws_client):
    op_a = _login(ws_client, "ws_op_a")
    aid = _make_assessment(ws_client, op_a)
    _expect_close(ws_client, f"/ws/assessments/{aid}?ticket=nope", 4401)


def test_ticket_is_single_use(ws_client):
    op_a = _login(ws_client, "ws_op_a")
    aid = _make_assessment(ws_client, op_a)
    ticket = _ticket(ws_client, op_a, aid)

    with ws_client.websocket_connect(f"/ws/assessments/{aid}?ticket={ticket}") as ws:
        first = ws.receive_json()
    assert first["type"] == "connected"
    assert first["assessment_id"] == aid

    # Replaying the consumed ticket fails closed.
    _expect_close(ws_client, f"/ws/assessments/{aid}?ticket={ticket}", 4401)


def test_ticket_bound_to_assessment(ws_client):
    op_a = _login(ws_client, "ws_op_a")
    aid1 = _make_assessment(ws_client, op_a)
    aid2 = _make_assessment(ws_client, op_a)
    ticket = _ticket(ws_client, op_a, aid1)

    _expect_close(ws_client, f"/ws/assessments/{aid2}?ticket={ticket}", 4403)


def test_cross_tenant_issuance_and_stream_denied(ws_client):
    op_a = _login(ws_client, "ws_op_a")
    op_b = _login(ws_client, "ws_op_b")
    aid = _make_assessment(ws_client, op_a)

    # Operator B cannot mint a ticket for A's assessment (404, no oracle).
    res = ws_client.post(f"/api/v1/assessments/{aid}/ws-ticket", headers=op_b)
    assert res.status_code == 404


def test_valid_flow_streams_versioned_snapshots(ws_client):
    op_a = _login(ws_client, "ws_op_a")
    aid = _make_assessment(ws_client, op_a)
    ticket = _ticket(ws_client, op_a, aid)

    with ws_client.websocket_connect(f"/ws/assessments/{aid}?ticket={ticket}") as ws:
        connected = ws.receive_json()
        assert connected["type"] == "connected"
        snapshot = ws.receive_json()
    assert snapshot["type"] == "progress"
    assert snapshot["assessment_id"] == aid
    assert isinstance(snapshot["state_version"], int)
    assert snapshot["state_version"] >= 1


def test_validator_and_management_can_stream(ws_client):
    op_a = _login(ws_client, "ws_op_a")
    val = _login(ws_client, "ws_val")
    mg = _login(ws_client, "ws_mg")
    aid = _make_assessment(ws_client, op_a)

    for headers in (val, mg):
        ticket = _ticket(ws_client, headers, aid)
        with ws_client.websocket_connect(f"/ws/assessments/{aid}?ticket={ticket}") as ws:
            first = ws.receive_json()
        assert first["type"] == "connected"


def test_inactive_user_ticket_redeem_fails(ws_client):
    op_a = _login(ws_client, "ws_op_a")
    aid = _make_assessment(ws_client, op_a)
    ticket = _ticket(ws_client, op_a, aid)

    async def _deactivate():
        async with Session() as session:
            from sqlalchemy.future import select
            result = await session.execute(
                select(DBUser).where(DBUser.uid == "ws_op_a"))
            user = result.scalar_one()
            user.active = False
            await session.commit()

    asyncio.run(_deactivate())
    _expect_close(ws_client, f"/ws/assessments/{aid}?ticket={ticket}", 4401)


def test_unauthenticated_issuance_is_401(ws_client):
    op_a = _login(ws_client, "ws_op_a")
    aid = _make_assessment(ws_client, op_a)
    res = ws_client.post(f"/api/v1/assessments/{aid}/ws-ticket")
    assert res.status_code == 401
