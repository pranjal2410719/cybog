from typing import AsyncGenerator

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.base import Base
from app.db.models import DBUser
from app.models.auth import AuditEvent, Role, User
from app.api.auth_routes import get_db, get_current_user
from app.services.auth_service import (
    AuditLog,
    generate_uid,
    require_role,
)
from app.services.passwords import hash_password, verify_password


def test_role_enum_has_three_roles():
    assert {r.value for r in Role} == {"OPERATOR", "VALIDATOR", "MANAGEMENT"}


def test_require_role_raises_403():
    operator = User(id="123", uid="USR-0001", name="x", role=Role.OPERATOR)
    with pytest.raises(HTTPException) as exc:
        require_role(operator, {Role.VALIDATOR})
    assert exc.value.status_code == 403


def test_audit_event_append_and_list(tmp_path):
    log = AuditLog(path=tmp_path / "audit.json")
    e = AuditEvent(actor_uid="USR-0001", action="assessment.create", resource="assessment:1")
    log.append(e)
    events = log.list()
    assert len(events) == 1
    assert events[0].action == "assessment.create"


def test_audit_filter_by_assessment_id(tmp_path):
    log = AuditLog(path=tmp_path / "audit.json")
    log.append(AuditEvent(actor_uid="USR-0001", action="assessment.create", resource="a:1", assessment_id="A1"))
    log.append(AuditEvent(actor_uid="USR-0024", action="finding.validate", resource="f:9", assessment_id="A2"))
    assert len(log.list(assessment_id="A1")) == 1
    assert log.list(assessment_id="A1")[0].assessment_id == "A1"


# --- T1: password hashing ---

def test_password_hash_roundtrip():
    h = hash_password("correct-horse-1234")
    assert h != "correct-horse-1234"
    assert verify_password("correct-horse-1234", h) is True


def test_password_wrong_password_fails():
    h = hash_password("correct-horse-1234")
    assert verify_password("wrong-password-000", h) is False


def test_password_none_or_malformed_hash_never_verifies():
    assert verify_password("anything-at-all", None) is False
    assert verify_password("anything-at-all", "not-a-hash") is False
    assert verify_password("", hash_password("x" * 12)) is False


def test_generate_uid_format_and_uniqueness():
    seen = set()
    for role, prefix in [(Role.OPERATOR, "op_"), (Role.VALIDATOR, "val_"), (Role.MANAGEMENT, "mg_")]:
        uid = generate_uid(role)
        assert uid.startswith(prefix)
        # 128 bits of entropy as lowercase hex (32 chars)
        assert len(uid) == len(prefix) + 32
        int(uid[len(prefix):], 16)
        seen.add(uid)
    assert len({generate_uid(Role.OPERATOR) for _ in range(10)}) == 10


# --- T1: login API (real auth; overrides are scoped to the fixture) ---

_LOGIN_ENGINE = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
_LoginSession = sessionmaker(_LOGIN_ENGINE, class_=AsyncSession, expire_on_commit=False)


async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with _LoginSession() as session:
        yield session


@pytest.fixture
def login_client():
    import asyncio

    # Scoped auth: drop the global mock and point get_db at an isolated
    # in-memory DB, restoring both afterwards so other modules are unaffected.
    prev_user = app.dependency_overrides.pop(get_current_user, None)
    prev_db = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = _override_get_db
    try:
        async def _setup():
            async with _LOGIN_ENGINE.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with _LoginSession() as session:
                session.add_all([
                    DBUser(id="u-ok", uid="op_login", name="Ok",
                           role=Role.OPERATOR, active=True,
                           password_hash=hash_password("login-password-1")),
                    DBUser(id="u-nopw", uid="op_nopw", name="NoPw",
                           role=Role.OPERATOR, active=True,
                           password_hash=None),
                    DBUser(id="u-off", uid="op_off", name="Off",
                           role=Role.OPERATOR, active=False,
                           password_hash=hash_password("login-password-2")),
                ])
                await session.commit()

        asyncio.run(_setup())
        with TestClient(app) as client:
            yield client
    finally:
        async def _teardown():
            async with _LOGIN_ENGINE.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)

        asyncio.run(_teardown())
        if prev_db is not None:
            app.dependency_overrides[get_db] = prev_db
        else:
            app.dependency_overrides.pop(get_db, None)
        if prev_user is not None:
            app.dependency_overrides[get_current_user] = prev_user


def test_login_success(login_client):
    res = login_client.post("/api/v1/auth/login",
                            json={"uid": "op_login", "password": "login-password-1"})
    assert res.status_code == 200
    body = res.json()
    assert body["token"]
    assert body["user"]["uid"] == "op_login"


def test_login_wrong_password_is_401(login_client):
    res = login_client.post("/api/v1/auth/login",
                            json={"uid": "op_login", "password": "wrong-password-x"})
    assert res.status_code == 401


def test_login_unknown_uid_is_401(login_client):
    res = login_client.post("/api/v1/auth/login",
                            json={"uid": "no_such_user", "password": "whatever-password"})
    assert res.status_code == 401


def test_login_without_password_set_is_401(login_client):
    res = login_client.post("/api/v1/auth/login",
                            json={"uid": "op_nopw", "password": "any-password-here"})
    assert res.status_code == 401


def test_login_inactive_user_is_401(login_client):
    res = login_client.post("/api/v1/auth/login",
                            json={"uid": "op_off", "password": "login-password-2"})
    assert res.status_code == 401


def test_login_role_card_mismatch_is_401(login_client):
    # Correct password, but the card selected the wrong role: the DB
    # record is authoritative, the card is not.
    res = login_client.post("/api/v1/auth/login", json={
        "uid": "op_login", "password": "login-password-1",
        "selected_role": "VALIDATOR",
    })
    assert res.status_code == 401
    assert "another role" in res.json()["detail"]


def test_login_role_card_match_succeeds(login_client):
    res = login_client.post("/api/v1/auth/login", json={
        "uid": "op_login", "password": "login-password-1",
        "selected_role": "OPERATOR",
    })
    assert res.status_code == 200
    assert res.json()["user"]["role"] == "OPERATOR"


def test_uid_alone_no_longer_authenticates(login_client):
    # The pre-T1 passwordless shape must be rejected (422: missing field).
    res = login_client.post("/api/v1/auth/login", json={"uid": "op_login"})
    assert res.status_code == 422


def test_logout_revokes_session(login_client):
    res = login_client.post("/api/v1/auth/login",
                            json={"uid": "op_login", "password": "login-password-1"})
    token = res.json()["token"]
    hdr = {"Authorization": f"Bearer {token}"}
    assert login_client.get("/api/v1/auth/me", headers=hdr).status_code == 200
    assert login_client.post("/api/v1/auth/logout", headers=hdr).status_code == 200
    assert login_client.get("/api/v1/auth/me", headers=hdr).status_code == 401
