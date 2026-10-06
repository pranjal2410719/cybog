"""
T6: server-side scope compiler.

Unit tests cover normalization/validation/canonicalization; API tests
cover structured create, input exclusivity, and the preview endpoint.
Overrides are fixture-scoped so module order cannot leak state.
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
from app.services.scope_compiler import ScopeCompileError, compile_scope


# ----------------------------------------------------------------------
# Unit: compiler
# ----------------------------------------------------------------------
def test_structured_basic():
    out = compile_scope(
        scope_include=["Example.COM ", "api.example.com", "example.com"],
        scope_exclude=["Admin.Example.COM"],
    )
    assert out.include == ["example.com", "api.example.com"]
    assert out.exclude == ["admin.example.com"]
    assert out.compiled == "example.com\napi.example.com\n!admin.example.com\n"
    assert len(out.sha256) == 64
    assert out.warnings == []


def test_overlap_warns_but_compiles():
    out = compile_scope(scope_include=["a.com"], scope_exclude=["a.com"])
    assert out.warnings == ["a.com is excluded by scope_exclude"]
    assert out.compiled == "a.com\n!a.com\n"


def test_wildcard_ip_cidr_accepted():
    out = compile_scope(scope_include=["*.example.com", "10.0.0.5", "203.0.113.0/24"])
    assert out.include == ["*.example.com", "10.0.0.5", "203.0.113.0/24"]


def test_invalid_patterns_rejected():
    for bad in ["!evil.com", "has space.com", "http://x.com/y", "", "   ",
                "a" * 254, "tab\there.com", "*."]:
        with pytest.raises(ScopeCompileError):
            compile_scope(scope_include=[bad])


def test_exclusivity_and_emptiness():
    with pytest.raises(ScopeCompileError):
        compile_scope(scope_file="a.com\n", scope_include=["a.com"])
    with pytest.raises(ScopeCompileError):
        compile_scope(scope_include=[], scope_exclude=[])
    with pytest.raises(ScopeCompileError):
        compile_scope()


def test_legacy_text_converges():
    out = compile_scope(scope_file="# comment\n\nExample.COM\n!Old.Example.COM\n")
    assert out.include == ["example.com"]
    assert out.exclude == ["old.example.com"]
    assert out.compiled == "example.com\n!old.example.com\n"


# ----------------------------------------------------------------------
# API: structured create + preview
# ----------------------------------------------------------------------
ENGINE = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
Session = sessionmaker(ENGINE, class_=AsyncSession, expire_on_commit=False)

PASSWORD = "scope-test-password"


async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with Session() as session:
        yield session


@pytest.fixture
def scope_client(tmp_path):
    prev_user = app.dependency_overrides.pop(get_current_user, None)
    prev_db = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = _override_get_db
    settings.CYBOG_OUTPUT_ROOT = str(tmp_path)
    try:
        async def _setup():
            async with ENGINE.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with Session() as session:
                session.add(DBUser(
                    id="s-uuid", uid="scope_op", name="S",
                    role=Role.OPERATOR, active=True,
                    password_hash=hash_password(PASSWORD)))
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


def _login(client):
    res = client.post("/api/v1/auth/login",
                      json={"uid": "scope_op", "password": PASSWORD})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['token']}"}


def test_create_with_structured_scope(scope_client):
    hdr = _login(scope_client)
    res = scope_client.post("/api/v1/assessments", json={
        "name": "Structured",
        "targets_file": "example.com\n",
        "scope_include": ["Example.COM", "api.example.com"],
        "scope_exclude": ["admin.example.com"],
        "profile": "quick",
    }, headers=hdr)
    assert res.status_code == 200, res.text
    aid = res.json()["assessment_id"]

    # The compiled scope gates and authorizes end to end.
    auth = scope_client.post(f"/api/v1/assessments/{aid}/authorize", headers=hdr)
    assert auth.status_code == 200, auth.text
    assert auth.json()["authorized"] is True
    assert len(auth.json()["scope_sha256"]) == 64


def test_create_rejects_mixed_and_invalid_scope(scope_client):
    hdr = _login(scope_client)
    base = {"name": "X", "targets_file": "example.com\n", "profile": "quick"}

    res = scope_client.post("/api/v1/assessments", json={
        **base, "scope_file": "example.com\n", "scope_include": ["example.com"],
    }, headers=hdr)
    assert res.status_code == 400

    res = scope_client.post("/api/v1/assessments", json={
        **base, "scope_include": ["http://evil/x"],
    }, headers=hdr)
    assert res.status_code == 400

    res = scope_client.post("/api/v1/assessments", json={
        **base, "scope_include": [],
    }, headers=hdr)
    assert res.status_code == 400


def test_preview_endpoint(scope_client):
    hdr = _login(scope_client)
    res = scope_client.post("/api/v1/assessments/scope/preview", json={
        "scope_include": ["Example.COM"],
        "scope_exclude": ["admin.example.com"],
    }, headers=hdr)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["include"] == ["example.com"]
    assert body["compiled"] == "example.com\n!admin.example.com\n"
    assert len(body["sha256"]) == 64

    res = scope_client.post("/api/v1/assessments/scope/preview", json={
        "scope_include": ["nope not a domain"],
    }, headers=hdr)
    assert res.status_code == 400

    res = scope_client.post("/api/v1/assessments/scope/preview", json={
        "scope_include": ["example.com"],
    })
    assert res.status_code == 401
