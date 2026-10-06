import pytest
import asyncio
from typing import AsyncGenerator
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from pathlib import Path
import json
from datetime import datetime

from app.main import app
from app.db.base import Base
from app.db.models import DBUser
from app.models.auth import Role, AuditEvent
from app.api.auth_routes import get_db, get_current_user
from app.config import settings

# For direct state manipulation
from cybog.models.assessment import Assessment, AssessmentStatus
from cybog.models.finding import Finding, Severity, ValidationStatus
from cybog.state.assessment_state import AssessmentState

app.dependency_overrides.pop(get_current_user, None)

pytestmark = pytest.mark.asyncio

SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=False)
TestingSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with TestingSessionLocal() as session:
        yield session

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
def tmp_output(tmp_path):
    settings.CYBOG_OUTPUT_ROOT = str(tmp_path)
    yield tmp_path

@pytest.fixture
def client(tmp_output):
    with TestClient(app) as c:
        yield c

async def seed_users():
    async with TestingSessionLocal() as session:
        op = DBUser(id="op-uuid", uid="op_123", name="Op", role=Role.OPERATOR, active=True)
        op2 = DBUser(id="op2-uuid", uid="op_456", name="Op2", role=Role.OPERATOR, active=True)
        val = DBUser(id="val-uuid", uid="val_123", name="Val", role=Role.VALIDATOR, active=True)
        mg = DBUser(id="mg-uuid", uid="mg_123", name="Mgmt", role=Role.MANAGEMENT, active=True)
        session.add_all([op, op2, val, mg])
        await session.commit()

async def get_token(client, uid):
    res = client.post("/api/v1/auth/login", json={"uid": uid})
    return res.json()["token"]

async def test_e2e_lifecycle(client, tmp_output: Path):
    await seed_users()
    
    op_token = await get_token(client, "op_123")
    op2_token = await get_token(client, "op_456")
    val_token = await get_token(client, "val_123")
    mg_token = await get_token(client, "mg_123")

    op_hdr = {"Authorization": f"Bearer {op_token}"}
    op2_hdr = {"Authorization": f"Bearer {op2_token}"}
    val_hdr = {"Authorization": f"Bearer {val_token}"}
    mg_hdr = {"Authorization": f"Bearer {mg_token}"}

    # 1. Operator creates assessment
    res = client.post("/api/v1/assessments", json={
        "name": "E2E Test",
        "targets_file": "example.com\n",
        "scope_file": "example.com\n",
        "profile": "quick"
    }, headers=op_hdr)
    assert res.status_code == 200
    aid = res.json()["assessment_id"]

    # Target/Assessment Ownership - Operator 1 sees it, Operator 2 does not see it (it sees nothing since it has none)
    # Wait, the endpoint `/api/v1/assessments` only returns assessments owned by the user (if not MANAGEMENT)
    res_op = client.get("/api/v1/assessments", headers=op_hdr)
    assert res_op.json()[0]["assessment_id"] == aid

    res_op2 = client.get("/api/v1/assessments", headers=op2_hdr)
    assert len(res_op2.json()) == 0
    res_op2 = client.get(f"/api/v1/assessments/{aid}", headers=op2_hdr)
    # The get individual assessment endpoint doesn't seem to enforce ownership currently? 
    # Or wait, cybog API only has list endpoint. There is no GET /assessments/{aid} except status endpoints.

    # 2. Modify state to COMPLETED but not VERIFIED, add a finding
    state_file = tmp_output / aid / "state.json"
    with state_file.open("r") as f:
        state_data = json.load(f)
    
    # Inject finding and completion
    state_data["assessment"]["status"] = "AWAITING_VALIDATION"
    state_data["findings"] = {"f-1": {
        "finding_id": "f-1", "dedup_key": "f-1",
        "finding_type": "xss",
        "title": "XSS Test",
        "severity": "high",
        "target_id": "t-1",
        "target_domain": "example.com\n",
        "url": "http://example.com",
        "source_tool": "nuclei",
        "template_id": "xss",
        "description": "desc",
        "validation_status": "NEEDS_VALIDATION"
    }}
    with state_file.open("w") as f:
        json.dump(state_data, f)
        
    # 3. Verification invariant: AWAITING_VALIDATION != VERIFIED
    res = client.get("/api/v1/assessments", headers=op_hdr)
    assert res.status_code == 200
    astate = res.json()[0]
    assert astate["status"] == "AWAITING_VALIDATION"
    # Not automatically verified just because it's done scanning
    assert "VERIFIED" not in astate["status"]

    # 4. Validator confirms finding -> Validator Identity Attribution
    val_res = client.post(
        f"/api/v1/assessments/{aid}/findings/f-1/validate",
        json={"validation_type": "confirm", "notes": "looks good"},
        headers=val_hdr
    )
    assert val_res.status_code == 200
    
    # Read state to verify metadata recorded
    with state_file.open("r") as f:
        new_state = json.load(f)
    finding = new_state["findings"]["f-1"]
    assert finding["validation_status"] == "REPORTABLE"
    assert new_state["assessment"]["verified_by_user_id"] == "val-uuid"

    # 5. Download Authorization and Formats
    for filename in ["report_verified.json", "report_verified.html", "report_verified.pdf", "findings_verified.jsonl", "report.pdf", "report.json"]:
        # Operator 2 tries to download (403)
        d2 = client.get(f"/api/v1/assessments/{aid}/reports/{filename}", headers=op2_hdr)
        assert d2.status_code == 403
        
        # Operator 1 tries to download (200)
        d1 = client.get(f"/api/v1/assessments/{aid}/reports/{filename}", headers=op_hdr)
        assert d1.status_code == 200, f"{filename} failed: {d1.text}"
        
        if filename.endswith(".pdf"):
            assert d1.headers["Content-Type"] == "application/pdf"
            assert len(d1.content) > 0
            assert d1.content.startswith(b"%PDF-")
            
        # Verify it's a regular file, not a symlink (the backend route would have failed with 400 if it was a symlink, but we double check)
        file_path = tmp_output / aid / "aggregate" / filename
        assert file_path.exists()
        assert file_path.is_file()
        assert not file_path.is_symlink()

    # Management tries to download (200)
    dmg = client.get(f"/api/v1/assessments/{aid}/reports/report_verified.json", headers=mg_hdr)
    assert dmg.status_code == 200
    
    # 6. Check malicious traversal
    d_trav = client.get(f"/api/v1/assessments/{aid}/reports/../state.json", headers=op_hdr)
    assert d_trav.status_code in (400, 404)
    
    # 7. Check malicious symlink attack
    malicious_symlink = tmp_output / aid / "aggregate" / "malicious.json"
    import os
    os.symlink("/etc/passwd", malicious_symlink)
    d_sym = client.get(f"/api/v1/assessments/{aid}/reports/malicious.json", headers=op_hdr)
    # The API should reject this! It might return 404 (because it's not a KNOWN_REPORT_FILES) or 400.
    assert d_sym.status_code in (400, 404)
    
    # Let's bypass KNOWN_REPORT_FILES by replacing an existing report file with a symlink!
    # e.g., overwrite report_unverified.json (which we aren't testing in the loop above) with a symlink
    report_unverified = tmp_output / aid / "aggregate" / "report_unverified.json"
    if report_unverified.exists():
        report_unverified.unlink()
    os.symlink("/etc/passwd", report_unverified)
    d_sym_known = client.get(f"/api/v1/assessments/{aid}/reports/report_unverified.json", headers=op_hdr)
    assert d_sym_known.status_code == 400  # "Report file must not be a symlink"
    
    # Download Audit
    # Let's check audit_log.json!
    from app.services.auth_service import AUDIT_LOG_PATH
    with open(AUDIT_LOG_PATH, "r") as f:
        audits = json.load(f)
    download_audits = [a for a in audits if a["action"] == "REPORT_DOWNLOADED" and a["assessment_id"] == aid]
    assert len(download_audits) == 7  # 6 files downloaded by op1 + 1 by mgmt
