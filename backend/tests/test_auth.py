import pytest
from fastapi import HTTPException

from app.models.auth import AuditEvent, Role, User
from app.services.auth_service import (
    AuditLog,
    require_role,
)


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
