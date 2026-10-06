"""
T5: explicit human authorization at the engine layer.

- create() stamps PENDING (never AUTHORIZED).
- execute()/resume() refuse unconfirmed assessments via require_authorized.
- confirm_authorization() records actor/timestamp/pinned scope hash;
  it is idempotent and frozen once execution begins.
"""
import pytest

from cybog.config.models import CybogConfig
from cybog.models.assessment import AssessmentStatus, AuthorizationStatus
from cybog.services.assessment_service import AssessmentService


def _make_service(tmp_path):
    config = CybogConfig()
    config.output.root = str(tmp_path)
    return AssessmentService(config)


def _write_inputs(tmp_path, targets="example.com\n", scope="example.com\n"):
    targets_file = tmp_path / "targets.txt"
    scope_file = tmp_path / "scope.txt"
    targets_file.write_text(targets)
    scope_file.write_text(scope)
    return str(targets_file), str(scope_file)


def test_create_starts_pending(tmp_path):
    svc = _make_service(tmp_path)
    targets_file, scope_file = _write_inputs(tmp_path)
    state = svc.create(targets_file=targets_file, scope_file=scope_file,
                       profile="quick", owner_id="op-1")
    auth = state.assessment.authorization
    assert auth.status == AuthorizationStatus.PENDING
    assert auth.authorized_by_user_id is None
    assert auth.authorized_at is None
    assert auth.scope_sha256 is None


def test_execute_and_resume_refuse_unconfirmed(tmp_path):
    svc = _make_service(tmp_path)
    targets_file, scope_file = _write_inputs(tmp_path)
    state = svc.create(targets_file=targets_file, scope_file=scope_file,
                       profile="quick", owner_id="op-1")
    with pytest.raises(ValueError, match="human-authorized"):
        AssessmentService.require_authorized(state)


def test_confirm_records_attribution_and_pins_scope(tmp_path):
    svc = _make_service(tmp_path)
    targets_file, scope_file = _write_inputs(tmp_path)
    state = svc.create(targets_file=targets_file, scope_file=scope_file,
                       profile="quick", owner_id="op-1")
    aid = state.assessment.assessment_id

    confirmed = svc.confirm_authorization(aid, "op-1")
    auth = confirmed.assessment.authorization
    assert auth.status == AuthorizationStatus.AUTHORIZED
    assert auth.authorized_by_user_id == "op-1"
    assert auth.authorized_at is not None
    assert auth.scope_sha256 is not None and len(auth.scope_sha256) == 64
    assert auth.scope_snapshot["include"] == ["example.com"]
    assert auth.scope_snapshot["targets"] == ["example.com"]

    # Idempotent retry: same scope, same digest, no error.
    again = svc.confirm_authorization(aid, "op-1")
    assert again.assessment.authorization.scope_sha256 == auth.scope_sha256

    # The gate now passes.
    AssessmentService.require_authorized(again)


def test_confirm_frozen_after_execution_begins(tmp_path):
    svc = _make_service(tmp_path)
    targets_file, scope_file = _write_inputs(tmp_path)
    state = svc.create(targets_file=targets_file, scope_file=scope_file,
                       profile="quick", owner_id="op-1")
    aid = state.assessment.assessment_id
    svc.confirm_authorization(aid, "op-1")

    from cybog.artifacts.manager import ArtifactManager
    state.assessment.status = AssessmentStatus.RUNNING
    state.save(ArtifactManager(str(tmp_path), aid).state_path())

    with pytest.raises(ValueError, match="frozen"):
        svc.confirm_authorization(aid, "op-1")


def test_pre_t5_authorized_states_keep_working(tmp_path):
    """States stamped AUTHORIZED by the old create() still pass the gate."""
    svc = _make_service(tmp_path)
    targets_file, scope_file = _write_inputs(tmp_path)
    state = svc.create(targets_file=targets_file, scope_file=scope_file,
                       profile="quick", owner_id="op-1")
    state.assessment.authorization.status = AuthorizationStatus.AUTHORIZED
    AssessmentService.require_authorized(state)
