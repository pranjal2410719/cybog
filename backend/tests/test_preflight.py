"""
T7: preflight check units (pure functions, no HTTP, no pipeline).
"""
import asyncio

from cybog.config.models import CybogConfig
from cybog.models.assessment import (
    Assessment,
    AssessmentStatus,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from cybog.models.target import Target, TargetStatus
from cybog.state.assessment_state import AssessmentState

from app.services import preflight as P


def _state(**overrides):
    assessment = Assessment(
        target_input_file="t.txt",
        scope_file="s.txt",
        status=overrides.get("status", AssessmentStatus.CREATED),
        scope=overrides.get("scope", Scope(patterns=["example.com"])),
        authorization=overrides.get("authorization", None),
        profile=overrides.get("profile", "quick"),
    )
    state = AssessmentState.create_new(assessment)
    for domain, tstatus in overrides.get("targets", [("example.com", TargetStatus.IN_SCOPE)]):
        target = Target(domain=domain)
        target.status = tstatus
        state.add_target(target)
    return state


def test_target_checks():
    assert P.check_target(_state(targets=[])).ok is False
    assert P.check_target(_state(targets=[("x.com", TargetStatus.OUT_OF_SCOPE)])).ok is False
    ok = P.check_target(_state())
    assert ok.ok is True and "example.com" in ok.detail


def test_scope_checks():
    assert P.check_scope(_state(scope=None)).ok is False
    assert P.check_scope(_state(scope=Scope(patterns=[]))).ok is False
    assert P.check_scope(_state()).ok is True


def test_authorization_checks():
    assert P.check_authorization(_state(authorization=None)).ok is False
    pending = Authorization(required=True, scope_file="s.txt",
                           status=AuthorizationStatus.PENDING)
    assert P.check_authorization(_state(authorization=pending)).ok is False
    nosha = Authorization(required=True, scope_file="s.txt",
                          status=AuthorizationStatus.AUTHORIZED,
                          authorized_by_user_id="u")
    assert P.check_authorization(_state(authorization=nosha)).ok is False
    full = Authorization(required=True, scope_file="s.txt",
                         status=AuthorizationStatus.AUTHORIZED,
                         authorized_by_user_id="u", scope_sha256="abc")
    assert P.check_authorization(_state(authorization=full)).ok is True


def test_profile_checks():
    assert P.check_profile(_state(profile="quick")).ok is True
    assert P.check_profile(_state(profile="standard")).ok is True
    assert P.check_profile(_state(profile="full")).ok is True
    bad = P.check_profile(_state(profile="turbo"))
    assert bad.ok is False and "turbo" in bad.detail


def test_worker_and_storage(tmp_path):
    assert P.check_worker(False).ok is True
    assert P.check_worker(True).ok is False

    class Cfg:
        class output:
            root = str(tmp_path / "new-root")
    assert P.check_storage(Cfg()).ok is True

    blocker = tmp_path / "file"
    blocker.write_text("x")

    class Cfg2:
        class output:
            root = str(blocker)
    assert P.check_storage(Cfg2()).ok is False


def test_scope_compiler_round_trip():
    state = _state()
    ok = P.check_scope_compiler(state)
    assert ok.ok is True
    # Pinned snapshot tampering is detected.
    tampered = Authorization(required=True, scope_file="s.txt",
                             status=AuthorizationStatus.AUTHORIZED,
                             authorized_by_user_id="u", scope_sha256="0" * 64)
    bad = P.check_scope_compiler(_state(authorization=tampered))
    assert bad.ok is False


def test_toolchain_reports_missing_binaries():
    config = CybogConfig()
    for tool in P.STAGE_TOOLS:
        getattr(config.tools, tool).binary = "definitely-not-a-real-tool"
        getattr(config.tools, tool).bin_dirs = []
    result = asyncio.run(P.check_toolchain(config, timeout_seconds=30.0))
    assert result.ok is False
    assert "subfinder" in result.detail and "nuclei" in result.detail


def test_as_dict_shape():
    d = P.as_dict(P.PreflightCheck(name="x", ok=True, detail="y"))
    assert d == {"name": "x", "ok": True, "detail": "y"}
