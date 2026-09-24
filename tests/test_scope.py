import pytest
from cybog.models.target import Target
from cybog.models.assessment import Scope
from cybog.scope.validator import ScopeValidator

def test_scope_validation(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("*.example.com\nexample.com\n!admin.example.com\n")
    validator = ScopeValidator(str(scope_file))
    scope = validator.load_scope()

    # In scope
    t1 = Target(domain="api.example.com")
    auth1, reason1 = validator.validate_target(t1, scope)
    assert auth1 is True

    t2 = Target(domain="example.com")
    auth2, reason2 = validator.validate_target(t2, scope)
    assert auth2 is True

    # Out of scope: explicit exclude
    t3 = Target(domain="admin.example.com")
    auth3, reason3 = validator.validate_target(t3, scope)
    assert auth3 is False

    # Out of scope: outside pattern
    t4 = Target(domain="attacker.org")
    auth4, reason4 = validator.validate_target(t4, scope)
    assert auth4 is False
