"""
Make the ``app`` package importable when pytest is invoked bare.

Without this, ``python -m pytest`` works only because cwd lands on sys.path;
``pytest`` does not, and collection fails with ``ModuleNotFoundError: app``.
"""
from __future__ import annotations

import sys
from pathlib import Path
import pytest
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
from app.models.auth import User, Role

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.main import app
from app.api.auth_routes import get_current_user

# Global mock for tests that do not test auth logic directly.
# `test_e2e_lifecycle.py` and `test_auth.py` will remove this override if they need to test real auth.
def mock_get_current_user() -> User:
    return User(
        id="test-internal-id",
        uid="op_12345",
        name="Test User",
        role=Role.OPERATOR,
        active=True
    )

app.dependency_overrides[get_current_user] = mock_get_current_user
