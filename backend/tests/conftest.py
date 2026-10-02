"""
Make the ``app`` package importable when pytest is invoked bare.

Without this, ``python -m pytest`` works only because cwd lands on sys.path;
``pytest`` does not, and collection fails with ``ModuleNotFoundError: app``.
"""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))