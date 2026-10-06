#!/usr/bin/env python3
"""
Run Alembic migrations programmatically.

Why: The SQLite file (`backend/data/cybog.db`) is created by the first
migration run. This script does the same thing that `alembic upgrade head`
does, but you can start it from any IDE with a *Run* button – no shell needed.
"""

import os
import sys
import pathlib
from logging.config import fileConfig

# ----------------------------------------------------------------------
# 1️⃣  Make sure the backend package is importable
# ----------------------------------------------------------------------
repo_root = pathlib.Path(__file__).resolve().parent
backend_path = repo_root / "backend"
os.environ["PYTHONPATH"] = str(backend_path)          # <- needed by the app’s imports
sys.path.insert(0, str(backend_path))

# ----------------------------------------------------------------------
# 2️⃣  Load Alembic configuration (the `alembic.ini` lives in the backend folder)
# ----------------------------------------------------------------------
from alembic.config import Config
from alembic import command

alembic_cfg_path = backend_path / "alembic.ini"
if not alembic_cfg_path.is_file():
    raise FileNotFoundError(f"Alembic config not found: {alembic_cfg_path}")

alembic_cfg = Config(str(alembic_cfg_path))

# Optional: if you have a logging config section in alembic.ini, enable it
if alembic_cfg.config_file_name:
    fileConfig(alembic_cfg.config_file_name)

# ----------------------------------------------------------------------
# 3️⃣  Run the migration (equivalent to `alembic upgrade head`)
# ----------------------------------------------------------------------
def run_migrations():
    """Apply all pending migrations – creates the SQLite file if it’s missing."""
    print("🔧 Running Alembic migrations …")
    command.upgrade(alembic_cfg, "head")
    print("✅ Migrations applied successfully.")
    # Show where the DB file ended up
    db_url = alembic_cfg.get_main_option("sqlalchemy.url")
    print(f"📂 DB URL from alembic.ini → {db_url}")

if __name__ == "__main__":
    run_migrations()
