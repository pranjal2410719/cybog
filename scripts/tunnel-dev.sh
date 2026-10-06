#!/usr/bin/env bash
#=====================================================================
# Cybog Development Tunnel
#
# This script prepares the environment, runs Alembic migrations,
# starts the FastAPI backend, and finally launches the Vite dev
# server for the React frontend.  All URLs are relative, so no
# external "tunnel" is needed – the frontend talks to http://localhost:8000.
#
# It is safe to run repeatedly; it will:
#   • Create the virtual‑env if missing
#   • Install required Python packages (requirements.txt)
#   • Apply any pending Alembic migrations (creates backend/data/cybog.db)
#   • Restart the backend if it is already running
#   • Start the frontend dev server (npm run dev)
#
#=====================================================================

set -euo pipefail

# ---------- 1. Resolve repo root (script may be called from any cwd) ----------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "📁 Repository root: $REPO_ROOT"

# ---------- 2. Activate (or create) the Python virtual‑env ----------
VENV_DIR="${REPO_ROOT}/backend/.venv"

if [[ ! -d "$VENV_DIR" ]]; then
    echo "🔧 Creating virtual‑env in $VENV_DIR …"
    python3 -m venv "$VENV_DIR"
fi

# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

# ---------- 3. Install / upgrade Python dependencies ----------
REQ_FILE="${REPO_ROOT}/backend/requirements.txt"
if [[ -f "$REQ_FILE" ]]; then
    echo "📦 Installing Python dependencies from $REQ_FILE …"
    pip install --upgrade pip setuptools wheel
    pip install -r "$REQ_FILE"
else
    echo "⚠️  requirements.txt not found – skipping pip install"
fi

# ---------- 4. Run Alembic migrations (creates backend/data/cybog.db) ----------
echo "🗄️  Applying Alembic migrations (idempotent)…"
mkdir -p "${REPO_ROOT}/backend/data"
python "${REPO_ROOT}/run_alembic.py"

# ---------- 5. Ensure the DB file exists (defensive check) ----------
DB_FILE="${REPO_ROOT}/backend/data/cybog.db"
if [[ ! -f "$DB_FILE" ]]; then
    echo "❌  Migration step should have created $DB_FILE but it is missing."
    echo "    aborting."
    exit 1
fi
echo "✅  SQLite DB ready at $DB_FILE"

# ---------- 6. Start / restart the FastAPI backend ----------
# We use `nohup` + `&` so the server runs in the background while we continue.
BACKEND_LOG="${REPO_ROOT}/backend/backend.log"

# Kill any previously started Uvicorn process (look for the exact command)
if pgrep -f "uvicorn app.main:app" > /dev/null; then
    echo "🛑  Stopping any previously‑running backend …"
    pkill -f "uvicorn app.main:app"
    # give it a moment to shut down cleanly
    sleep 2
fi

echo "🚀  Starting FastAPI backend (Uvicorn)…"
cd "${REPO_ROOT}/backend"
nohup uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    > "$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
echo "   → backend PID $BACKEND_PID (log: $BACKEND_LOG)"

# ---------- 7. Verify the backend is up (simple health‑check) ----------
MAX_RETRIES=10
RETRY_DELAY=1
echo -n "🔎  Waiting for backend health‑check …"
for ((i=1; i<=MAX_RETRIES; i++)); do
    if curl -s http://127.0.0.1:8000/health | grep -q '"status":"healthy"'; then
        echo " OK"
        break
    fi
    echo -n "."
    sleep $RETRY_DELAY
done
if (( i > MAX_RETRIES )); then
    echo -e "\n❌  Backend never responded to /health. Check $BACKEND_LOG"
    exit 1
fi

# ---------- 8. Launch the frontend dev server ----------
echo "⚡  Starting the React/Vite dev server …"
cd "${REPO_ROOT}/frontend"
# Install node deps if missing (idempotent)
if [[ ! -d "node_modules" ]]; then
    echo "   → npm install (first‑time setup)…"
    npm ci
fi

# Vite runs in foreground; when you stop the script the frontend also stops.
npm run dev
# When you exit the script (Ctrl‑C) the backend server will be killed automatically:
kill "$BACKEND_PID" 2>/dev/null || true
echo "🛑  Shutdown complete."
