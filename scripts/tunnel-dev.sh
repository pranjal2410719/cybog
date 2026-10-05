#!/usr/bin/env bash
#
# tunnel-dev.sh — publish the Vite dev server through ONE Cloudflare
# quick tunnel.
#
# SECURITY NOTICE: this publishes a Vite dev server. Source files, source
# maps, and environment variables are reachable by anyone holding the URL.
# The hardening path is `dist` + `vite preview` (not implemented here).
#
# Architecture: a single tunnel points at the Vite dev server
# (0.0.0.0:5173). The backend (uvicorn on 127.0.0.1:8000) stays
# PRIVATE and is never tunneled: the browser reaches it through the
# Vite dev proxy (`server.proxy` in vite.config.ts) at /api/v1 on the
# SAME host, so no CORS allowlist and no second public hostname are
# needed.
#
# Quick tunnels are EPHEMERAL: cloudflared assigns a random
# <random>.trycloudflare.com hostname on every start. The frontend uses
# same-origin relative URLs, so a fresh hostname needs no repointing.
#
# Testing only. The tunnel is unauthenticated.
#
# Usage:
#   scripts/tunnel-dev.sh        start servers + the single tunnel
#   scripts/tunnel-dev.sh stop   tear everything down
#   scripts/tunnel-dev.sh status show the public URL from the last run

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${CYBOG_TUNNEL_RUN_DIR:-/tmp/cybog-tunnel}"
BE_PORT=8000
FE_PORT=5173

mkdir -p "$RUN_DIR"

C_INFO=$'\033[1;34m==>\033[0m'
C_ERR=$'\033[1;31mERROR:\033[0m'
log() { printf '%s %s\n' "$C_INFO" "$*"; }
die() { printf '%s %s\n' "$C_ERR" "$*" >&2; exit 1; }

# cloudflared announces its assigned hostname inside a boxed banner on
# stderr; both streams are captured in the log file.
wait_for_tunnel_url() { # <logfile> <label> <pid>
  local logfile="$1" label="$2" pid="$3" i url=""
  for ((i = 0; i < 120; i++)); do
    url="$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$logfile" 2>/dev/null | head -n1 || true)"
    if [[ -n "$url" ]]; then printf '%s' "$url"; return 0; fi
    kill -0 "$pid" 2>/dev/null || die "$label tunnel exited early — see $logfile"
    sleep 0.5
  done
  die "$label tunnel never reported a hostname — see $logfile"
}

wait_for_http() { # <url> <label>
  local url="$1" label="$2" i
  for ((i = 0; i < 60; i++)); do
    curl -fsS -o /dev/null --max-time 2 "$url" && return 0
    sleep 0.5
  done
  die "$label never became reachable at $url"
}

# First connection through a new quick tunnel can take a few seconds
# while the Cloudflare edge warms up, so public checks get their own
# generous retry.
check_public() { # <url>
  local url="$1" i
  for ((i = 0; i < 20; i++)); do
    curl -fsS -o /dev/null --max-time 10 "$url" && return 0
    sleep 1
  done
  return 1
}

port_listening() { # <port>
  lsof -t -i:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

kill_port() { # <port>
  local pids i
  pids="$(lsof -t -i:"$1" -sTCP:LISTEN 2>/dev/null || true)"
  [[ -z "$pids" ]] && return 0
  log "stopping listener(s) on port $1 (pids: $pids)"
  kill $pids 2>/dev/null || true
  for ((i = 0; i < 20; i++)); do
    lsof -t -i:"$1" -sTCP:LISTEN >/dev/null 2>&1 && sleep 0.25 || return 0
  done
  kill -9 $pids 2>/dev/null || true
  sleep 1
}

# The frontend must keep the same-origin relative values: only the Vite
# dev server is published, so /api/v1 is reached on the SAME host via
# the dev proxy. The obsolete form rewrote this file with absolute
# *.trycloudflare.com URLs on every run — that is gone.
validate_env_local() {
  if grep -q '^VITE_API_BASE_URL=/api/v1' "$ROOT/frontend/.env.local" &&
     grep -q '^VITE_WS_BASE_URL=/$' "$ROOT/frontend/.env.local"; then
    return 0
  fi
  die "frontend/.env.local must hold the same-origin relative values.
The absolute *.trycloudflare.com form is obsolete: the backend is never
tunneled, and the frontend reaches it through the Vite dev proxy on the
same host. The file must contain these two lines:

    VITE_API_BASE_URL=/api/v1
    VITE_WS_BASE_URL=/"
}

# Start the backend and the Vite dev server only if they are not
# already listening. The backend binds 127.0.0.1 only — it must stay
# private — and is started WITHOUT CORS_ORIGINS and WITHOUT --reload.
# Vite binds 0.0.0.0: it is the one process the tunnel publishes.
ensure_running() {
  if port_listening "$BE_PORT"; then
    log "backend already listening on port $BE_PORT (127.0.0.1)"
  else
    log "starting backend on 127.0.0.1:$BE_PORT"
    (
      cd "$ROOT/backend"
      nohup python3 -m uvicorn app.main:app \
        --host 127.0.0.1 --port "$BE_PORT" \
        >"$RUN_DIR/uvicorn.log" 2>&1 &
    )
    wait_for_http "http://localhost:$BE_PORT/health" "backend /health"
  fi

  if port_listening "$FE_PORT"; then
    log "Vite dev server already listening on port $FE_PORT (0.0.0.0)"
  else
    log "starting Vite dev server on 0.0.0.0:$FE_PORT"
    (
      cd "$ROOT/frontend"
      nohup npm run dev >"$RUN_DIR/vite.log" 2>&1 &
    )
    wait_for_http "http://localhost:$FE_PORT/" "Vite dev server"
  fi
}

stop_tunnel() {
  local pid
  if [[ -f "$RUN_DIR/tunnel.pid" ]]; then
    pid="$(cat "$RUN_DIR/tunnel.pid" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      log "stopping cloudflared tunnel (pid $pid)"
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$RUN_DIR/tunnel.pid"
  fi
}

case "${1:-start}" in
  stop)
    stop_tunnel
    kill_port "$BE_PORT"
    kill_port "$FE_PORT"
    log "stopped: tunnel closed, backend and Vite dev server down."
    exit 0
    ;;
  status)
    if [[ -f "$RUN_DIR/frontend.url" ]]; then
      log "frontend: $(cat "$RUN_DIR/frontend.url")"
    else
      log "frontend: no URL recorded — run scripts/tunnel-dev.sh start"
    fi
    exit 0
    ;;
  start) ;;
  *) die "unknown command '$1' (use: start | stop | status)" ;;
esac

# ── Preflight: fail fast if the toolchain is broken ─────────────────────
# The healthcheck exits non-zero when any compiled Go binary is shadowed by
# a script of the same name (the httpx binary-collision bug class). Passing
# here means every tool in config.yaml resolved to a compiled ELF/Mach-O.
log "running toolchain preflight..."
python3 -m cybog.cli.main healthcheck --config "$ROOT/cybog/config.yaml" \
  || die "toolchain healthcheck failed — run $ROOT/cybog/setup.sh to repair"

# Python runtime + cybog package
python3 -c "import cybog, fastapi" \
  || die "Python deps missing — run: cd $ROOT/cybog && ./setup.sh"

# Frontend deps (Vite dev server needs node_modules)
if [[ ! -d "$ROOT/frontend/node_modules" ]]; then
  die "frontend/node_modules is missing — run: cd $ROOT/frontend && npm install"
fi

for bin in cloudflared lsof curl node npm python3; do
  command -v "$bin" >/dev/null || die "required command not found: $bin"
done

# ── 0. Clear an aborted run's leftovers ────────────────────────────────
# A previous (possibly interrupted) run may have left a live tunnel plus
# stale *.pid / *.url / *.log files. Kill the old tunnel first so a
# rerun never ends up with two cloudflared processes, then clear the
# leftovers so they cannot confuse this run. *.url files are intentionally
# preserved so `status` still works after a failed start.
if [[ -f "$RUN_DIR/tunnel.pid" ]]; then
  old_pid="$(cat "$RUN_DIR/tunnel.pid" 2>/dev/null || true)"
  if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
    log "stopping tunnel left over from a previous run (pid $old_pid)"
    kill "$old_pid" 2>/dev/null || true
  fi
fi
rm -f "$RUN_DIR"/*.pid "$RUN_DIR"/*.log

# ── 1. Validate frontend/.env.local (never rewrite it) ─────────────────
validate_env_local

# ── 2. Backend + Vite, only if not already running ─────────────────────
ensure_running

# ── 3. The single tunnel → Vite dev server ONLY ────────────────────────
# The backend on 127.0.0.1:8000 is deliberately NOT tunneled.
log "starting the tunnel -> http://localhost:$FE_PORT"
cloudflared tunnel --no-autoupdate --url "http://localhost:$FE_PORT" \
  >"$RUN_DIR/tunnel.log" 2>&1 &
echo $! >"$RUN_DIR/tunnel.pid"
TUNNEL_PID="$(cat "$RUN_DIR/tunnel.pid")"
FE_URL="$(wait_for_tunnel_url "$RUN_DIR/tunnel.log" frontend "$TUNNEL_PID")"
printf '%s' "$FE_URL" >"$RUN_DIR/frontend.url"
log "frontend tunnel: $FE_URL"

# ── 4. Verify the tunnel actually serves traffic ───────────────────────
log "verifying the public endpoint (Cloudflare edge may take a moment)"
check_public "$FE_URL/" || die "frontend not reachable via $FE_URL/"

cat <<EOF

───────────────────────────────────────────────────
  frontend : $FE_URL
  backend  : private on 127.0.0.1:$BE_PORT (reached via the
             Vite dev proxy at /api/v1 — never tunneled)
  logs     : $RUN_DIR
───────────────────────────────────────────────────
  open the FRONTEND url. It already points at the backend.

  tear down:  scripts/tunnel-dev.sh stop
  rerun:      scripts/tunnel-dev.sh  (new random URL each time —
              harmless now: the frontend uses relative URLs)
───────────────────────────────────────────────────
EOF
