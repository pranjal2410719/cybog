# Cybor — Cybog Security Assessment Platform

Browser-based control interface for the **Cybog** security-assessment pipeline.

Cybog runs an 8-stage authorized assessment pipeline against targets you are
**permitted to test**, tracks every finding through a human-validation
lifecycle, and generates reports plus per-target export archives.

```
React / Vite  ──REST + WebSocket──▶  FastAPI Backend  ──▶  Cybog Runtime
                                                              │
                                                              ▼
                                                       JobScheduler
                                                              │
                                                              ▼
                                              subfinder → dnsx → httpx
                                                     → naabu → katana
                                                     → ffuf  → nuclei
                                                     → auth validation
```

The browser is **only** a control plane. It never executes a scanner, never
builds a shell command, and never touches Cybog state files directly.

---

## ⚠️ Authorized use only

This tool actively probes hosts (port scanning, crawling, template-based
vulnerability scanning). **Only run it against systems you own or have explicit
written authorization to assess.** Scanning without authorization is illegal in
most jurisdictions. The `scope_file` mechanism exists to enforce this — use it.

---

## 1. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | **3.10+** | Required by both `cybog` and `backend` |
| Node.js / npm | not pinned | Vite 5.x toolchain |
| OS | **Debian / Ubuntu / Kali** | `setup.sh` requires `apt-get` |
| Go | 1.21+ | Installed by `setup.sh` if absent |
| Internet | required at setup | Downloads tools, nuclei templates, wordlists |
| sudo | required at setup | Only if Go is missing |

---

## 2. Quick start

```bash
git clone <your-repo-url> cybor
cd cybor

# 1. Install Go toolchain + all 7 security tools + Python deps (~5–15 min)
./cybog/setup.sh

# 2. Copy the example configs and fix machine-specific paths  ← REQUIRED, see §4
cp cybog/config.example.yaml cybog/config.yaml
cp backend/.env.example backend/.env          # CYBOG_CONFIG_PATH, CYBOG_OUTPUT_ROOT
cp frontend/.env.example frontend/.env.local
$EDITOR cybog/config.yaml backend/.env

# 3. Verify the toolchain
cd cybog && cybog healthcheck

# 4. Start the backend API
cd ../backend && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 5. Start the frontend (separate terminal)
cd frontend && npm install && npm run dev     # → http://localhost:5173
```

### What `setup.sh` actually does

Runs these steps in order:

1. **Go toolchain** — if `go` is absent, runs `sudo apt-get update && sudo apt-get install -y golang-go git curl jq`.
2. **PATH** — adds `$HOME/go/bin` and `$HOME/.local/bin` to `PATH`, appending to `~/.bashrc` / `~/.zshrc` if missing.
3. **Security tools** — `go install ...@latest` for subfinder, dnsx, httpx, naabu, katana, ffuf, nuclei.
4. **Nuclei templates** — `nuclei -update-templates -silent`.
5. **Wordlist** — downloads SecLists `raft-small-words.txt` to `cybog/config/wordlists/common.txt`, falling back to a small builtin list if the fetch fails.
6. **Python** — `pip install --user -r requirements.txt` then `pip install --user -e .`
7. **Verify** — runs `cybog tools` healthcheck.

**Caveats — read before trusting it:**
- **Tool versions are NOT pinned.** All 7 install at `@latest`, so two machines
  one month apart can get different scanner versions and different JSON output.
- Nuclei templates and the wordlist are re-downloaded from the network, unpinned.
- Requires `sudo` when Go is missing.
- Partially idempotent — existing tools are skipped, but nuclei templates are
  re-fetched on every run.

---

## 3. Repository layout

```
cybor/
├── cybog/                 # Unit 1 — core pipeline library + CLI
│   ├── cybog/             #   Python package
│   │   ├── adapters/      #     8 scanner adapters
│   │   ├── workflow/      #     JobScheduler + PipelineRouter
│   │   ├── models/        #     Finding lifecycle, targets, jobs
│   │   ├── state/         #     AssessmentState (source of truth)
│   │   ├── queue/         #     analyst task queue
│   │   └── reporting/     #     JSON / JSONL / HTML reporters
│   ├── config/            #   config.yaml, wordlists/
│   ├── tests/             #   engine tests
│   └── setup.sh           #   toolchain installer
├── backend/               # Unit 2 — FastAPI control plane
│   ├── app/
│   │   ├── api/routes.py  #     REST + report routes
│   │   ├── services/      #     export, progress snapshot, integration
│   │   └── main.py        #     app + WebSocket progress push
│   ├── tests/             #   backend tests
│   └── .env.example       #   copy to `.env` and edit (`.env` is untracked)
├── frontend/              # Unit 3 — React + Vite SPA
│   ├── src/api/           #   centralized API layer (single source of truth)
│   ├── src/components/    #   dashboard, form, detail views
│   └── .env.example       #   copy to `.env.local` (untracked)
├── docs/                  #   DEVELOPER_GUIDE + cybog-engine deep-dive
│   ├── DEVELOPER_GUIDE.md
│   └── cybog-engine.md
└── reports/               # default assessment output root (untracked)
```

> `frontend/dist/`, `*/reports/`, `node_modules/`, `__pycache__/` and
> local `.env` files are build outputs / machine-local state — all ignored,
> never committed.

---

## 4. Configuration — the two things you MUST change

### 4.1 `cybog/config.yaml`

Most settings work as-is on a fresh clone. All tool binaries resolve via
`PATH` (including `httpx`) — if a tool lives outside your `PATH`, set its
`binary` to the absolute path:

```yaml
tools:
  httpx:
    binary: httpx   # or e.g. /home/you/go/bin/httpx if not on PATH
```

Other keys worth knowing:

| Key | Meaning |
|---|---|
| `tools.<name>.enabled` | Skip a stage entirely |
| `tools.<name>.timeout` | Per-stage seconds before kill |
| `tools.<name>.extra_args` | Extra CLI flags appended to the command |
| `tools.ffuf.wordlist` | Fuzzing wordlist path — see the warning below |
| `tools.nuclei.severity` | Comma-separated severity filter |
| `execution.continue_on_error` | Keep going when a stage fails |
| `execution.retry_failed` | Retry count for failed stages |
| `output.root` | Where assessment artifacts are written |

> **Relative paths in this file are resolved against the directory containing
> `config.yaml`**, not against your shell's working directory. So
> `./config/wordlists/common.txt` means
> `<repo>/cybog/config/wordlists/common.txt` whether you launch the CLI from
> `cybog/` or the API server from `backend/`. Absolute paths are used as-is.

> ⚠️ **The bundled ffuf wordlist is a 10-line placeholder** — `admin`, `login`,
> `api`, `v1`, `v2`, `health`, `dashboard`, `metrics`, `test`, `staging`. It
> exists so the stage is runnable, not because it is useful. The fuzzing stage
> is effectively a no-op until you point `tools.ffuf.wordlist` at a real
> wordlist (e.g. SecLists).

> Copy `cybog/config.example.yaml` to `cybog/config.yaml` for local use.
> The committed example uses portable defaults — keep machine-specific
> paths in your untracked local copy, never in git.

### 4.2 `backend/.env`

```bash
# Copy backend/.env.example to backend/.env (untracked). The backend also
# resolves correct repo-relative defaults on its own, so this file is only
# needed when you want to override:
CYBOG_RUNTIME=development
CYBOG_CONFIG_PATH=/path/to/cybor/cybog/config.yaml
CYBOG_OUTPUT_ROOT=/path/to/cybor/cybog/reports
API_HOST=0.0.0.0
API_PORT=8000
API_RELOAD=true
```

| Variable | Purpose |
|---|---|
| `CYBOG_CONFIG_PATH` | Which `config.yaml` the backend loads |
| `CYBOG_OUTPUT_ROOT` | Where the backend reads/writes assessments |
| `CORS_ORIGINS` | Allowed browser origins (defaults include `localhost:5173`) |

`CYBOG_CONFIG_PATH` and `CYBOG_OUTPUT_ROOT` **must point at your local paths**,
or the dashboard will show zero assessments.

Precedence is the standard: real environment variable > `.env` file > built-in
default. `CYBOG_OUTPUT_ROOT` overrides `output.root` from `config.yaml`, which
is what keeps the backend reading the same assessments no matter which directory
it was launched from.

> **Fixed during development:** these settings were previously a plain
> `pydantic.BaseModel`, where the `env_file` key is inert. Neither the
> environment nor `.env` was read at all, and `CYBOG_OUTPUT_ROOT` was logged at
> startup while having no effect. If your dashboard ever shows an unexpected
> number of assessments, check which root is actually in play.

### 4.3 `frontend/.env.local`

```bash
VITE_API_BASE_URL=http://localhost:8000/api/v1
VITE_WS_BASE_URL=ws://localhost:8000/ws
```

Both are read in exactly one place, `frontend/src/api/config.ts`. **Never put a
secret in a `VITE_*` variable** — Vite inlines them into the public browser
bundle. Backend secrets stay backend-side.

There is deliberately **no Vite dev proxy**: the frontend talks to the backend
directly and CORS handles it, so dev and production share one code path.

---

## 5. Using the CLI

The console script `cybog` maps to `cybog.cli.main:app` (Typer).

```bash
cd cybog

cybog healthcheck                      # verify binaries + config
cybog tools                            # per-tool availability/version

# Create → execute → report
cybog create  -t targets.txt -s authorized_scope.txt -p standard
cybog execute <ASSESSMENT_ID>
cybog status   <ASSESSMENT_ID>
cybog findings <ASSESSMENT_ID>
cybog report   <ASSESSMENT_ID>         # --wait by default

# Interrupted runs
cybog resume <ASSESSMENT_ID>

# Human validation plane
cybog pending <ASSESSMENT_ID>         # findings needing a decision
cybog confirm <ASSESSMENT_ID>         # VALIDATED → REPORTABLE
cybog reject  <ASSESSMENT_ID>         # VALIDATING → FALSE_POSITIVE

cybog cancel <ASSESSMENT_ID>
```

Common flags: `-c/--config` (default `config.yaml`), `-p/--profile`
(`standard|quick`), `--output` (override output root).

### The finding lifecycle

Findings are **candidates** until validated. Statuses only move along allowed
transitions; anything else is rejected by `Finding.transition_to()`.

```
DISCOVERED → NEEDS_VALIDATION → VALIDATING → VALIDATED → REPORTABLE
                                        └───▶ FALSE_POSITIVE
```

A finding that cannot be judged automatically stays `NEEDS_VALIDATION` for a
human. **The system never invents a verdict.** An assessment with unresolved
findings reports `AWAITING_VALIDATION`, deliberately *not* `COMPLETED`.

---

## 6. Using the web interface

1. `npm run dev` → <http://localhost:5173>
2. **New Assessment** → choose **Single Target** (type a domain or URL) or
   **Multiple Targets** (upload a `.txt`).
3. Review the parsed, normalized target list before starting.
4. Start → the assessment appears on the dashboard.
5. Detail view shows live status, per-target state, findings, reports, export.

### Live status

The backend pushes a real state snapshot over `ws://localhost:8000/ws/assessments/{id}`
roughly once a second, with a REST poll as fallback.

**Honest limitation:** per-stage status is a *rollup of persisted job rows*, not
an emitted event. The scheduler runs concurrent workers per stage, so there is
**no single "current stage"** — the UI shows a *list* of running stages. A stage
not yet listed means *not started*, not *failed* or *skipped*.

### API surface

All REST routes are under `/api/v1`. The WebSocket is at the app root.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Health check (app root, not under `/api/v1`) |
| `GET` `POST` | `/api/v1/assessments` | List / create |
| `GET` | `/api/v1/assessments/{id}` | Assessment detail |
| `POST` | `/api/v1/assessments/{id}/start` | Start execution |
| `POST` | `/api/v1/assessments/{id}/resume` | Resume after interruption |
| `GET` | `/api/v1/assessments/{id}/status` `/progress` | Real state snapshot |
| `GET` | `/api/v1/assessments/{id}/findings` | Findings list |
| `GET` | `/api/v1/assessments/{id}/validation/pending` | Awaiting-human queue |
| `POST` | `/api/v1/assessments/{id}/findings/{fid}/validate` | Confirm |
| `POST` | `/api/v1/assessments/{id}/findings/{fid}/reject` | Reject |
| `GET` | `/api/v1/assessments/{id}/reports` | Report metadata |
| `GET` | `/api/v1/assessments/{id}/reports/{filename}` | Download a report |
| `GET` | `/api/v1/assessments/{id}/reports/{filename}/inline` | HTML viewer (CSP-hardened) |
| `POST` | `/api/v1/assessments/{id}/export` | Build a ZIP archive |
| `GET` | `/api/v1/assessments/{id}/export/status` `/download` | Export status / file |

**Report formats actually generated:** `report.json`, `findings.jsonl`,
`report.html`. There is **no Markdown reporter**.

**HTML report safety:** `report.html` is built from scanner output that can
contain attacker-influenced strings. It is served as a **download by default**.
The optional `/inline` route adds
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:`
plus `nosniff` and `no-referrer`. A CSP is defence in depth, not a guarantee —
prefer downloading.

### Export archive layout

Every target gets **its own top-level directory**. Reports are never mixed
across domains.

```
assessment.zip
├── example.com/
│   ├── report/       report.html, findings.json
│   ├── findings/     finding-<id>.json
│   ├── evidence/     <tool>-<finding_id>.json
│   ├── recon/        subfinder-raw.jsonl
│   ├── discovery/    httpx-raw.jsonl
│   ├── crawl/        katana-raw.jsonl
│   ├── scanning/     nuclei-raw.jsonl
│   └── artifacts/    metadata.json + per-stage logs
└── _manifest/
    ├── assessment.json
    ├── targets.json
    ├── execution-summary.json
    └── export-manifest.json
```

Domain names are sanitised into safe path components (no `..`, no separators),
collisions are disambiguated, and every written path is asserted to stay inside
the output root — so a hostile target name cannot escape the archive or the
filesystem.

---

## 7. Running the tests

```bash
# Core pipeline — 205 tests
cd cybog && python -m pytest tests/ -q

# Backend API — 102 tests
cd backend && python -m pytest tests/ -q

# Frontend — 42 tests (vitest + testing-library)
cd frontend
npm test             # vitest run
npm run build        # tsc typecheck + production build
npm run typecheck    # typecheck only
```

The backend suite needs the `cybog` package importable (it is, via
`pip install -e`). Backend tests override the service dependency with a
temp directory, so they never touch real assessment data.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `cybog: command not found` | Run `source ~/.bashrc`; binaries live in `$HOME/go/bin` |
| Tool reported missing by `cybog healthcheck` | `go install` step failed — re-run `./setup.sh`, check `PATH` |
| `httpx` fails but other tools work | `config.yaml` still has the old absolute `httpx.binary` path |
| Dashboard shows **"No assessments yet"** | `backend/.env` `CYBOG_OUTPUT_ROOT` points at the wrong directory |
| Dashboard shows an error instead of a list | Backend is not running, or `CORS_ORIGINS` excludes your frontend origin |
| Frontend requests 404 | `VITE_API_BASE_URL` must include the `/api/v1` suffix |
| Live progress not updating | WebSocket blocked — check `VITE_WS_BASE_URL` and that the backend is reachable |
| `npm run lint` fails immediately | **Pre-existing.** The repo has no ESLint config file. `npm run build` is the real gate. |
| Assessment stuck `AWAITING_VALIDATION` | Expected — findings need a human decision via the UI or `cybog confirm/reject` |
| **"created but could not be started: unknown error"** | See §8.1 — almost always a **client timeout**, not a server failure. The run usually completed; check the dashboard before retrying. |
| `ffuf` fails with `stat .../wordlists/common.txt: no such file` | Fixed in the config loader (relative paths now anchor to the config file). Reinstall/restart the backend so the new loader is used. |
| `katana` fails with `name 'json' is not defined` | Fixed — a missing `import json` in `cybog/adapters/katana.py`. Restart the backend. |

### 8.1 "Created but could not be started: unknown error"

This is the most misleading message in the UI, so it is worth explaining.

`POST /api/v1/assessments/{id}/start` is **synchronous on the server**: it
awaits the entire pipeline (subfinder → dnsx → httpx → naabu → katana → ffuf →
nuclei) and only then returns. A real run takes minutes — easily longer than a
subdomain-rich target.

The frontend's shared axios timeout is 30 seconds. So the browser aborted the
request while the server kept working, and the UI reported a failure. The
assessment on disk was typically already `COMPLETED` or still progressing.

**What to do:** open the assessment from the dashboard and check its real
status before retrying — retrying can start a duplicate run.

**Current state:** `startAssessment`/`resumeAssessment` now send their own
2-hour timeout (`LONG_RUNNING_TIMEOUT_MS` in `frontend/src/api/assessments.ts`),
and a transport-level abort is reported distinctly from a server error instead
of collapsing to "unknown error". The underlying architectural issue remains:
a long-running job should return `202 Accepted` immediately and report progress
over the existing WebSocket, rather than holding an HTTP request open for the
duration of the scan.

---

## 10. End-to-end verification status

Two live end-to-end runs were executed against the IANA-reserved
`example.com` / `example.net` / `example.org` domains — safe, documentation-
only targets that are not owned by a third party. These were the first runs
that exercised **real scanner binaries** rather than stubbed adapters.

| Check | Result |
|---|---|
| Single target: create → start → poll → findings → export → download | Pass |
| Export manifest `total_size_bytes` == actual archive size | Pass |
| Export manifest `total_files` == `len(namelist)` | Pass |
| Export manifest `file_list` == `namelist` | Pass |
| Bulk 3-target manifest → 3 separate per-target ZIP directories | Pass |

This is *partial* real-tool evidence, not the full validation phase: the runs
confirmed that the pipeline executes, that later stages are reachable, and that
export integrity holds against real artifacts. It does **not** establish that
every tool version parses correctly — see §11, item 1.

### Bugs these runs uncovered (all invisible to the 347 stubbed tests)

1. **Stage-loop drain race** — `cybog/workflow/scheduler.py`.
   `_is_pipeline_drained()` only asked "is my queue empty *right now*", so a
   downstream stage loop started while its own queue was empty exited within
   its first 0.2s poll, before the upstream stage had enqueued anything. Those
   jobs stayed `PENDING` for the whole run while the assessment was still
   reported `COMPLETED`. Real evidence: subfinder produced 22,249 hosts and the
   `dnsx` job was enqueued but never ran.
   *Fix:* an `_inflight` counter, incremented on enqueue and decremented in
   `_execute_stage`'s `finally` **after** `_enqueue_next_stages`, so the counter
   can never read zero between "job finished" and "successors queued". Drain is
   now queue-empty **and** `_inflight == 0`. Regression coverage in
   `cybog/tests/test_stage_loop_drain.py` (a deliberately slow upstream
   adapter is required to expose it — the existing e2e test's instant fakes run
   entirely inside one poll window).

2. **Missing `import json`** — `cybog/adapters/katana.py` called
   `json.loads`/`json.JSONDecodeError` without importing `json`, so every
   katana run died with `NameError`. The only adapter missing the import.

3. **Relative config paths resolved against the wrong directory** —
   `cybog/config/loader.py` left `output.root`, `targets.input`,
   `authorization.scope_file` and `tools.ffuf.wordlist` as relative strings, so
   they resolved against the *process* working directory. The CLI runs from
   `cybog/` and worked; the API server runs from `backend/` and silently looked
   for `backend/config/wordlists/common.txt`, failing every ffuf job.
   *Fix:* `_resolve_relative_paths()` anchors relative path values at the
   directory containing `config.yaml`, making the same file behave identically
   from either launch directory.

4. **`secure_filename` dropped from upload responses** —
   `FileUploadResponse` omitted the field, so FastAPI's response filtering
   stripped it and clients saw `null`.

5. **UI reported a completed run as a failure** — see §8.1.

---

## 11. Known limitations — read this before trusting the system

**1. Real-tool compatibility is NOT fully proven.** This is the most important
caveat. The core and backend tests exercise the orchestration with **stubbed
adapters**. They prove the scheduler, state machine, lifecycle and export
logic. They do **not** prove that the real scanner binaries emit the JSON
Cybog expects. A tool version bump can change that output and break a stage
silently. The live runs in §10 are encouraging but not a systematic validation
of every tool and version.

**2. No containerization or CI.** There is no `Makefile` or GitHub Actions
workflow. Everything is run manually via `setup.sh` and `scripts/tunnel-dev.sh`,
and the setup script assumes a Debian-family host. Tool versions are unpinned.

**3. Authentication is a placeholder.** `get_current_user()` returns
`"anonymous"`; there is no real auth. Every endpoint is effectively open —
do not expose this backend to an untrusted network.

**4. Frontend tests cover the target logic and the form/dashboard flows, but
not the WebSocket or export polling paths.** 42 tests run via `npm test`
(vitest + testing-library). They mock the API layer, so they verify the UI
contract — what is previewed, what is POSTed, how empty-vs-error is
distinguished — not live network behaviour.

**5. Findings need humans.** By design, anything not automatically decidable
waits for validation. An assessment will not reach `COMPLETED` on its own.

**6. Unpinned dependencies.** Scanner binaries, nuclei templates, and wordlists
are all fetched at `@latest`/unversioned. Reproducibility is not guaranteed.

**7. `/start` blocks the HTTP request for the whole run.** Long scans hold a
connection open; the client timeout was raised to 2h to compensate. The correct
fix is `202 Accepted` plus WebSocket progress.

**8. The bundled ffuf wordlist is a 10-line placeholder** — see §4.1.

**9. An assessment can be reported `COMPLETED` while a target is `FAILED`.**
`_terminal_status()` only considers pending validation, so per-target job
failures do not block the terminal `COMPLETED` state. Always check per-target
status, not just the assessment status.

---

## 12. Suggested next steps

1. **Return `202 Accepted` from `/start`** and drive progress over the existing
   WebSocket, so a long scan no longer depends on a long-lived HTTP request.
2. **Real-tool integration validation** — run one authorized target end to end
   with real binaries and confirm each stage parses correctly. This is the
   biggest remaining gap.
3. **Containerization was rejected in favour of `setup.sh`** — the project is
   VPS-hosted on Azure and `scripts/tunnel-dev.sh` is the single entrypoint.
   If you want a reproducible build, pin tool versions in `setup.sh` or write
   a Nix flake; a Dockerfile is not on the roadmap.
4. **Implement real authentication** — the placeholder should not survive to
   any shared deployment.
5. **Ship a real wordlist** — the 10-line `config/wordlists/common.txt` makes
   the fuzzing stage nearly a no-op.
6. **Make config paths portable** — remove the hardcoded `httpx.binary` path so
   a fresh clone works without edits.