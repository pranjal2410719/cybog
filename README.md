# Project Cybog 🛡️

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture: Persistent Scheduler](https://img.shields.io/badge/engine-asyncio%20workflow-orange.svg)](#architecture)
[![Testing: Pytest](https://img.shields.io/badge/tests-42%20passed-brightgreen.svg)](#testing)

**Cybog** is an authorized-use-only, deterministic security assessment workflow engine designed for high-throughput single-node and VPS operations.

Instead of running slow, serialized batch shell scripts (`Target 1 -> all tools -> Target 2`), Cybog operates as a **persistent workflow scheduler**. Each target domain advances through security tool stages independently as bounded worker pools become available.

---

## 📚 Documentation Quick Links

- 📖 **[Developer & Operational Guide](DEVELOPER_GUIDE.md)** — Complete guide for deployment, VPS configuration, target manifests, failure isolation, and custom adapter development.
- ⚙️ **[Single-Command Automated Installer (`setup.sh`)](setup.sh)** — One-line script to install Go, all 7 tool binaries, templates, wordlists, and Python dependencies.
- 📋 **[Default Configuration (`config.yaml`)](config.yaml)** — Configurable timeouts, worker concurrency limits, and queue bounds.

---

## ⚡ Key Architectural Principles

1. **Strict Scope Validation First**: Unauthenticated or unauthorized domains are stopped at the admission gate (`authorized_scope.txt`) before any security tool executes.
2. **Target-Level Independence**: Target A can advance to `dnsx` and `httpx` while Target B is still queued in `subfinder`.
3. **Parallel Discovery Execution**: Following DNS resolution, HTTP probing (`httpx`) and high-speed port scanning (`naabu`) execute concurrently via `asyncio.gather`.
4. **Bounded Concurrency & Backpressure**: Per-stage `WorkerPool` limits prevent CPU/network exhaustion, while `BoundedJobQueue` prevents memory bloat.
5. **Zero Results ≠ Failure**: If a tool finishes with 0 subdomains or 0 open ports, the stage completes cleanly with `result_count: 0`, and downstream stages are conditionally skipped.
6. **Crash-Resilient State & Resumption**: Assessment state is persisted atomically after every stage completion. Use `cybog resume <id>` to resume interrupted assessments without re-running finished jobs.
7. **Clean Normalization & Deduplication**: Raw tool outputs are archived to disk; findings are automatically deduplicated via SHA256 hashes and normalized into Pydantic models.

---

## 🔄 The MVP Security Pipeline

```
       TARGET MANIFEST (targets.txt)
                   │
                   ▼
      SCOPE VALIDATION (authorized_scope.txt)
                   │
                   ▼
               subfinder  (Subdomain discovery)
                   │
                   ▼
                 dnsx     (DNS resolution & filtering)
            ┌──────┴──────┐
            ▼             ▼
          httpx         naabu    (Concurrent probing)
            └──────┬──────┘
                   ▼
                katana    (JS-aware crawling)
                   │
                   ▼
                 ffuf     (Directory & path fuzzing)
                   │
                   ▼
                nuclei    (Vulnerability scanning)
                   │
                   ▼
       FINDING (DISCOVERED — an unverified candidate)
                   │
                   ▼
       NEEDS_VALIDATION  (enters the human-validation boundary)
                   │
                   ▼
       AnalystTask ──► BoundedAnalystQueue
                   │
                   ▼
            VALIDATING
                   │
        ┌──────────┴───────────┐
        ▼                      ▼
  ValidationAdapter       No applicable
  (AuthAdapter, when     validator →
        auth applies)    AWAITING_ANALYST
        │                      │
        ▼                      ▼
   Evidence ◄──────────────────┘
        │
   ┌────┴─────┐
   ▼          ▼
VALIDATED  FALSE_POSITIVE
   │
   ▼
REPORTABLE
        │
        ▼
 REPORTS (JSON / JSONL / Self-Contained HTML)
        │
        ▼
 ASSESSMENT COMPLETE
 *(only when no finding is still pending validation; otherwise
   the assessment ends in AWAITING_VALIDATION)*
```

---

## 🚀 Quick Start

### 1. Automated Environment Setup (Recommended)
On Debian, Ubuntu, Kali, or VPS:
```bash
./setup.sh
```
*This installs Go, subfinder, dnsx, httpx, naabu, katana, ffuf, nuclei, updates templates, establishes wordlists, and installs Cybog.*

### 2. Manual Installation
```bash
pip install -r requirements.txt
pip install -e .
```

Verify your toolchain:
```bash
python3 -m cybog.cli.main tools
```

---

## 💻 CLI Commands

### 1. Create Assessment
```bash
python3 -m cybog.cli.main create --targets ./targets.txt --scope ./authorized_scope.txt --profile standard
```
*Generates an `assessment_id` (e.g. `assessment-20260924-123456-abc12345`).*

### 2. Execute Pipeline
```bash
python3 -m cybog.cli.main execute <assessment_id>
```

### 3. Check Real-Time Status
```bash
python3 -m cybog.cli.main status <assessment_id>
```

### 4. View Findings
```bash
python3 -m cybog.cli.main findings <assessment_id>
# Or filter by severity:
python3 -m cybog.cli.main findings <assessment_id> --severity critical,high
```

### 5. Generate Multi-Format Reports
```bash
python3 -m cybog.cli.main report <assessment_id>
```
Reports are written to `./reports/<assessment_id>/aggregate/`:
- `report.json` — Complete machine-readable data snapshot
- `findings.jsonl` — Line-delimited JSON findings for SIEM / data pipelines
- `report.html` — Self-contained HTML report with responsive tables & badges (no CDN dependencies)

### 6. Resume Interrupted Assessment
```bash
python3 -m cybog.cli.main resume <assessment_id>
```

### 7. Human Validation Boundary
Findings that cannot be resolved automatically are parked for analyst review.
```bash
# List findings awaiting a decision
python3 -m cybog.cli.main pending <assessment_id>

# Confirm a finding (VALIDATED → REPORTABLE)
python3 -m cybog.cli.main confirm <assessment_id> <dedup_key> --notes "verified manually"

# Reject a finding (→ FALSE_POSITIVE)
python3 -m cybog.cli.main reject <assessment_id> <dedup_key> --notes "not exploitable"
```

An assessment reaches `COMPLETED` only when every finding has reached a terminal
validation state. Otherwise it ends in `AWAITING_VALIDATION`.

To enable automatic authentication-based validation, set the credential via the
environment (never commit it):
```bash
export CYBOG_AUTH_CREDENTIALS='user:password'
```
Auth validation runs only for findings on confirmed live httpx services.

---

## 🧪 Testing

Run the test suite with fixtures:
```bash
python3 -m pytest tests/ -v -W ignore::DeprecationWarning
```

---

## 📁 Repository Structure

```
cybog/
├── README.md                 # Project overview and entry point
├── DEVELOPER_GUIDE.md        # Comprehensive technical & operator guide
├── setup.sh                  # One-command automated toolchain installer
├── setup.py                  # Setuptools package configuration
├── requirements.txt          # Python runtime dependencies
├── config.yaml               # Tool parameters, timeouts, and concurrency
├── authorized_scope.txt      # Scope authorization whitelist & exclusions
├── targets.txt               # Input target domains manifest
├── config/
│   └── wordlists/
│       └── common.txt        # Baseline discovery wordlist
├── cybog/
│   ├── adapters/             # ToolAdapter ABC & implementations for 8 tools
│   ├── artifacts/            # ArtifactManager for raw logs and execution metadata
│   ├── cli/                  # Typer / Rich CLI commands
│   ├── config/               # Pydantic configuration schemas and loader
│   ├── findings/             # Thread-safe finding deduplication
│   ├── ingestion/            # Target manifest loader & parser
│   ├── models/               # Domain models (Target, Finding, Host, Job, etc.)
│   ├── queue/                # Bounded asyncio JobQueue & AnalystTask queue
│   ├── reporting/            # JSON, JSONL, and HTML report generators
│   ├── scope/                # ScopeValidator
│   ├── services/             # AssessmentService application layer
│   ├── state/                # Persisted AssessmentState with atomic writes
│   ├── workers/              # Semaphore-bounded WorkerPools
│   └── workflow/             # Scheduler, nodes, and router
└── tests/                    # 15 unit tests & output fixtures
```

---

## ⚖️ Legal Disclaimer
**Authorized Use Only.** This tool is designed strictly for authorized security assessments, penetration testing, and bug bounty programs with explicit written authorization. Scanning unauthorized targets is strictly illegal.
