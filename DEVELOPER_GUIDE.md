# Cybog Developer & Operational Guide

Welcome to **Project Cybog** — an authorized, deterministic security assessment workflow engine designed for high-throughput single-node and VPS operations.

This document serves as the **master reference** for operators and developers.

---

## Table of Contents
1. [Architecture & Philosophy](#1-architecture--philosophy)
2. [Prerequisites & System Requirements](#2-prerequisites--system-requirements)
3. [One-Command Automated Setup](#3-one-command-automated-setup)
4. [Manual Configuration Guide](#4-manual-configuration-guide)
5. [End-to-End Workflow Execution](#5-end-to-end-workflow-execution)
6. [Failure Isolation, Dump, & Resume Mechanics](#6-failure-isolation-dump--resume-mechanics)
7. [Reporting & Output Artifacts](#7-reporting--output-artifacts)
8. [Developer Guide: Extending Tools & Adapters](#8-developer-guide-extending-tools--adapters)
9. [Troubleshooting & Healthchecks](#9-troubleshooting--healthchecks)

---

## 1. Architecture & Philosophy

Cybog is built as a **persistent workflow scheduler**, **not** a naive bash loop:
- **Scope First**: Targets cannot be scanned unless they pass strict whitelist checks in `authorized_scope.txt`.
- **Target Independence**: Target A does not wait for Target B. While Target B is waiting in Subfinder, Target A advances into DNS resolution, HTTP probing, and crawling.
- **Concurrent Branches**: Post-DNS validation, `httpx` (web probing) and `naabu` (port discovery) execute concurrently via `asyncio.gather`.
- **Zero Results ≠ Tool Failure**: If a tool finishes without finding subdomains or endpoints, the stage status is `COMPLETED` with `result_count: 0`. The router cleanly skips dependent downstream stages without crashing the pipeline.

```
       TARGET MANIFEST (targets.txt)
                   │
                   ▼
      SCOPE VALIDATION (authorized_scope.txt)
                   │
                   ▼
               subfinder
                   │
                   ▼
                 dnsx
            ┌──────┴──────┐
            ▼             ▼
          httpx         naabu  (Concurrent)
            └──────┬──────┘
                   ▼
                katana
                   │
                   ▼
                 ffuf
                   │
                   ▼
                nuclei
                   │
                   ▼
   REPORTS (JSON / JSONL / Self-Contained HTML)
```

---

## 2. Prerequisites & System Requirements

### Supported Environments
- **OS**: Linux (Debian 11+, Ubuntu 20.04+, Kali Linux, AlmaLinux/Rocky Linux).
- **Architecture**: `amd64` or `arm64`.
- **Hardware**: Minimum 2 vCPU / 4 GB RAM (Recommended: 4 vCPU / 8 GB+ RAM for high concurrency).

### Software Requirements
- **Python**: 3.10 or higher.
- **Go (Golang)**: 1.21+ (for installing Go-based security binaries).
- **Core Utilities**: `git`, `curl`, `jq`.

---

## 3. One-Command Automated Setup

If you or another user are setting this up on a fresh machine or VPS without any of the tools installed, run the single-command setup script:

```bash
cd /home/dev/Desktop/cybor/docs/cybog
./setup.sh
```

### What `setup.sh` does automatically:
1. Detects or installs `golang-go` and essential build packages via `apt`.
2. Configures and persists `export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"` in shell profiles (`.bashrc` / `.zshrc`).
3. Installs all 7 security tools via `go install`:
   - `subfinder`
   - `dnsx`
   - `httpx`
   - `naabu`
   - `katana`
   - `ffuf`
   - `nuclei`
4. Updates Nuclei templates to the latest version (`nuclei -update-templates`).
5. Establishes the default discovery wordlist (`config/wordlists/common.txt`).
6. Installs Python dependencies (`pydantic`, `typer`, `rich`, `pyyaml`, `langgraph`) and registers the `cybog` CLI.
7. Executes a health check to verify all binaries are active and responding.

---

## 4. Manual Configuration Guide

All configuration options reside in `config.yaml`:

```yaml
pipeline:
  profile: standard    # standard | quick | deep

targets:
  input: ./targets.txt # Input manifest path
  batch_size: 100

authorization:
  required: true
  scope_file: ./authorized_scope.txt # Authorization whitelist

workers:
  # Concurrency limits per stage (Semaphore bounded)
  subfinder: 4
  dnsx: 8
  httpx: 8
  naabu: 4
  katana: 4
  ffuf: 2
  nuclei: 4

queues:
  max_size: 100        # Asyncio bounded queue depth (backpressure)

tools:
  subfinder:
    enabled: true
    binary: subfinder
    timeout: 300
    extra_args: []

  dnsx:
    enabled: true
    binary: dnsx
    timeout: 300
    extra_args: []

  httpx:
    enabled: true
    binary: httpx
    timeout: 300
    extra_args: []

  naabu:
    enabled: true
    binary: naabu
    timeout: 600
    extra_args: []

  katana:
    enabled: true
    binary: katana
    timeout: 600
    extra_args: []

  ffuf:
    enabled: true
    binary: ffuf
    timeout: 600
    wordlist: ./config/wordlists/common.txt
    extra_args: []

  nuclei:
    enabled: true
    binary: nuclei
    timeout: 900
    severity: low,medium,high,critical
    extra_args: []

execution:
  continue_on_error: true # Isolates errors so other targets continue
  retry_failed: 2         # Max automatic retries for failed tool executions
  resume: true

output:
  root: ./reports

logging:
  level: INFO
  format: json            # json | text
```

### Scope Rule Configuration (`authorized_scope.txt`)
Scope validation is **hard-closed** (whitelist only):
```text
# Allow root domain and any subdomains
example.com
*.example.com

# Explicit exclusions (! prefix)
!internal.example.com
!staging.example.com
```

---

## 5. End-to-End Workflow Execution

### Step 1: Prepare Targets and Scope
Edit `targets.txt`:
```text
example.com
api.example.com
target.org
```

### Step 2: Create Assessment
```bash
python3 -m cybog.cli.main create --targets ./targets.txt --scope ./authorized_scope.txt --profile standard
```
*Output:*
```text
Assessment created:
  ID:      assessment-20260924-073000-a1b2c3d4
  Profile: standard
  Targets: ./targets.txt
  Scope:   ./authorized_scope.txt
```

### Step 3: Execute Assessment
Run the async scheduler:
```bash
python3 -m cybog.cli.main execute assessment-20260924-073000-a1b2c3d4
```

### Step 4: Live Status & Findings Inspection
Check real-time progress:
```bash
python3 -m cybog.cli.main status assessment-20260924-073000-a1b2c3d4
```

Inspect deduplicated findings:
```bash
python3 -m cybog.cli.main findings assessment-20260924-073000-a1b2c3d4
# Or filter by critical / high:
python3 -m cybog.cli.main findings assessment-20260924-073000-a1b2c3d4 --severity critical,high
```

### Step 5: Generate Reports
```bash
python3 -m cybog.cli.main report assessment-20260924-073000-a1b2c3d4
```
Reports are produced at:
`./reports/assessment-<id>/aggregate/`
- `report.json`
- `findings.jsonl`
- `report.html` (Standalone, viewable in any browser without external CSS/JS)

---

## 6. Failure Isolation, Dump, & Resume Mechanics

### Target Isolation
- Each target executes in its own isolated worker context.
- If a target fails in a stage (e.g. timeout or DNS crash), that target's job is recorded as `FAILED`, its error context is logged in `execution.json`, and it does **not** stop other targets in the queue.

### Crash Recovery & Resume
If the process is interrupted (Ctrl+C, VPS reboot, network disconnect):
```bash
python3 -m cybog.cli.main resume assessment-20260924-073000-a1b2c3d4
```
- Cybog reads `state.json`.
- Completed stages are **never** re-run (idempotent skip).
- Interrupted or pending stages resume immediately.

---

## 7. Reporting & Output Artifacts

Under `./reports/<assessment_id>/`:
```
reports/assessment-xxx/
├── state.json                 # Atomic state snapshot (single source of truth)
├── manifest.json              # Admission & scope log
├── aggregate/                 # Final reports
│   ├── report.json
│   ├── findings.jsonl
│   └── report.html
└── targets/
    └── <target_id>/
        ├── subfinder/attempt_1/
        │   ├── stdout.log
        │   ├── stderr.log
        │   ├── raw.jsonl
        │   ├── normalized.json
        │   └── execution.json
        ├── dnsx/attempt_1/
        ├── httpx/attempt_1/
        └── ...
```

---

## 8. Developer Guide: Extending Tools & Adapters

To add a new tool to Cybog:
1. Inherit from `ToolAdapter` in `cybog/adapters/base.py`.
2. Implement the required contract methods:
   - `metadata() -> dict`
   - `health_check() -> HealthCheckResult`
   - `validate_input(job, context) -> ValidationResult`
   - `build_command(job, stage_dir, context) -> list[str]`
   - `parse_output(tool_result, stage_dir) -> list[dict]`
   - `normalize_output(parsed, job) -> NormalizedOutput`
3. Add the tool configuration block in `cybog/config/models.py`.
4. Register the adapter in `cybog/workflow/scheduler.py`.

---

## 9. Troubleshooting & Healthchecks

### Verifying Tool Availability
Run:
```bash
python3 -m cybog.cli.main tools
```
Every tool must display `✔` under `Available`.

### Running the Test Suite
Verify that models, adapters, routing, and reporting are functioning:
```bash
python3 -m pytest tests/ -v -W ignore::DeprecationWarning
```
