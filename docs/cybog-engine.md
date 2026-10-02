# Cybog engine — pipeline, validation plane, adapters

> Start with the monorepo overview in [`../README.md`](../README.md).
> This note is the deep-dive for `cybog/` (Unit 1: core pipeline library + CLI).
> Full operator reference: [`DEVELOPER_GUIDE.md`](DEVELOPER_GUIDE.md).

## Pipeline

```
        TARGET MANIFEST (targets.txt)
                    │
                    ▼
       SCOPE VALIDATION (authorized_scope.txt)
                    │
                    ▼
                subfinder  (subdomain discovery)
                    │
                    ▼
                  dnsx     (DNS resolution & filtering)
             ┌──────┴──────┐
             ▼             ▼
           httpx         naabu    (concurrent probing)
             └──────┬──────┘
                    ▼
                 katana    (JS-aware crawling)
                    │
                    ▼
                  ffuf     (directory & path fuzzing)
                    │
                    ▼
                 nuclei    (vulnerability scanning)
                    │
                    ▼
        FINDING (DISCOVERED — an unverified candidate)
                    │
                    ▼
        NEEDS_VALIDATION → analyst queue → VALIDATING
                    │
         ┌──────────┴───────────┐
         ▼                      ▼
   validator verdict        no verdict →
   VALIDATED /               stays NEEDS_VALIDATION
   FALSE_POSITIVE            (AWAITING_ANALYST)
         │
         ▼
     REPORTABLE → reports (JSON / JSONL / HTML)
```

Key principles: scope-first admission, per-target independence, bounded
concurrency with backpressure, `zero results ≠ failure`, atomic persisted
state with `cybog resume <id>`, SHA256 finding deduplication.

## Finding lifecycle

Statuses move only along `ALLOWED_TRANSITIONS` in
`cybog/cybog/models/finding.py` — use `finding.transition_to(status)`,
never assign `validation_status` directly:

```
DISCOVERED → NEEDS_VALIDATION → VALIDATING → VALIDATED → REPORTABLE
                                         └──▶ FALSE_POSITIVE
```

(`VALIDATING → NEEDS_VALIDATION` is also legal: validator could not conclude.)
An assessment reaches `COMPLETED` only when no finding is pending validation;
otherwise it ends in `AWAITING_VALIDATION`. Auth validation is opt-in via
`CYBOG_AUTH_CREDENTIALS='user:password'` (env only, never committed) and runs
only for findings on confirmed live httpx services.

## Adding a tool adapter

1. Inherit from `ToolAdapter` in `cybog/cybog/adapters/base.py` and implement:
   `metadata()`, `health_check()`, `validate_input()`, `build_command()`,
   `parse_output()`, `normalize_output()`.
2. Add the tool config block in `cybog/cybog/config/models.py`.
3. Register the adapter in `cybog/cybog/workflow/scheduler.py`.

Adding a validator: implement
`validate_finding(finding, live_urls, stage_dir) -> ValidationOutcome`
(see `AuthAdapter`). Return `validated=None` when no verdict is reachable —
never guess, never create a new `Finding`, never put credentials in evidence.

## CLI quick reference

```bash
cd cybog
cybog healthcheck                      # verify binaries + config
cybog create  -t targets.txt -s authorized_scope.txt -p standard
cybog execute <ASSESSMENT_ID>
cybog status <ASSESSMENT_ID> | cybog findings <ASSESSMENT_ID>
cybog report <ASSESSMENT_ID>
cybog resume <ASSESSMENT_ID>
cybog pending <ASSESSMENT_ID>          # findings awaiting a decision
cybog confirm <ASSESSMENT_ID> <key>    # → REPORTABLE
cybog reject  <ASSESSMENT_ID> <key>    # → FALSE_POSITIVE
```

Copy `targets.example.txt` / `authorized_scope.example.txt` to
`targets.txt` / `authorized_scope.txt` and `config.example.yaml` to
`config.yaml` before first use — the working files are machine-local and
intentionally untracked.
