# CYBOG PRD v2.0 — Gap Analysis (2026-10-05)

## 1. Scope

PRD v2.0 is the master spec. This doc maps each PRD requirement to the current implementation state and defines the work items.

Verdict legend: **MET** = requirement satisfied by the current implementation; **PARTIAL** = core mechanism exists but the full requirement is unmet; **MISSING** = no implementation; **N/A** = row is informational or overridden by decision.

## 2. Met Requirements (PRD Phase 1 "Core Engine")

- Deterministic pipeline subfinder -> dnsx -> (httpx || naabu) -> katana -> ffuf -> nuclei (cybog/cybog/workflow/scheduler.py, STAGES_ORDER)
- Tool adapters with execute/parse/normalize behind ToolAdapter ABC (cybog/cybog/adapters/)
- Fail-closed scope/authorization gate (cybog/cybog/scope/validator.py) — PRD §52
- Normalization + SHA256 dedup (cybog/cybog/models/finding.py dedup_key, state.add_finding occurrence merging) — seed of PRD §23
- Isolated immutable artifacts (cybog/cybog/artifacts/manager.py) — PRD §48
- Resumable persisted state, atomic save (cybog/cybog/state/assessment_state.py) — PRD §63
- Finding lifecycle with enforced transitions (ALLOWED_TRANSITIONS in models/finding.py) — PRD §25 core (POTENTIAL != VERIFIED, PRD §5)
- Timeout/concurrency/bounded-queue resource controls (workers + queues + config) — PRD §66
- CLI execution (cybog/cybog/cli/main.py)
- 369 passing tests (219 core, 108 backend, 42 frontend) as of 2026-10-05

## 3. Gaps

| PRD Section | Requirement | Current State | Verdict (MET/PARTIAL/MISSING) | Work Item | Phase |
|---|---|---|---|---|---|
| §10–12 | Target identity: normalized root domain as logical target identity; target persists across assessments; TGT-XXXX ids; subtargets linked to parent; one-target-one-submitter | `Target` is a per-assessment uuid object embedded in `AssessmentState` | MISSING | Target registry with normalized domain identity + metadata (submitted_by, created_at, assessment_count, verified/potential counts, current risk) | P1 |
| §11 | Target metadata: submitted_by UID, timestamps, risk rollups | None | MISSING | Same work item as §10–12 (target registry metadata) | P1 |
| §24–26 | Finding model: confidence (High/Medium/Low automated), analyst_id, analyst_notes, impact, remediation, source_tools plural, affected_parameters, asset id | `Finding` has severity, dedup_key, single source_tool, evidence list (Evidence has analyst_notes/reproduction/validation_result) | PARTIAL | Add missing fields: confidence, analyst_id, impact, remediation, verification_method, observed_behavior; source_tools plural; affected_parameters. Backward-compatible schema extension — add fields with defaults, keep dedup_key stable | P1 |
| §25 | Finding states: POTENTIAL / UNDER_REVIEW / VERIFIED / FALSE_POSITIVE / DUPLICATE / OUT_OF_SCOPE / NEEDS_INVESTIGATION | DISCOVERED / NEEDS_VALIDATION / VALIDATING / VALIDATED / FALSE_POSITIVE / REPORTABLE | PARTIAL | Mapping: DISCOVERED+NEEDS_VALIDATION ≈ POTENTIAL, VALIDATING ≈ UNDER_REVIEW, VALIDATED+REPORTABLE ≈ VERIFIED. Missing: DUPLICATE, OUT_OF_SCOPE, NEEDS_INVESTIGATION. Extend `ValidationStatus` + `ALLOWED_TRANSITIONS` (DUPLICATE and OUT_OF_SCOPE reachable from NEEDS_VALIDATION/VALIDATING); keep existing states, add new ones; document the mapping | P1 |
| §23 / §53 | Correlation: cross-tool evidence merge with source attribution + confidence assignment | dedup_key merge increments occurrence_count but no per-source attribution on finding, no confidence | PARTIAL | Correlation pass: keep dedup as seed, add source_tools list, merge evidence, assign automated confidence | P1/P2 |
| §27–32 | Reports: 3-state model (PRELIMINARY → UNDER VALIDATION → PARTIALLY VERIFIED → VERIFIED/FINAL), versioned (v1/v2/v3), mandatory unverified disclaimer, precise language rules (§58), auto-generated preliminary report when pipeline reaches AWAITING_VALIDATION | Single-version report.json / findings.jsonl / report.html, generated on demand, no state, no disclaimer, no versioning | MISSING | Report state model + versioning + preliminary-report auto-generation + disclaimer/language rules | P1 |
| §6, §9, §60 | UID + roles + RBAC: USR-XXXX ids, 3 business roles (OPERATOR / ANALYST / MANAGEMENT), backend-enforced authorization, frontend presentational only, target scope per user | `get_current_user` stub (returns Optional[str], no enforcement), no user store | MISSING | User store with USR-XXXX ids + 3-role RBAC, backend-enforced; frontend presentational only | P1 |
| §50 | Audit trail: AuditEvent (actor_uid, timestamp, action, resource, previous_state, new_state, assessment_id, target_id) for all sensitive actions | None | MISSING | Audit event capture + persistence for all sensitive actions | P1 |
| §33–34 | Management dashboard: org metrics (targets, assessments, verified/pending findings), target inventory (domain, submitted_by, date, last assessment, risk, findings), target drill-down + assessment history | None | MISSING | Management dashboard UI + supporting API endpoints | P2 |
| §36–38 | Operator UX: abstract human-readable workflow stages (NOT tool names), my-targets, new-assessment flow with authorization checkbox, cancel | LiveStatusPanel.tsx shows raw stage names (subfinder/dnsx/httpx/naabu/katana/ffuf/nuclei); no auth confirmation step | MISSING | Operator UI: human-readable stages, target submission with authorization confirmation, cancel | P2 |
| §29–30 | Analyst UX: validation queue, finding detail with evidence/request-response, verdict capture (confirm/reject/duplicate/out-of-scope/needs-investigation), analyst description, final severity/confidence, remediation | API has findings validate endpoint; no queue/evidence UI | MISSING | Analyst validation UI: queue, evidence viewer, verdict capture | P2 |
| §64 | Assessment states: PARTIALLY_COMPLETED / BLOCKED / OUT_OF_SCOPE | AssessmentStatus has CREATED / RUNNING / COMPLETED / FAILED / CANCELLED / RESUMING / AWAITING_VALIDATION | PARTIAL | Add PARTIALLY_COMPLETED (+ document mapping of target-level OUT_OF_SCOPE handling, which already exists via scope gate) | P1 (small enum extension) |
| §55 | Report formats: Web / PDF / JSON / CSV | JSON / JSONL / HTML | PARTIAL | CSV export of findings; PDF deferred decision (HTML print-to-PDF vs weasyprint) — marked as open question (§6) | P2/P3 |
| §43 | LangGraph mention | STALE — PRD text says "recommends LangGraph" but the user decision (2026-10-05) overrode it: JobScheduler (pure asyncio) is the frozen canonical orchestrator; langgraph/langchain-core dependencies removed in Phase 1 cleanup; see docs/ARCHITECTURE.md | N/A (superseded) | Annotate PRD §43 as superseded. No code work. | — |
| §46 | jq in toolset | Informational — normalization is done in Python adapters, jq not needed | N/A (informational) | No work | — |
| §61–63, §74 | Persistence: PRD Phase 2 wants PostgreSQL + entities (Organization, User, Role, Permission, Target, TargetAccess, Assessment, …) | Single JSON state file per assessment (documented working model) | PARTIAL | Introduce a persistence INTERFACE first (JSONBackend now, SQLiteBackend next, PostgreSQL when multi-user/concurrency demands it) — preserves the proven deterministic MVP | P2 |
| §68–71 | Performance + accuracy benchmarks | None yet | MISSING | Benchmark 10/50/100 targets; accuracy via controlled environments (local lab app exists at cybog/lab/, add OWASP Juice Shop/DVWA) | P2 |
| §78, §79 | Advanced tooling (Amass, gau, Dalfox, Nikto, ZAP, Gowitness) and optional intelligence layer | Not implemented | MISSING | Explicitly deferred until deterministic core proven + reliable | P3/P4 |
| §72 | MVP definition: 20-item checklist | See check-off list below | PARTIAL | Close open items per P1/P2 work items above | P1/P2 |

### §72 MVP 20-item checklist (check-off)

- [ ] 1. Target submission with recorded authorization (authenticated submitter) — MISSING
- [ ] 2. Stable user UID (USR-XXXX) — MISSING
- [ ] 3. Role model (operator / analyst / management) — MISSING
- [~] 4. Operator creates target — PARTIAL: CLI/service exists, no user
- [~] 5. Target normalization — PARTIAL: domain normalization exists in ingestion/manifest.py, target registry missing
- [x] 6. Authorization recorded — MET (Authorization model + fail-closed scope gate)
- [x] 7. Scope validated before execution — MET
- [x] 8. Assessment created and persisted — MET
- [x] 9. Deterministic workflow — MET (STAGES_ORDER pipeline)
- [x] 10. Real tool adapters — MET (7 adapters, structured execute/parse/normalize)
- [x] 11. Normalization of tool output — MET
- [x] 12. Dedup — MET (SHA256 dedup_key, occurrence merging)
- [~] 13. Severity + confidence — PARTIAL: severity yes, confidence missing
- [ ] 14. Preliminary report auto-generated with unverified disclaimer — MISSING: report exists but no preliminary state/disclaimer
- [x] 15. Findings enter analyst validation — MET (engine)
- [~] 16. Analyst verify/reject — PARTIAL: API exists, UI missing
- [~] 17. Analyst evidence preserved — PARTIAL: Evidence model has analyst fields, flow incomplete
- [ ] 18. Verified report (versioned, verified state) — MISSING: no versioning/verified state
- [ ] 19. Management view — MISSING
- [ ] 20. Audit history — MISSING

## 4. Execution Order (PRD-aligned, post-Phase-1-cleanup)

**P0 (done/in-flight):**
- [x] Phase 1 cleanup (deps, dead code, dupes, 29 unused imports, docs) — 369 tests green
- [ ] E2E live pipeline proof on local lab target (in progress 2026-10-05)

**P1 (next, in order):**
1. Target registry + normalized domain identity + target metadata (submitted_by)
2. Finding schema extension (confidence, analyst fields, impact/remediation, source_tools plural, DUPLICATE/OUT_OF_SCOPE/NEEDS_INVESTIGATION states) + PARTIALLY_COMPLETED assessment state
3. Report state model + versioning + preliminary-report auto-generation + disclaimer/language rules
4. UID + 3-role RBAC + audit trail (backend-enforced)

**P2:**
5. Analyst validation UI (queue, evidence viewer, verdict capture)
6. Operator UI (human-readable stages, target submission with authorization confirmation, cancel)
7. Management dashboard (inventory, submitter, risk rollup, history)
8. Persistence interface (JSON -> SQLite -> PostgreSQL as demanded)
9. Performance + accuracy benchmarks (controlled envs: lab app, Juice Shop, DVWA)

**P3:**
10. Advanced tooling (Amass/Dalfox/ZAP…) only with defined purpose + normalized output
11. Optional intelligence layer (assist-only, never overrides analyst verdict)

## 5. Core Product Rules (non-negotiable, from PRD §84)

1. **Authorization first** — no scan activity runs against a target without recorded, verifiable authorization; the scope gate fails closed.
2. **Domain identity** — a target is identified by its normalized root domain, and that identity persists across assessments.
3. **Assessment identity** — each assessment is a distinct, immutable unit of work tied to a target.
4. **UID accountability** — every actor is identified by a stable USR-XXXX uid and every sensitive action is attributable to one.
5. **Automated != verified** — tool output is potential evidence only; it never becomes a verified finding on its own.
6. **Analyst owns verification** — only an analyst verdict, with recorded reasoning, can promote a finding to verified.
7. **Reports preserve truth** — reports state explicitly what remains unverified, use precise language, and are versioned as validation progresses.
8. **Management observes** — management sees rollups and trends but does not operate the platform or alter findings.
9. **Backend enforces security** — authorization is enforced in the backend; the frontend is presentational only.
10. **Preserve evidence** — raw tool output and request/response evidence are retained as immutable artifacts for every finding.
11. **No silent scope expansion** — assessments stay inside their recorded scope; expansion requires a new, explicit decision.
12. **Deterministic core first** — the deterministic pipeline is the foundation; anything non-deterministic is layered on top and must never replace it.
13. **Every finding traceable** — every finding traces back to the tool output, assessment, and target that produced it.
14. **Historical assessments immutable** — completed assessments and their artifacts never change; new work creates new versions.
15. **Simplicity for operators** — operators see abstracted workflow stages and clear states, not tool names or raw internals.

## 6. Open Questions

- PDF generation approach (print-ready HTML vs weasyprint library)
- Database choice timing (SQLite vs PostgreSQL for multi-user)
- Benchmark target set finalization
