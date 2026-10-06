# CYBOG CURRENT PROJECT STATUS

## 1. Executive Summary

The Cybog project has achieved a solid foundational architecture with a robust core assessment engine and a well-structured REST control plane. However, the system is currently **NOT READY** for production or even a controlled beta due to a critical runtime logic flaw in the authentication layer and an out-of-sync test suite. Overall completion is estimated at **70%**. 

The strongest areas are the core assessment pipeline (deterministic state machine, scope gate, finding lifecycle) and the report generators (HTML, JSON, JSONL, PDF). The biggest remaining gaps are the broken integration between the SQLAlchemy auth backend and the FastAPI route handlers (AttributeError on `user.id`), the incomplete frontend operator/validator views, and a completely broken test suite.

## 2. Repository Architecture

```text
cybog/
├── backend/ (FastAPI control plane)
│   ├── app/
│   │   ├── api/ (REST endpoints & auth routes)
│   │   ├── db/ (SQLAlchemy models & sessions)
│   │   └── services/ (cybog_integration, auth_service)
│   └── tests/ (Currently broken due to stale mocks/deps)
├── cybog/ (Core Engine)
│   └── cybog/
│       ├── ingestion/ (Target manifest handling)
│       ├── models/ (Core domain models: Assessment, Finding)
│       ├── reporting/ (JSON, HTML, PDF reporters)
│       ├── services/ (AssessmentService, Executor)
│       └── workflow/ (Asyncio job scheduler)
├── docs/ (Documentation)
└── frontend/ (React + Vite + TypeScript)
    └── src/
        ├── api/ (Client integration)
        ├── components/ (Dashboard, TargetInput, Login)
        └── pages/ (management/Users.tsx, operator/ and validator/ are empty)
```

## 3. Feature Status Matrix

| Feature | Status | Evidence | Confidence |
|---|---|---|---|
| Authentication | PARTIALLY_IMPLEMENTED | Backend `auth_routes.py` generates tokens, but `User` model lacks DB `id` | High |
| RBAC | BROKEN | `require_role` works, but endpoints fail on `user.id` access | High |
| Target ownership | BROKEN | `create_assessment` attempts to access `user.id` on Pydantic `User` | High |
| Assessment execution | IMPLEMENTED | Non-blocking `asyncio` execution in `cybog_integration.py` | High |
| Validation | BROKEN | `validate_finding` attempts to use `user.id`, causing 500 error | High |
| Reports | IMPLEMENTED | `PDFReporter`, `HTMLReporter` correctly process validation metadata | High |
| Downloads | BROKEN | `download_report` uses `user.id` for ownership check (AttributeError) | High |
| Audit | PARTIALLY_IMPLEMENTED| Events are generated, but `actor_user_id` assignment fails | High |
| E2E tests | STUB | `test_e2e_lifecycle.py` is an empty skeleton; other tests crash | High |

## 4. Role Capability Matrix

*(Note: Capabilities marked with ❌ fail at runtime due to the `user.id` AttributeError)*

| Capability | Operator | Validator | Management |
|---|---:|---:|---:|
| Login | ✅ | ✅ | ✅ |
| Create target | ❌ | ❌ | ❌ |
| Execute assessment | ❌ | ❌ | ❌ |
| Validate finding | ⛔ | ❌ | ⛔ |
| Download report | ❌ | ❌ | ❌ |
| Download ZIP | ❌ | ❌ | ❌ |
| View own assessments | ❌ | ❌ | ❌ |
| View all assessments | ⛔ | ⛔ | ✅ |
| Manage users | ⛔ | ⛔ | ❌ |
| View audit | ⛔ | ✅ | ✅ |

*(✅ = Allowed and functional, ❌ = Allowed but broken at runtime, ⛔ = Denied by RBAC)*

## 5. Assessment Lifecycle

```text
CREATED
  → QUEUED
  → RUNNING
  → RESUMING (if interrupted)
  → AWAITING_VALIDATION (if pending findings exist)
  → COMPLETED (verified metadata added only if human action occurs)
  → FAILED
  → CANCELLED
```
*Note: The distinction between scanner completion (`COMPLETED`) and verification has been correctly isolated. Zero findings result in `COMPLETED` but NOT `verified`.*

## 6. Finding Lifecycle

```text
DISCOVERED
  → NEEDS_VALIDATION
  → VALIDATING
  → VALIDATED
  → REPORTABLE
  → FALSE_POSITIVE
```
*Note: Invalid transitions (e.g. `REPORTABLE` -> `VALIDATING`) are strictly rejected by `InvalidTransitionError` inside `cybog/models/finding.py`.*

## 7. Report Lifecycle

```text
Assessment Pipeline
  ↓
Preliminary Report (report_unverified.*)
  ↓
Human Validation (`confirm_finding` / `reject_finding`)
  ↓
Assessment COMPLETED
  ↓
Final Report (report_verified.*)
  ↓
Download (Requires RBAC + Ownership check)
```
*Note: Reports are generated automatically by `_auto_generate_reports` and immutable (unverified and verified are stored separately).*

## 8. Identity & Ownership Model

The intended model exists in the schema (`DBUser` -> `DBTarget` -> `Assessment`), but the internal wiring is broken:
- `backend/app/db/models.py` defines `DBUser` with an internal `id` (UUID) and an external `uid`.
- `backend/app/api/auth_routes.py` authenticates users and returns a Pydantic `User` model.
- **CRITICAL FLAW:** The Pydantic `User` model (`backend/app/models/auth.py`) does **not** contain the `id` field. However, almost all REST endpoints in `routes.py` reference `user.id` (e.g., `owner_id=user.id`, `actor_user_id=user.id`), leading to an inevitable `AttributeError: 'User' object has no attribute 'id'`.

## 9. Security Findings

| Severity | Finding | Location | Impact | Recommendation |
|---|---|---|---|---|
| HIGH | Unhandled AttributeError on Authenticated Routes | `backend/app/api/routes.py` (multiple) | 100% of state-changing operations fail for authenticated users, breaking the platform. | Add `id: str` to the Pydantic `User` model in `auth.py` and populate it in `auth_routes.py`. |
| MEDIUM | Test Suite Broken / Stale Dependencies | `backend/tests/` | Cannot automatically verify security boundaries or business logic. | Update test dependencies (add `sqlalchemy` to test env) and refactor tests to use real DB instead of mocked `UserStore`. |

## 10. Missing Functionality

**BLOCKING:**
- Fix `user.id` attribute error across all endpoints.
- Fix broken test suite environment (`ModuleNotFoundError: No module named 'sqlalchemy'`).

**IMPORTANT:**
- Complete frontend UI for Operator/Validator (pages currently empty/missing).
- Fully implement `test_e2e_lifecycle.py` integration tests.

**NICE_TO_HAVE:**
- `cleanup_completed_assessments` (currently just a placeholder).

## 11. Broken / Stubbed / Mocked Components

- **`test_e2e_lifecycle.py`**: Stubbed skeleton.
- **`frontend/src/pages/operator/` & `validator/`**: Empty directories, lacking complete dashboard implementations.
- **`backend/tests/test_auth.py`**: Attempts to import `UserStore`, which was likely removed during the SQLAlchemy migration.
- **`cybog/services/assessment_service.py`**: `cleanup_completed_assessments` is an empty placeholder returning `[]`.

## 12. Test Coverage

- **Unit:** Broken (Import errors, missing `UserStore`).
- **Integration:** Broken (Environment issues).
- **E2E:** Stubbed.
- **Security:** Tested strictly in engine (`scope_validator.py`), but integration paths untested.
- **Frontend:** Unknown, likely low given missing page components.
- **Backend:** 0% currently passing due to global import errors.
- **CI:** Unknown / Unverified.

Highest risk untested paths: End-to-end report download authorization, actual DB commit success for audit trails.

## 13. Production Readiness

**NOT_READY**
The backend API contains a fatal runtime exception (`AttributeError`) on almost all core endpoints because the authentication payload (`User` model) lacks the internal database `id` expected by the route handlers. Additionally, the test suite is fundamentally broken and the frontend is missing critical views.

## 14. Top 10 Remaining Engineering Tasks

| Rank | Task | Impact | Effort | Priority |
|---|---|---|---|---|
| 1 | Fix `User` model to include `id` and update `auth_routes.py`. | Functional/Security | Low | P0 |
| 2 | Fix test environment (`sqlalchemy` dependency) and `UserStore` mocks. | Dependency | Medium | P0 |
| 3 | Implement comprehensive E2E tests in `test_e2e_lifecycle.py`. | Functional | Medium | P1 |
| 4 | Implement Frontend Operator pages/dashboard. | Functional | Medium | P1 |
| 5 | Implement Frontend Validator validation queue. | Functional | Medium | P1 |
| 6 | Validate all audit trail DB commits (ensure no silent failures). | Security | Low | P2 |
| 7 | Implement robust CI/CD pipeline for backend tests. | Dependency | Low | P2 |

## 15. Recommended Execution Plan

**Phase 1: Stabilization (Immediate)**
- Add `id` to `app.models.auth.User` and ensure `get_optional_current_user` populates it from `DBUser.id`.
- Fix the `pytest` environment (add missing packages to virtualenv/requirements).
- Remove stale references to `UserStore` in tests and replace with `AsyncSession` fixtures.

**Phase 2: Integration Testing**
- Complete `test_e2e_lifecycle.py` to assert the final acceptance matrix (Ownership, Verification, Auditing).
- Do not build any new features until the backend is fully green.

**Phase 3: Frontend Completion**
- Build out the missing `operator` and `validator` views in React.
- Connect them to the now-stable FastAPI REST/WebSocket boundaries.

**Phase 4: Hardening & Beta**
- Containerize and conduct a dry-run execution against a lab target.

# FINAL VERDICT

CURRENT STATE:
The Cybog platform possesses a well-designed architectural foundation with strict state boundaries and immutable reporting, but the recent transition to a real SQLAlchemy authentication backend introduced a critical runtime defect (Pydantic `User` model missing the internal `id`). As a result, the entire MVP lifecycle (assessment creation, validation, downloading) crashes with an `AttributeError` for authenticated users. The test suite is currently failing globally due to stale mocks and missing dependencies, obscuring this flaw.

MVP:
NOT READY

PRODUCTION:
NOT READY

BIGGEST RISK:
The complete failure of the test suite (`ModuleNotFoundError`, stale `UserStore` imports) allowed a fatal backend API crash (`AttributeError` on `user.id`) to be committed undetected.

NEXT ACTION:
Fix the `User` Pydantic model in `backend/app/models/auth.py` to include the `id` field, and repair the backend test suite environment.

CONFIDENCE:
HIGH
