# Internal Developer Remediation Report

> **DEMO REPORT — all organizations, hosts, accounts, people and data below are fictional and for template demonstration only.**


**INTERNAL — NOT FOR CLIENT DISTRIBUTION**

| Field | Value |
|---|---|
| Assessment ID | ASM-2026-014 |
| Client | Acme Retail Pvt Ltd |
| Report Date | 2026-10-05 |
| Report Version | 1.0 |
| Total Findings | 3 |

---

## Part 1. Assessment-Level Overview

### 1.1 Remediation Tracker

| Internal ID | Title | Severity | Confidence | Priority | Status | Owner | Team | Ticket | SLA |
|---|---|---|---|---|---|---|---|---|---|
| CYB-2026-0042 | Broken Object Level Authorization in User Profile API | HIGH | CONFIRMED | P1 | IN_PROGRESS | R. Mehta | Platform API | ACME-2291 | 7 days |
| CYB-2026-0043 | Broken Object Level Authorization in Order API | MEDIUM | CONFIRMED | P3 | ACKNOWLEDGED | R. Mehta | Platform API | ACME-2292 | 30 days |
| CYB-2026-0051 | No Observed Rate Limiting on Login Endpoint | MEDIUM | MEDIUM | P3 | OPEN | A. Khan | Identity & Auth | ACME-2305 | 30 days |

### 1.2 Shared Root Cause Groups
*One architectural fix may close many findings.*

**Group 1: Missing centralized object-level authorization**
- CYB-2026-0042 — Broken Object Level Authorization in User Profile API (/v2/users/{id})
- CYB-2026-0043 — Broken Object Level Authorization in Order API (/v2/orders/{orderId})

**Recommended single fix:** Introduce a service-layer authorization policy (principal + resource) used by all resource controllers; add shared cross-user regression tests.


### 1.3 Internal Risk / Confidence Matrix

| Severity | Confidence | Action |
|---|---|---|
| Critical | Confirmed | Immediate escalation |
| Critical | High | Immediate validation |
| High | Confirmed | Developer remediation |
| High | Medium | Priority validation |
| Medium | Confirmed | Normal remediation |
| Medium | Low | Manual review |
| Low | Any | Normal backlog |
| Informational | Any | Track if relevant |

---

## Part 2. Detailed Internal Findings


---

# CYB-2026-0042 — Broken Object Level Authorization in User Profile API

## 1. Internal Finding Header

| Field | Value |
|---|---|
| Internal Finding ID | INT-0042 |
| Client Finding ID | CYB-2026-0042 |
| Assessment ID | ASM-2026-014 |
| Detection Source | Cybog differential-authorization module |
| Validation Source | Manual analyst validation |
| Analyst | S. Verma |
| Date Discovered | 2026-09-17 |
| Date Validated | 2026-09-18 |
| Status | Confirmed |
| Severity | HIGH |
| Confidence | CONFIRMED |
| Priority | P1 |
| Owner | R. Mehta |
| SLA | 7 days |

## 2. Technical Classification

| Field | Value |
|---|---|
| CWE | CWE-639 |
| CVE | N/A |
| OWASP Category | API1:2023 BOLA |
| CVSS (score + vector) | 7.1 — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/C:H/I:L/A:N |
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| Confidentiality Impact | High |
| Integrity Impact | Low |
| Availability Impact | None |

## 3. Exact Vulnerability Location

| Field | Value |
|---|---|
| Repository | acme-customer-api |
| Service | customer-api |
| Application | Acme Customer API v2 |
| Module | users |
| File | src/controllers/users.controller.ts |
| Function | getUserById / updateUser |
| Class | UsersController |
| API Route | /v2/users/:id |
| HTTP Method | GET, PUT |
| Parameter | id (path) |
| Database Table | users |
| Database Field | all profile columns |
| Frontend Component | N/A |
| Configuration | N/A |
| Infrastructure Component | N/A |

## 4. Root Cause

The handlers load the user record using the id from the URL and return or update it. They only check that the caller is authenticated (authenticate middleware); no check compares the caller's principal with the requested user id or verifies an elevated role.

## 5. Vulnerable Code & Data Flow

| Field | Value |
|---|---|
| File | src/controllers/users.controller.ts |
| Line(s) | 41-58 |
| Function | getUserById |

```typescript
router.get('/v2/users/:id', authenticate, async (req, res) => {
  const user = await db.users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  return res.json(serializeUser(user));
});
```

**Data flow:**
```text
Input
 ↓
Controller
 ↓
Service
 ↓
Database query
 ↓
Missing / failed control: Ownership / role check between req.principal and req.params.id
 ↓
Sensitive response / state change
```
updateUser (lines 61-80) follows the same pattern for PUT /v2/users/:id.

## 6. Technical Reproduction

| Field | Value |
|---|---|
| Prerequisites | Two client-provisioned test accounts (A and B) with the standard customer role. |
| Authentication State | Authenticated as test account A |
| Required Account Type | Standard customer (low privilege) |

**Request:**
```http
GET /v2/users/10482 HTTP/1.1
Host: api.acme-retail.example
Authorization: Bearer <REDACTED>
Accept: application/json
```
*(Credentials must be placeholders, e.g. `Authorization: Bearer <REDACTED>`)*

| Field | Value |
|---|---|
| Headers | Authorization: Bearer <REDACTED>; Accept: application/json |
| Parameters | Path parameter id = 10482 |
| Payload | None (GET). For PUT: {"displayName": "cybog-test"} |

**Response:**
```http
HTTP/1.1 200 OK  {"id":10482,"name":"<REDACTED>","email":"<REDACTED>", ...}
```

| | |
|---|---|
| **Expected Behavior** | HTTP 403 Forbidden. |
| **Actual Behavior** | Request returned 200 with full profile of another user; PUT with the same token changed account B's displayName. |
| Evidence Reference | ART-88231 / EVD-0042-01..03 |

## 7. Attack Preconditions

| Field | Value |
|---|---|
| Unauthenticated / Authenticated | Authenticated |
| Required Role | Customer (lowest privilege) |
| Required Account | Any valid customer account |
| Network Access | Internet-reachable |
| User Interaction | None |
| Special Configuration | None |

## 8. What the Attacker Can Actually Do

**PROVEN**
Read another user's profile (name, email, phone, address). Modify another user's displayName via PUT.

**LIKELY**
Read profiles of other users by iterating over numeric IDs (IDs appear sequential).

**POSSIBLE**
Modification of additional fields if field-level validation is weak; chaining with password-reset flows (not tested).

**NOT PROVEN**
Account takeover. Administrative access. Remote code execution. Bulk data export.

## 9. Blast Radius

| Field | Value |
|---|---|
| Scope of Impact (single endpoint / user / tenant / multiple users / multiple tenants / entire application / infrastructure) | Multiple users (all customers) |
| Affected Environments | Production |
| Affected Versions | Customer API v2 (all deployed builds assessed) |
| Affected Services | customer-api |
| Related Endpoints | /v2/orders/{orderId} (see CYB-2026-0043) |
| Potentially Affected Components | Any controller using the same pattern |

## 10. Why Existing Controls Failed

**Control failure type:** Missing authorization check

Authentication is enforced via middleware but authorization is left to individual handlers, and these two handlers do not perform it.

## 11. Recommended Developer Fix

**Immediate Fix**
Reject requests where req.principal.id differs from :id unless the principal has the admin role.

**Code-Level Fix**
```typescript
router.get('/v2/users/:id', authenticate, async (req, res) => {
  const user = await userService.getUserForPrincipal(req.principal, req.params.id);
  return res.json(serializeUser(user));
});

// userService
function assertCanAccessUser(principal, targetId) {
  if (principal.id !== targetId && principal.role !== 'admin') throw new ForbiddenError();
}
```
Return 403 (or 404 to avoid existence disclosure — decide per API policy and apply consistently).

**Architecture-Level Fix**
Move object-level authorization into a shared policy layer in the service tier so every entry point uses the same checks.

**Regression Prevention**
Add automated authorization tests for every resource endpoint (owner, other user, other tenant, admin, nonexistent object).

## 12. Before / After Architecture

```text
CURRENT                          TARGET

Request                          Request
  ↓                                ↓
Controller (authenticate only)           Authentication
  ↓                                ↓
Database           Authorization
  ↓                                ↓
Response                         Service → Database → Response
```
Target adds a policy check between authentication and the service call.

## 13. Fix Acceptance Criteria

**CYB-2026-0042 is CLOSED when:**

- [ ] Request for another user's profile returns 403.
- [ ] Owner access to own profile still returns 200.
- [ ] PUT on another user's profile is rejected.
- [ ] Equivalent endpoints (orders, addresses) reviewed.
- [ ] Regression tests added and passing.
- [ ] Existing test suite passes.
- [ ] Cybog retest confirms remediation.

*Default set: unauthorized request is rejected (e.g. 403) · authorized request still works · cross-tenant access blocked · equivalent endpoints reviewed · regression tests added · existing tests pass · security test passes · retest confirms remediation.*

## 14. Regression Tests Required

| Test Name | Purpose |
|---|---|
| `test_owner_can_get_own_profile()` | Owner access still works |
| `test_user_cannot_get_other_users_profile()` | Cross-user read returns 403 |
| `test_user_cannot_update_other_users_profile()` | Cross-user write returns 403 |
| `test_admin_can_get_any_profile()` | Privileged path still works |
| `test_nonexistent_user_returns_expected_response()` | Consistent 404 behavior |

## 15. Related Findings / Shared Root Cause

| Related Finding | Title | Endpoint | Shared Root Cause |
|---|---|---|---|
| CYB-2026-0043 | BOLA in Order API | /v2/orders/{orderId} | Missing centralized object-level authorization |

## 16. Detection & Validation Source

| Field | Value |
|---|---|
| Discovery Tool | httpx + katana |
| Detection Tool | Cybog authz-differential check |
| Validation Tool | Burp Repeater (manual replay) |
| Rule / Template | authz-idor-differential-v1 |
| Workflow Stage | Vulnerability Detection |
| Execution ID | EXE-20260917-0311 |
| Artifact ID | ART-88231 |

```text
Cybog authz-differential check → Candidate finding → Specialized validation → Evidence → Analyst confirmation
```

## 17. Evidence Chain

```text
Target:      acme-retail.example
 ↓ Asset:    api.acme-retail.example
 ↓ Endpoint: /v2/users/{id}
 ↓ Execution:EXE-20260917-0311
 ↓ Raw Artifact: ART-88231
 ↓ Detection:    DET-0042
 ↓ Validation:   VAL-0042
 ↓ Finding:      CYB-2026-0042
 ↓ Evidence:     EVD-0042-01, EVD-0042-02, EVD-0042-03
 ↓ Report:       RPT-ASM-2026-014
```

**Why did Cybog create this finding?** The differential check replayed the same request with two accounts and received identical 200 responses containing the other account's data; an analyst reproduced it manually.

## 18. Developer Remediation Status

| Field | Value |
|---|---|
| Status (OPEN / ACKNOWLEDGED / IN_PROGRESS / FIX_READY / READY_FOR_RETEST / RETEST_FAILED / RETEST_PASSED / CLOSED / RISK_ACCEPTED / FALSE_POSITIVE) | IN_PROGRESS |
| Developer Owner | R. Mehta |
| Team | Platform API |
| Ticket ID | ACME-2291 |
| Commit | — |
| Pull Request | — |
| Fix Version | — |
| Retest Date | — |
| Retest Result | — |


---

# CYB-2026-0043 — Broken Object Level Authorization in Order API

## 1. Internal Finding Header

| Field | Value |
|---|---|
| Internal Finding ID | INT-0043 |
| Client Finding ID | CYB-2026-0043 |
| Assessment ID | ASM-2026-014 |
| Detection Source | Cybog differential-authorization module |
| Validation Source | Manual analyst validation |
| Analyst | S. Verma |
| Date Discovered | 2026-09-17 |
| Date Validated | 2026-09-18 |
| Status | Confirmed |
| Severity | MEDIUM |
| Confidence | CONFIRMED |
| Priority | P3 |
| Owner | R. Mehta |
| SLA | 30 days |

## 2. Technical Classification

| Field | Value |
|---|---|
| CWE | CWE-639 |
| CVE | N/A |
| OWASP Category | API1:2023 BOLA |
| CVSS (score + vector) | 6.5 — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/C:H/I:N/A:N |
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| Confidentiality Impact | High |
| Integrity Impact | None |
| Availability Impact | None |

## 3. Exact Vulnerability Location

| Field | Value |
|---|---|
| Repository | acme-customer-api |
| Service | customer-api |
| Application | Acme Customer API v2 |
| Module | orders |
| File | src/controllers/orders.controller.ts |
| Function | getOrderById |
| Class | OrdersController |
| API Route | /v2/orders/:orderId |
| HTTP Method | GET |
| Parameter | orderId (path) |
| Database Table | orders |
| Database Field | all columns |
| Frontend Component | N/A |
| Configuration | N/A |
| Infrastructure Component | N/A |

## 4. Root Cause

getOrderById fetches the order by orderId and returns it. It does not compare order.userId with the caller's principal.

## 5. Vulnerable Code & Data Flow

| Field | Value |
|---|---|
| File | src/controllers/orders.controller.ts |
| Line(s) | 22-35 |
| Function | getOrderById |

```typescript
router.get('/v2/orders/:orderId', authenticate, async (req, res) => {
  const order = await db.orders.findByOrderId(req.params.orderId);
  return order ? res.json(serializeOrder(order)) : res.status(404).end();
});
```

**Data flow:**
```text
Input
 ↓
Controller
 ↓
Service
 ↓
Database query
 ↓
Missing / failed control: order.userId === req.principal.id check
 ↓
Sensitive response / state change
```
Same pattern as CYB-2026-0042.

## 6. Technical Reproduction

| Field | Value |
|---|---|
| Prerequisites | Two client-provisioned test accounts, with an order created by account B. |
| Authentication State | Authenticated as test account A |
| Required Account Type | Standard customer |

**Request:**
```http
GET /v2/orders/ORD-559120 HTTP/1.1
Host: api.acme-retail.example
Authorization: Bearer <REDACTED>
```
*(Credentials must be placeholders, e.g. `Authorization: Bearer <REDACTED>`)*

| Field | Value |
|---|---|
| Headers | Authorization: Bearer <REDACTED> |
| Parameters | Path parameter orderId = ORD-559120 |
| Payload | None |

**Response:**
```http
HTTP/1.1 200 OK  {"orderId":"ORD-559120","shippingAddress":"<REDACTED>", ...}
```

| | |
|---|---|
| **Expected Behavior** | HTTP 403 Forbidden. |
| **Actual Behavior** | Order of another user returned. |
| Evidence Reference | ART-88240 / EVD-0043-01..02 |

## 7. Attack Preconditions

| Field | Value |
|---|---|
| Unauthenticated / Authenticated | Authenticated |
| Required Role | Customer |
| Required Account | Any valid customer account |
| Network Access | Internet-reachable |
| User Interaction | None |
| Special Configuration | None |

## 8. What the Attacker Can Actually Do

**PROVEN**
Read another user's order (items, shipping address, status).

**LIKELY**
Read other orders if order IDs can be discovered (e.g., from email links, logs).

**POSSIBLE**
Enumeration if ID format proves predictable.

**NOT PROVEN**
Order modification. Payment data access. Account takeover.

## 9. Blast Radius

| Field | Value |
|---|---|
| Scope of Impact (single endpoint / user / tenant / multiple users / multiple tenants / entire application / infrastructure) | Multiple users |
| Affected Environments | Production |
| Affected Versions | Customer API v2 |
| Affected Services | customer-api |
| Related Endpoints | /v2/users/{id} (CYB-2026-0042) |
| Potentially Affected Components | Other order sub-resources (invoices, tracking) — not tested |

## 10. Why Existing Controls Failed

**Control failure type:** Missing authorization check

Handler relies on authentication middleware only.

## 11. Recommended Developer Fix

**Immediate Fix**
Add ownership check (order.userId === principal.id) or admin-role exception.

**Code-Level Fix**
```typescript
const order = await orderService.getOrderForPrincipal(req.principal, req.params.orderId);
```
Use the shared policy helper introduced for CYB-2026-0042.

**Architecture-Level Fix**
Centralize object-level authorization policy in the service layer.

**Regression Prevention**
Add cross-user access tests for every order sub-resource.

## 12. Before / After Architecture

```text
CURRENT                          TARGET

Request                          Request
  ↓                                ↓
Controller (authenticate only)           Authentication
  ↓                                ↓
Database           Authorization
  ↓                                ↓
Response                         Service → Database → Response
```
Same target architecture as CYB-2026-0042.

## 13. Fix Acceptance Criteria

**CYB-2026-0043 is CLOSED when:**

- [ ] Cross-user order request returns 403.
- [ ] Owner access still returns 200.
- [ ] Order sub-resources reviewed.
- [ ] Regression tests added and passing.
- [ ] Cybog retest confirms remediation.

*Default set: unauthorized request is rejected (e.g. 403) · authorized request still works · cross-tenant access blocked · equivalent endpoints reviewed · regression tests added · existing tests pass · security test passes · retest confirms remediation.*

## 14. Regression Tests Required

| Test Name | Purpose |
|---|---|
| `test_owner_can_get_own_order()` | Owner access works |
| `test_user_cannot_get_other_users_order()` | Cross-user read denied |
| `test_admin_can_get_any_order()` | Privileged access works |

## 15. Related Findings / Shared Root Cause

| Related Finding | Title | Endpoint | Shared Root Cause |
|---|---|---|---|
| CYB-2026-0042 | BOLA in User Profile API | /v2/users/{id} | Missing centralized object-level authorization |

## 16. Detection & Validation Source

| Field | Value |
|---|---|
| Discovery Tool | httpx + katana |
| Detection Tool | Cybog authz-differential check |
| Validation Tool | Burp Repeater (manual replay) |
| Rule / Template | authz-idor-differential-v1 |
| Workflow Stage | Vulnerability Detection |
| Execution ID | EXE-20260917-0318 |
| Artifact ID | ART-88240 |

```text
Cybog authz-differential check → Candidate finding → Specialized validation → Evidence → Analyst confirmation
```

## 17. Evidence Chain

```text
Target:      acme-retail.example
 ↓ Asset:    api.acme-retail.example
 ↓ Endpoint: /v2/orders/{orderId}
 ↓ Execution:EXE-20260917-0318
 ↓ Raw Artifact: ART-88240
 ↓ Detection:    DET-0043
 ↓ Validation:   VAL-0043
 ↓ Finding:      CYB-2026-0043
 ↓ Evidence:     EVD-0043-01, EVD-0043-02
 ↓ Report:       RPT-ASM-2026-014
```

**Why did Cybog create this finding?** Differential replay with two accounts returned the other account's order; confirmed manually.

## 18. Developer Remediation Status

| Field | Value |
|---|---|
| Status (OPEN / ACKNOWLEDGED / IN_PROGRESS / FIX_READY / READY_FOR_RETEST / RETEST_FAILED / RETEST_PASSED / CLOSED / RISK_ACCEPTED / FALSE_POSITIVE) | ACKNOWLEDGED |
| Developer Owner | R. Mehta |
| Team | Platform API |
| Ticket ID | ACME-2292 |
| Commit | — |
| Pull Request | — |
| Fix Version | — |
| Retest Date | — |
| Retest Result | — |


---

# CYB-2026-0051 — No Observed Rate Limiting on Login Endpoint

## 1. Internal Finding Header

| Field | Value |
|---|---|
| Internal Finding ID | INT-0051 |
| Client Finding ID | CYB-2026-0051 |
| Assessment ID | ASM-2026-014 |
| Detection Source | Cybog rate-limit probe |
| Validation Source | Pending manual validation |
| Analyst | S. Verma |
| Date Discovered | 2026-09-19 |
| Date Validated | Pending |
| Status | Requires Validation |
| Severity | MEDIUM |
| Confidence | MEDIUM |
| Priority | P3 |
| Owner | A. Khan |
| SLA | 30 days |

## 2. Technical Classification

| Field | Value |
|---|---|
| CWE | CWE-307 |
| CVE | N/A |
| OWASP Category | API2:2023 Broken Authentication |
| CVSS (score + vector) | N/A (not justified until validated) |
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Confidentiality Impact | N/A |
| Integrity Impact | N/A |
| Availability Impact | N/A |

## 3. Exact Vulnerability Location

| Field | Value |
|---|---|
| Repository | acme-customer-api |
| Service | auth-service |
| Application | Acme Customer API v2 |
| Module | auth |
| File | UNKNOWN (no rate-limit middleware found in reviewed paths) |
| Function | UNKNOWN |
| Class | N/A |
| API Route | /v2/auth/login |
| HTTP Method | POST |
| Parameter | email, password |
| Database Table | N/A |
| Database Field | N/A |
| Frontend Component | N/A |
| Configuration | UNKNOWN — gateway/WAF configuration not provided |
| Infrastructure Component | UNKNOWN — upstream CDN/WAF not in scope |

## 4. Root Cause

UNKNOWN until validated. No application-level throttling was found in the reviewed login handler, but an upstream control (WAF/CDN/API gateway) could exist outside the reviewed code.

## 5. Vulnerable Code & Data Flow

| Field | Value |
|---|---|
| File | src/controllers/auth.controller.ts |
| Line(s) | 12-40 |
| Function | login |

```typescript
router.post('/v2/auth/login', async (req, res) => {
  const user = await authService.verify(req.body.email, req.body.password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  return res.json(issueToken(user));
});
```

**Data flow:**
```text
Input
 ↓
Controller
 ↓
Service
 ↓
Database query
 ↓
Missing / failed control: Rate limiting / lockout middleware (application level)
 ↓
Sensitive response / state change
```
No limiter observed in reviewed code; gateway config not reviewed.

## 6. Technical Reproduction

| Field | Value |
|---|---|
| Prerequisites | A client-provisioned test account (do not use real customer accounts). |
| Authentication State | Unauthenticated |
| Required Account Type | Test account (target of attempts) |

**Request:**
```http
POST /v2/auth/login HTTP/1.1
Host: api.acme-retail.example
Content-Type: application/json

{"email":"<TEST-ACCOUNT>","password":"<INVALID>"}
```
*(Credentials must be placeholders, e.g. `Authorization: Bearer <REDACTED>`)*

| Field | Value |
|---|---|
| Headers | Content-Type: application/json |
| Parameters | N/A |
| Payload | {"email":"<TEST-ACCOUNT>","password":"<INVALID>"} |

**Response:**
```http
401 Unauthorized x60 (no Retry-After / X-RateLimit headers)
```

| | |
|---|---|
| **Expected Behavior** | Throttling (HTTP 429), temporary lockout or CAPTCHA challenge after a small number of failures. |
| **Actual Behavior** | No rate limiting observed in a 30-second window. |
| Evidence Reference | ART-88512 |

## 7. Attack Preconditions

| Field | Value |
|---|---|
| Unauthenticated / Authenticated | Unauthenticated |
| Required Role | None |
| Required Account | Target account email known or guessed |
| Network Access | Internet-reachable |
| User Interaction | None |
| Special Configuration | Depends on upstream WAF configuration |

## 8. What the Attacker Can Actually Do

**PROVEN**
Submit 60 failed logins in 30 seconds without being throttled (test account).

**LIKELY**
Higher-volume guessing against a single account from one source.

**POSSIBLE**
Credential stuffing at scale if no upstream control exists.

**NOT PROVEN**
Any successful account takeover. Behavior over longer windows or from multiple IPs.

## 9. Blast Radius

| Field | Value |
|---|---|
| Scope of Impact (single endpoint / user / tenant / multiple users / multiple tenants / entire application / infrastructure) | Multiple users (any account reachable by email) |
| Affected Environments | Production |
| Affected Versions | Customer API v2 |
| Affected Services | auth-service |
| Related Endpoints | /v2/auth/password-reset (not tested) |
| Potentially Affected Components | Mobile app login, SSO callback |

## 10. Why Existing Controls Failed

**Control failure type:** Missing / unverified brute-force protection

No evidence of per-account or per-IP throttling at the application layer.

## 11. Recommended Developer Fix

**Immediate Fix**
Confirm upstream controls; if absent, add per-IP and per-account rate limiting on /v2/auth/login.

**Code-Level Fix**
```typescript
router.post('/v2/auth/login', loginRateLimiter({ windowMs: 15*60*1000, max: 10, keyBy: ['ip','email'] }), loginHandler);
```
Tune limits to avoid locking out legitimate users; return 429 with Retry-After.

**Architecture-Level Fix**
Apply a shared rate-limiting policy at the API gateway for all authentication routes.

**Regression Prevention**
Add automated tests that assert 429/lockout after N failures.

## 12. Before / After Architecture

```text
CURRENT                          TARGET

Request                          Request
  ↓                                ↓
Auth handler (no limiter)           Authentication
  ↓                                ↓
User store           Authorization
  ↓                                ↓
Response                         Service → Database → Response
```
Target adds a limiter before credential verification.

## 13. Fix Acceptance Criteria

**CYB-2026-0051 is CLOSED when:**

- [ ] Throttling or lockout triggers after configured failures.
- [ ] Legitimate login still works.
- [ ] Limits apply to password-reset endpoints too.
- [ ] Manual validation completed and finding status updated.
- [ ] Cybog retest confirms remediation.

*Default set: unauthorized request is rejected (e.g. 403) · authorized request still works · cross-tenant access blocked · equivalent endpoints reviewed · regression tests added · existing tests pass · security test passes · retest confirms remediation.*

## 14. Regression Tests Required

| Test Name | Purpose |
|---|---|
| `test_login_throttled_after_n_failures()` | 429 returned after threshold |
| `test_valid_login_succeeds_below_threshold()` | No false lockouts |
| `test_lockout_resets_after_window()` | Recovery behavior |

## 15. Related Findings / Shared Root Cause

| Related Finding | Title | Endpoint | Shared Root Cause |
|---|---|---|---|

## 16. Detection & Validation Source

| Field | Value |
|---|---|
| Discovery Tool | httpx + katana |
| Detection Tool | Cybog rate-limit probe |
| Validation Tool | N/A |
| Rule / Template | auth-ratelimit-probe-v1 |
| Workflow Stage | Vulnerability Detection |
| Execution ID | EXE-20260919-0420 |
| Artifact ID | ART-88512 |

```text
Cybog rate-limit probe → Candidate finding → Specialized validation → Evidence → Analyst confirmation
```

## 17. Evidence Chain

```text
Target:      acme-retail.example
 ↓ Asset:    api.acme-retail.example
 ↓ Endpoint: /v2/auth/login
 ↓ Execution:EXE-20260919-0420
 ↓ Raw Artifact: ART-88512
 ↓ Detection:    DET-0051
 ↓ Validation:   Pending
 ↓ Finding:      CYB-2026-0051
 ↓ Evidence:     EVD-0051-01
 ↓ Report:       RPT-ASM-2026-014
```

**Why did Cybog create this finding?** Automated probe observed 60 consecutive 401 responses with no throttling indicators; not yet manually validated.

## 18. Developer Remediation Status

| Field | Value |
|---|---|
| Status (OPEN / ACKNOWLEDGED / IN_PROGRESS / FIX_READY / READY_FOR_RETEST / RETEST_FAILED / RETEST_PASSED / CLOSED / RISK_ACCEPTED / FALSE_POSITIVE) | OPEN |
| Developer Owner | A. Khan |
| Team | Identity & Auth |
| Ticket ID | ACME-2305 |
| Commit | — |
| Pull Request | — |
| Fix Version | — |
| Retest Date | — |
| Retest Result | — |


---
*INTERNAL — Cybog Security Team — Assessment ASM-2026-014 — v1.0*
