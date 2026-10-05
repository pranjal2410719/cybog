<!--
TEMPLATE: INTERNAL DEVELOPER REMEDIATION REPORT
Syntax: {{ value }} = placeholder, {% for %} / {% if %} = Jinja2-style logic

GENERATION RULES (do not print in the final report):
1. This is NOT a copy of the client report. It must contain substantially more technical detail.
2. Uses the SAME Finding ID as the client report: {{ finding_id }} (e.g. CYB-2026-0042).
3. Never store real credentials: use Authorization: Bearer <REDACTED>, Cookie: session=<REDACTED>.
4. Only populate classification fields (CWE/CVE/CVSS vectors) that are actually justified.
5. In "What the Attacker Can Actually Do", separate PROVEN / LIKELY / POSSIBLE / NOT PROVEN. Do not overstate.
6. Root cause and code locations must come from real code/evidence, not guesses. Use "UNKNOWN" if not established.
7. Every statement about why Cybog raised the finding must trace to the evidence chain, not LLM narrative.
-->

# Internal Developer Remediation Report

**INTERNAL — NOT FOR CLIENT DISTRIBUTION**

| Field | Value |
|---|---|
| Assessment ID | {{ assessment_id }} |
| Client | {{ client_name }} |
| Report Date | {{ report_date }} |
| Report Version | {{ report_version }} |
| Total Findings | {{ total_findings }} |

---

## Part 1. Assessment-Level Overview

### 1.1 Remediation Tracker

| Internal ID | Title | Severity | Confidence | Priority | Status | Owner | Team | Ticket | SLA |
|---|---|---|---|---|---|---|---|---|---|
{% for f in findings %}
| {{ f.finding_id }} | {{ f.title }} | {{ f.severity }} | {{ f.confidence }} | {{ f.priority }} | {{ f.dev_status }} | {{ f.owner }} | {{ f.team }} | {{ f.ticket_id }} | {{ f.sla }} |
{% endfor %}

### 1.2 Shared Root Cause Groups
*One architectural fix may close many findings.*

{% for g in root_cause_groups %}
**Group {{ loop.index }}: {{ g.common_root_cause }}**
{% for rf in g.findings %}
- {{ rf.finding_id }} — {{ rf.title }} ({{ rf.endpoint }})
{% endfor %}

**Recommended single fix:** {{ g.single_fix }}

{% endfor %}

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

{% for f in findings %}

---

# {{ f.finding_id }} — {{ f.title }}

## 1. Internal Finding Header

| Field | Value |
|---|---|
| Internal Finding ID | {{ f.internal_id }} |
| Client Finding ID | {{ f.finding_id }} |
| Assessment ID | {{ assessment_id }} |
| Detection Source | {{ f.detection.source }} |
| Validation Source | {{ f.validation.source }} |
| Analyst | {{ f.analyst }} |
| Date Discovered | {{ f.date_discovered }} |
| Date Validated | {{ f.date_validated }} |
| Status | {{ f.status }} |
| Severity | {{ f.severity }} |
| Confidence | {{ f.confidence }} |
| Priority | {{ f.priority }} |
| Owner | {{ f.owner }} |
| SLA | {{ f.sla }} |

## 2. Technical Classification

| Field | Value |
|---|---|
| CWE | {{ f.cls.cwe | default("N/A") }} |
| CVE | {{ f.cls.cve | default("N/A") }} |
| OWASP Category | {{ f.cls.owasp | default("N/A") }} |
| CVSS (score + vector) | {{ f.cls.cvss | default("N/A") }} |
| Attack Vector | {{ f.cls.attack_vector | default("N/A") }} |
| Attack Complexity | {{ f.cls.attack_complexity | default("N/A") }} |
| Privileges Required | {{ f.cls.privileges | default("N/A") }} |
| User Interaction | {{ f.cls.user_interaction | default("N/A") }} |
| Confidentiality Impact | {{ f.cls.c_impact | default("N/A") }} |
| Integrity Impact | {{ f.cls.i_impact | default("N/A") }} |
| Availability Impact | {{ f.cls.a_impact | default("N/A") }} |

## 3. Exact Vulnerability Location

| Field | Value |
|---|---|
| Repository | {{ f.loc.repository | default("UNKNOWN") }} |
| Service | {{ f.loc.service | default("UNKNOWN") }} |
| Application | {{ f.loc.application }} |
| Module | {{ f.loc.module | default("UNKNOWN") }} |
| File | {{ f.loc.file | default("UNKNOWN") }} |
| Function | {{ f.loc.function | default("UNKNOWN") }} |
| Class | {{ f.loc.class | default("N/A") }} |
| API Route | {{ f.loc.route }} |
| HTTP Method | {{ f.loc.method }} |
| Parameter | {{ f.loc.parameter | default("N/A") }} |
| Database Table | {{ f.loc.db_table | default("N/A") }} |
| Database Field | {{ f.loc.db_field | default("N/A") }} |
| Frontend Component | {{ f.loc.frontend | default("N/A") }} |
| Configuration | {{ f.loc.configuration | default("N/A") }} |
| Infrastructure Component | {{ f.loc.infrastructure | default("N/A") }} |

## 4. Root Cause

{{ f.root_cause }}

## 5. Vulnerable Code & Data Flow

| Field | Value |
|---|---|
| File | {{ f.code.file }} |
| Line(s) | {{ f.code.lines }} |
| Function | {{ f.code.function }} |

```{{ f.code.language }}
{{ f.code.snippet }}
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
Missing / failed control: {{ f.code.missing_control }}
 ↓
Sensitive response / state change
```
{{ f.code.flow_notes }}

## 6. Technical Reproduction

| Field | Value |
|---|---|
| Prerequisites | {{ f.repro.prerequisites }} |
| Authentication State | {{ f.repro.auth_state }} |
| Required Account Type | {{ f.repro.account_type }} |

**Request:**
```http
{{ f.repro.request }}
```
*(Credentials must be placeholders, e.g. `Authorization: Bearer <REDACTED>`)*

| Field | Value |
|---|---|
| Headers | {{ f.repro.headers }} |
| Parameters | {{ f.repro.parameters }} |
| Payload | {{ f.repro.payload }} |

**Response:**
```http
{{ f.repro.response }}
```

| | |
|---|---|
| **Expected Behavior** | {{ f.repro.expected }} |
| **Actual Behavior** | {{ f.repro.actual }} |
| Evidence Reference | {{ f.repro.evidence_ref }} |

## 7. Attack Preconditions

| Field | Value |
|---|---|
| Unauthenticated / Authenticated | {{ f.pre.auth }} |
| Required Role | {{ f.pre.role }} |
| Required Account | {{ f.pre.account }} |
| Network Access | {{ f.pre.network }} |
| User Interaction | {{ f.pre.user_interaction }} |
| Special Configuration | {{ f.pre.special_config | default("None") }} |

## 8. What the Attacker Can Actually Do

**PROVEN**
{{ f.attacker.proven }}

**LIKELY**
{{ f.attacker.likely }}

**POSSIBLE**
{{ f.attacker.possible }}

**NOT PROVEN**
{{ f.attacker.not_proven }}

## 9. Blast Radius

| Field | Value |
|---|---|
| Scope of Impact (single endpoint / user / tenant / multiple users / multiple tenants / entire application / infrastructure) | {{ f.blast.scope }} |
| Affected Environments | {{ f.blast.environments }} |
| Affected Versions | {{ f.blast.versions }} |
| Affected Services | {{ f.blast.services }} |
| Related Endpoints | {{ f.blast.related_endpoints }} |
| Potentially Affected Components | {{ f.blast.potential_components }} |

## 10. Why Existing Controls Failed

**Control failure type:** {{ f.control_failure.type }}

{{ f.control_failure.explanation }}

## 11. Recommended Developer Fix

**Immediate Fix**
{{ f.fix.immediate }}

**Code-Level Fix**
```{{ f.code.language }}
{{ f.fix.code_example }}
```
{{ f.fix.code_notes }}

**Architecture-Level Fix**
{{ f.fix.architecture }}

**Regression Prevention**
{{ f.fix.regression_prevention }}

## 12. Before / After Architecture

```text
CURRENT                          TARGET

Request                          Request
  ↓                                ↓
{{ f.arch.current_1 }}           Authentication
  ↓                                ↓
{{ f.arch.current_2 }}           Authorization
  ↓                                ↓
Response                         Service → Database → Response
```
{{ f.arch.notes }}

## 13. Fix Acceptance Criteria

**{{ f.finding_id }} is CLOSED when:**

{% for c in f.acceptance_criteria %}
- [ ] {{ c }}
{% endfor %}

*Default set: unauthorized request is rejected (e.g. 403) · authorized request still works · cross-tenant access blocked · equivalent endpoints reviewed · regression tests added · existing tests pass · security test passes · retest confirms remediation.*

## 14. Regression Tests Required

| Test Name | Purpose |
|---|---|
{% for t in f.regression_tests %}
| `{{ t.name }}` | {{ t.purpose }} |
{% endfor %}

## 15. Related Findings / Shared Root Cause

| Related Finding | Title | Endpoint | Shared Root Cause |
|---|---|---|---|
{% for r in f.related %}
| {{ r.finding_id }} | {{ r.title }} | {{ r.endpoint }} | {{ r.root_cause }} |
{% endfor %}

## 16. Detection & Validation Source

| Field | Value |
|---|---|
| Discovery Tool | {{ f.detection.discovery_tool }} |
| Detection Tool | {{ f.detection.tool }} |
| Validation Tool | {{ f.validation.tool }} |
| Rule / Template | {{ f.detection.rule }} |
| Workflow Stage | {{ f.detection.stage }} |
| Execution ID | {{ f.detection.execution_id }} |
| Artifact ID | {{ f.detection.artifact_id }} |

```text
{{ f.detection.tool }} → Candidate finding → Specialized validation → Evidence → Analyst confirmation
```

## 17. Evidence Chain

```text
Target:      {{ f.chain.target }}
 ↓ Asset:    {{ f.chain.asset }}
 ↓ Endpoint: {{ f.chain.endpoint }}
 ↓ Execution:{{ f.chain.execution_id }}
 ↓ Raw Artifact: {{ f.chain.artifact_id }}
 ↓ Detection:    {{ f.chain.detection_id }}
 ↓ Validation:   {{ f.chain.validation_id }}
 ↓ Finding:      {{ f.finding_id }}
 ↓ Evidence:     {{ f.chain.evidence_ids }}
 ↓ Report:       {{ report_id }}
```

**Why did Cybog create this finding?** {{ f.chain.justification }}

## 18. Developer Remediation Status

| Field | Value |
|---|---|
| Status (OPEN / ACKNOWLEDGED / IN_PROGRESS / FIX_READY / READY_FOR_RETEST / RETEST_FAILED / RETEST_PASSED / CLOSED / RISK_ACCEPTED / FALSE_POSITIVE) | {{ f.dev_status }} |
| Developer Owner | {{ f.owner }} |
| Team | {{ f.team }} |
| Ticket ID | {{ f.ticket_id }} |
| Commit | {{ f.commit | default("—") }} |
| Pull Request | {{ f.pr | default("—") }} |
| Fix Version | {{ f.fix_version | default("—") }} |
| Retest Date | {{ f.retest_date | default("—") }} |
| Retest Result | {{ f.retest_result | default("—") }} |

{% endfor %}

---
*INTERNAL — {{ prepared_by }} — Assessment {{ assessment_id }} — v{{ report_version }}*
