# CYBOG Phase 2 E2E Scan Traceability Framework

## Overview

This document defines the traceability framework for CYBOG Phase 2 E2E scans, establishing how findings are linked to sources, assessments, and reports throughout the security assessment lifecycle.

## Core Concepts

### Scan Identification

Every E2E scan run is uniquely identified by a `scan_id` that serves as the primary key for traceability. The `scan_id` is generated at the start of the scan and propagated throughout the entire assessment lifecycle.

### Mapping Relationships

```
Scan ID (unique per E2E run) → Assessment ID (in AssessmentState)
Scan ID → Finding Records (in Assessment.findings)
Scan ID → Report Metadata (in Assessment.reports)
Scan ID → Correlation Events (in cybog/cybog/state/scan_trace.json)
```

### Data Model

#### 1. Scan Record (`scan_record`)
- `scan_id`: Unique identifier (UUID)
- `assessment_id`: Reference to the associated assessment
- `start_time`: ISO timestamp when the scan began
- `end_time`: ISO timestamp when the scan completed
- `duration_seconds`: Total elapsed time
- `status`: `STARTED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`
- `resource_usage`: CPU%, memory usage during scan
- `execution_summary`: Brief summary of scan phases

#### 2. Assessment Record (`assessment`)
- `assessment_id`: Unique identifier
- `scan_id`: Linked to the E2E scan
- `created_at`: When the assessment was initiated
- `updated_at`: Last modification timestamp
- `status`: `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`
- `findings`: Array of finding objects
- `reports`: Array of generated report objects (HTML, PDF)
- `trace_link`: Direct reference to `scan_record`

#### 3. Finding Record (`finding`)
- `finding_id`: Unique identifier
- `scan_id`: Linked to the E2E scan
- `assessment_id`: Associated assessment
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- `description`: Human-readable description
- `evidence`: Raw output from scanners (subfinder, nuclei, etc.)
- `detected_by`: List of tools that discovered the finding
- `validated`: Boolean indicating human validation status
- `remediation`: Suggested remediation steps

#### 4. Correlation Event (`scan_trace`)
Stored in `cybog/cybog/state/scan_trace.json`:
- `scan_id`: Primary key
- `start_time`, `end_time`
- `phases`: Array of phase records (discovery, enumeration, scanning, validation)
- `resource_metrics`: Per-phase CPU, memory, duration
- `events`: Chronological list of significant events (target discovered, vulnerability found, etc.)

## Implementation Details

### Scan ID Generation
- Each E2E scan receives a UUID v4 as `scan_id`
- The ID is stored in the `scan_record` and linked to the `assessment`
- The `scan_id` is propagated to all findings and reports

### Assignment Flow
1. **Scan Initiation** – `ci/e2e-scan.yml` creates a new `scan_record`
2. **Target Injection** – Test targets are injected into the scan
3. **Pipeline Execution** – Subfinder → DNSX → HTTPX → NAABU → Katana → FFUF → Nuclei
4. **Findings Collection** – Each finding is recorded with `scan_id` and `assessment_id`
5. **Validation** – Human analysts validate findings; `validated` flag is set
6. **Report Generation** – HTML and PDF reports are generated and linked to `scan_id`
7. **Completion** – `scan_record` status set to `COMPLETED` or `FAILED`

### Reporting Links
- **HTML Reports** – Embedded in `scan_trace.json` under `reports[].embedded_html`
- **PDF Reports** – Stored in `s3://cybog-reports/` with naming convention `e2e-{scan_id}-{timestamp}.pdf`
- **Audit Trail** – Immutable log in `s3://cybog-audit/` with WORM protection

## Benefits

- **Full Lineage**: Every finding can be traced back to the originating scan
- **Regulatory Compliance**: Audit trail meets GDPR/SOC2 requirements
- **Root Cause Analysis**: Correlation events enable rapid incident investigation
- **Continuous Improvement**: Historical scan data informs future scan tuning

## Integration Points

- **CI/CD Pipeline** (`ci/e2e-scan.yml`): Generates and stores scan records
- **Backend State** (`cybog/cybog/state/`): Hosts `scan_trace.json` for correlation
- **Reporting Module** (`cybog/reporting/`): Produces HTML/PDF reports linked to `scan_id`
- **Alerting System**: Monitors scan health and triggers notifications
