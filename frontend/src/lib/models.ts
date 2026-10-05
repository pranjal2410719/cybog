/**
 * Cybog Frontend API Models
 *
 * TypeScript interfaces matching the backend API responses.
 */

export enum Role {
  OPERATOR = "OPERATOR",
  ANALYST = "ANALYST",
  MANAGEMENT = "MANAGEMENT",
}

export interface User {
  uid: string;
  name: string;
  role: Role;
  active: boolean;
  created_at: string;
}

export interface AssessmentCreate {
  name: string;
  targets_file: string;
  scope_file: string;
  profile?: string;
}

/** Progress payload returned by the backend for an assessment. */
export interface AssessmentProgress {
  total_targets: number;
  completed_targets: number;
  total_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
  completion_percentage: number;
  targets?: AssessmentProgressTarget[];
}

export interface AssessmentProgressTarget {
  target_id: string;
  domain: string;
  status: string;
  completion_percentage: number;
}

export interface AssessmentResponse {
  assessment_id: string;
  name?: string | null;
  status: string;
  created_at: string;
  /**
   * Emitted by `_format_assessment_response`, but NOT declared on the backend
   * `AssessmentResponse` schema, so pydantic strips it. Treat as optional.
   */
  updated_at?: string;
  profile: string;
  artifact_root: string;
  progress: AssessmentProgress;
  findings_count: number;
  pending_validation_count: number;
}

/**
 * Shape returned by `GET /assessments/{id}/status` and `GET /progress`, which
 * both serve `backend/app/services/progress_snapshot.build_progress_snapshot`.
 * It is a pure projection of persisted `AssessmentState` — nothing estimated.
 */
export interface ProgressSnapshot {
  type: string;
  assessment_id: string;
  status: string;
  is_terminal: boolean;
  timestamp: string;
  last_updated?: string | null;
  progress: AssessmentProgress;
  targets: LiveTarget[];
  targets_total: number;
  targets_completed: number;
  targets_failed: number;
  stages: LiveStage[];
  /** Stages with >=1 RUNNING job. There is no single "current stage". */
  running_stages: string[];
  jobs: LiveJob[];
  jobs_total: number;
  jobs_completed: number;
  jobs_failed: number;
  job_status_counts: Record<string, number>;
  completion_percentage: number;
  findings_count: number;
  pending_validation_count: number;
  created_at: string;
  updated_at: string;
  partial_failure: boolean;
  failed_stages: string[];
}

export interface LiveTarget {
  target_id: string;
  domain: string;
  status: string;
  total_jobs: number;
  completed_jobs: number;
  completion_percentage: number;
  findings_count: number;
}

/** Per-stage rollup of `StageJob` rows, not an emitted event. */
export interface LiveStage {
  stage: string;
  status: string;
  job_count: number;
  running_jobs: number;
  completed_jobs: number;
  job_status_counts: Record<string, number>;
}

export interface LiveJob {
  job_id: string;
  target_id: string;
  stage: string;
  status: string;
  attempt: number;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
}

/** Shape of the `{"type":"progress", ...}` WebSocket push body. */
export type ProgressSocketMessage = ProgressSnapshot | SocketErrorMessage;

export interface SocketErrorMessage {
  type: string;
  status: string;
  is_terminal: boolean;
  error?: string;
}

export interface AssessmentStatusResponse {
  assessment_id: string;
  status: string;
  progress: AssessmentProgress;
  findings_count: number;
  pending_validation_count: number;
  created_at: string;
  updated_at: string;
}

export interface FindingResponse {
  finding_id: string;
  dedup_key: string;
  title: string;
  description?: string | null;
  severity: string;
  target_id: string;
  target_domain: string;
  url?: string | null;
  source_tool: string;
  validation_status: string;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
  evidence: FindingEvidence[];
}

/** One evidence row of a finding, as serialized by the backend service. */
export interface FindingEvidence {
  evidence_id: string;
  tool: string;
  raw_output: string;
  analyst_notes?: string | null;
  validation_result?: string | null;
  collected_at: string;
  /** Present on some evidence records; absent from the serializer today. */
  reproduction?: string | null;
}

/** Backend `ValidationStatus` values. `ALLOWED_TRANSITIONS` is authoritative. */
export const VALIDATION_STATUSES = [
  'DISCOVERED',
  'NEEDS_VALIDATION',
  'VALIDATING',
  'VALIDATED',
  'FALSE_POSITIVE',
  'REPORTABLE',
  'DUPLICATE',
  'OUT_OF_SCOPE',
  'NEEDS_INVESTIGATION',
] as const;

export type ValidationStatus = (typeof VALIDATION_STATUSES)[number];

/**
 * Mirror of `cybog.models.finding.TERMINAL_VALIDATION_STATUSES`: confirm and
 * reject are rejected from these states by `Finding.transition_to`, so the UI
 * disables those actions rather than sending a request that must fail.
 */
export const TERMINAL_VALIDATION_STATUSES: ReadonlySet<string> = new Set([
  'VALIDATED',
  'FALSE_POSITIVE',
  'REPORTABLE',
  'DUPLICATE',
  'OUT_OF_SCOPE',
]);

export const PENDING_VALIDATION_STATUSES: ReadonlySet<string> = new Set([
  'DISCOVERED',
  'NEEDS_VALIDATION',
  'VALIDATING',
  'DUPLICATE',
  'OUT_OF_SCOPE',
  'NEEDS_INVESTIGATION',
]);

export interface ReportEntry {
  filename: string;
  type: string;
  path?: string;
  size_bytes: number;
  created_at: string;
  exists?: boolean;
}

export interface ReportsResponse {
  assessment_id: string;
  reports: ReportEntry[];
}

/** `pending` | `in_progress` | `completed` | `failed` (backend constants). */
export interface ExportStatusResponse {
  export_id: string;
  assessment_id: string;
  format: string;
  status: string;
  created_at?: string | null;
  estimated_completion?: string | null;
  error?: string | null;
  file_size_bytes?: number | null;
  file_count?: number | null;
}

export interface FindingValidationRequest {
  validation_type: string;
  notes?: string | null;
}

export interface ExportRequest {
  format?: string;
  /** Include raw stage output in the archive. Defaults to true. */
  include_raw?: boolean;
  /** Include per-finding evidence files. Defaults to true. */
  include_evidence?: boolean;
  /** Only include findings in VALIDATED or REPORTABLE state. Defaults to false. */
  include_validated_only?: boolean;
}

export interface ExportResponse {
  export_id: string;
  assessment_id: string;
  format: string;
  status: string;
  created_at: string;
  estimated_completion: string | null;
  error?: string | null;
  file_size_bytes?: number | null;
  file_count?: number | null;
}

export interface HealthResponse {
  status: string;
  version: string;
  cybog_version: string;
}

export interface WebSocketMessage {
  type: string;
  assessment_id?: string;
  stage?: string;
  target_id?: string;
  target_domain?: string;
  progress_percentage?: number;
  message?: string;
  timestamp: string;
  finding_id?: string;
  finding?: Record<string, any>;
  action?: string;
  received?: string;
}

export interface ProgressUpdate {
  assessment_id: string;
  stage: string;
  target_id: string;
  target_domain: string;
  progress_percentage: number;
  message: string;
  timestamp: string;
}

export interface FindingUpdate {
  assessment_id: string;
  finding_id: string;
  finding: Record<string, any>;
  action: string;
  timestamp: string;
}
