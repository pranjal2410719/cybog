/**
 * Assessment domain endpoints.
 *
 * Paths are relative to the configured axios base URL (which already
 * includes `/api/v1`). No leading slash duplication is needed.
 */

import type { AssessmentCreate, AssessmentResponse, AssessmentStatusResponse } from '../lib/models';
import { axiosInstance } from './client';

export async function checkHealth(): Promise<{ status: string; version: string; cybog_version: string }> {
  const response = await axiosInstance.get('/health');
  return response.data;
}

export async function createAssessment(data: AssessmentCreate): Promise<AssessmentResponse> {
  const response = await axiosInstance.post<AssessmentResponse>('/assessments', data);
  return response.data;
}

export async function listAssessments(): Promise<AssessmentResponse[]> {
  const response = await axiosInstance.get<AssessmentResponse[]>('/assessments');
  return response.data;
}

export async function getAssessment(assessmentId: string): Promise<AssessmentResponse> {
  const response = await axiosInstance.get<AssessmentResponse>(`/assessments/${assessmentId}`);
  return response.data;
}

export async function startAssessment(assessmentId: string): Promise<AssessmentResponse> {
  const response = await axiosInstance.post<AssessmentResponse>(
    `/assessments/${assessmentId}/start`,
    undefined,
  );
  return response.data;
}

export async function resumeAssessment(assessmentId: string): Promise<AssessmentResponse> {
  const response = await axiosInstance.post<AssessmentResponse>(
    `/assessments/${assessmentId}/resume`,
    undefined,
  );
  return response.data;
}

export interface AuthorizeResponse {
  assessment_id: string;
  authorized: boolean;
  authorized_by_user_id: string | null;
  authorized_at: string | null;
  scope_sha256: string | null;
}

/**
 * Record explicit human authorization (T5: blocking pre-execution step).
 * The owner confirms they are authorized to assess the target/scope;
 * execution refuses unconfirmed assessments. Rejected (409) once the
 * assessment has left CREATED: target/scope are frozen then.
 */
export async function authorizeAssessment(assessmentId: string): Promise<AuthorizeResponse> {
  const response = await axiosInstance.post<AuthorizeResponse>(
    `/assessments/${assessmentId}/authorize`
  );
  return response.data;
}

export interface PreflightCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface PreflightResponse {
  assessment_id: string;
  ready: boolean;
  status: string;
  checks: PreflightCheck[];
}

/**
 * Run the mandatory pre-execution boundary (T7). All checks must pass
 * (ready=true, status READY) before start is accepted. A NOT READY
 * response carries itemized reasons and mutates nothing.
 */
export async function preflightAssessment(assessmentId: string): Promise<PreflightResponse> {
  const response = await axiosInstance.post<PreflightResponse>(
    `/assessments/${assessmentId}/preflight`
  );
  return response.data;
}

export async function cancelAssessment(
  assessmentId: string
): Promise<{ assessment_id: string; cancelled: boolean }> {
  const response = await axiosInstance.post(`/assessments/${assessmentId}/cancel`);
  return response.data;
}

export async function getAssessmentStatus(assessmentId: string): Promise<AssessmentStatusResponse> {
  const response = await axiosInstance.get<AssessmentStatusResponse>(
    `/assessments/${assessmentId}/status`
  );
  return response.data;
}

export async function getAssessmentProgress(assessmentId: string): Promise<AssessmentStatusResponse> {
  return getAssessmentStatus(assessmentId);
}

export interface WsTicket {
  ticket: string;
  expires_in: number;
  assessment_id: string;
}

/**
 * Mint a single-use WebSocket ticket (T3). Browsers cannot send
 * Authorization headers on WS handshakes, so each (re)connect fetches a
 * fresh ticket and presents it as `?ticket=`. Tickets expire after 60s
 * and are consumed on first use.
 */
export async function fetchWsTicket(assessmentId: string): Promise<WsTicket> {
  const response = await axiosInstance.post<WsTicket>(
    `/assessments/${assessmentId}/ws-ticket`
  );
  return response.data;
}