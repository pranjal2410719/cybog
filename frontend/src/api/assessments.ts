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

/**
 * Timeout for calls that block until the whole pipeline finishes.
 *
 * `POST /assessments/{id}/start` (and `/resume`) are synchronous on the
 * server: they run every stage to completion before returning. A full run
 * against a real target takes minutes, so the shared 30s client timeout
 * aborted the request and the UI reported "could not be started: unknown
 * error" even though the server went on to complete the assessment. These
 * calls get their own, much longer budget.
 */
const LONG_RUNNING_TIMEOUT_MS = 2 * 60 * 60 * 1000; // 2 hours

export async function startAssessment(assessmentId: string): Promise<AssessmentResponse> {
  const response = await axiosInstance.post<AssessmentResponse>(
    `/assessments/${assessmentId}/start`,
    undefined,
    { timeout: LONG_RUNNING_TIMEOUT_MS }
  );
  return response.data;
}

export async function resumeAssessment(assessmentId: string): Promise<AssessmentResponse> {
  const response = await axiosInstance.post<AssessmentResponse>(
    `/assessments/${assessmentId}/resume`,
    undefined,
    { timeout: LONG_RUNNING_TIMEOUT_MS }
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