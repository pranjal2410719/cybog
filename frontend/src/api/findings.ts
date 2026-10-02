/**
 * Findings domain endpoints (read-only lookups).
 */

import type { FindingResponse } from '../lib/models';
import { axiosInstance } from './client';

export async function getFindings(
  assessmentId: string,
  severity?: string
): Promise<FindingResponse[]> {
  const params = severity ? { severity } : {};
  const response = await axiosInstance.get<FindingResponse[]>(
    `/assessments/${assessmentId}/findings`,
    { params }
  );
  return response.data;
}

export async function getFinding(
  assessmentId: string,
  findingId: string
): Promise<FindingResponse> {
  const response = await axiosInstance.get<FindingResponse>(
    `/assessments/${assessmentId}/findings/${findingId}`
  );
  return response.data;
}