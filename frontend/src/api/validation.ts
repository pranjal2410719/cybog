/**
 * Validation domain endpoints (pending queue, confirm, reject).
 */

import type { FindingResponse } from '../lib/models';
import { axiosInstance } from './client';

export async function getPendingValidation(assessmentId: string): Promise<{
  assessment_id: string;
  pending_count: number;
  findings: FindingResponse[];
}> {
  const response = await axiosInstance.get(
    `/assessments/${assessmentId}/validation/pending`
  );
  return response.data;
}

export async function validateFinding(
  assessmentId: string,
  findingId: string,
  notes?: string
): Promise<{ success: boolean; finding_id: string }> {
  const response = await axiosInstance.post(
    `/assessments/${assessmentId}/findings/${findingId}/validate`,
    { validation_type: 'confirm', notes }
  );
  return response.data;
}

export async function rejectFinding(
  assessmentId: string,
  findingId: string,
  notes?: string
): Promise<{ success: boolean; finding_id: string }> {
  const response = await axiosInstance.post(
    `/assessments/${assessmentId}/findings/${findingId}/reject`,
    { validation_type: 'reject', notes }
  );
  return response.data;
}