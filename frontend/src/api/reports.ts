/**
 * Reports + artifacts domain endpoints.
 */

import { axiosInstance } from './client';

export async function getArtifacts(
  assessmentId: string,
  artifactType?: string
): Promise<{
  assessment_id: string;
  artifacts: Array<{
    artifact_id: string;
    target_id?: string;
    stage?: string;
    artifact_type: string;
    path: string;
    filename: string;
    size_bytes: number;
    checksum?: string;
    created_at: string;
  }>;
}> {
  const params = artifactType ? { artifact_type: artifactType } : {};
  const response = await axiosInstance.get(
    `/assessments/${assessmentId}/artifacts`,
    { params }
  );
  return response.data;
}

export async function getReports(assessmentId: string): Promise<{
  assessment_id: string;
  reports: Array<{
    filename: string;
    type: string;
    path: string;
    size_bytes: number;
    created_at: string;
  }>;
}> {
  const response = await axiosInstance.get(`/assessments/${assessmentId}/reports`);
  return response.data;
}