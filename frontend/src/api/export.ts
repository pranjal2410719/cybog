/**
 * Export domain endpoints.
 */

import type { ExportRequest, ExportResponse } from '../lib/models';
import { axiosInstance } from './client';

export async function createExport(
  assessmentId: string,
  data: ExportRequest = { format: 'zip' }
): Promise<ExportResponse> {
  const response = await axiosInstance.post<ExportResponse>(
    `/assessments/${assessmentId}/export`,
    data
  );
  return response.data;
}

export async function getExportStatus(
  assessmentId: string,
  exportId: string
): Promise<{
  export_id: string;
  assessment_id: string;
  format: string;
  status: string;
  created_at?: string | null;
  estimated_completion?: string | null;
  error?: string | null;
  file_size_bytes?: number | null;
  file_count?: number | null;
}> {
  // Backend mounts export_id as a query parameter on this route.
  const response = await axiosInstance.get(
    `/assessments/${assessmentId}/export/status`,
    { params: { export_id: exportId } }
  );
  return response.data;
}

export async function downloadExport(
  assessmentId: string,
  exportId: string
): Promise<Blob> {
  const response = await axiosInstance.get(
    `/assessments/${assessmentId}/export/download`,
    { params: { export_id: exportId }, responseType: 'blob' }
  );
  return response.data;
}