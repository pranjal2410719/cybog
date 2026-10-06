/**
 * Audit log domain endpoints (management oversight).
 *
 * GET /audit/events returns all audit events, optionally scoped to a
 * single assessment. Requires VALIDATOR or MANAGEMENT role (enforced
 * server-side in routes.py).
 */

import { axiosInstance } from './client';

export type AuditEventType =
  | 'user_login'
  | 'user_create'
  | 'user_update'
  | 'assessment_create'
  | 'assessment_start'
  | 'assessment_cancel'
  | 'finding_validate'
  | 'finding_reject'
  | 'export_create'
  | 'export_download'
  | string;

export interface AuditEvent {
  event_id: string;
  user_id: string;
  user_name?: string | null;
  action: AuditEventType;
  assessment_id: string | null;
  target: string | null;
  detail: string;
  ip_address: string | null;
  timestamp: string;
}

export async function getAuditEvents(params?: {
  assessment_id?: string;
}): Promise<{ events: AuditEvent[] }> {
  const query: Record<string, string> = {};
  if (params?.assessment_id) {
    query.assessment_id = params.assessment_id;
  }
  const response = await axiosInstance.get('/audit/events', { params: query });
  return response.data;
}
