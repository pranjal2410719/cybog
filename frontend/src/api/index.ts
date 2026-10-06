/**
 * Single aggregated API entry point for components.
 *
 * Import `api` from here and call `api.listAssessments()`, etc. Nothing in
 * `src/` outside this directory should know about hosts, ports, or the
 * `/api/v1` prefix.
 */

import { axiosInstance, apiUrl } from './client';
import {
  API_BASE_URL,
  WS_BASE_URL,
  apiUrl as apiUrlHelper,
  wsUrl,
} from './config';
import * as assessments from './assessments';
import * as findings from './findings';
import * as validation from './validation';
import * as reports from './reports';
import * as exportApi from './export';
import * as audit from './audit';
import { WebSocketManager } from './ws';

export const api = {
  ...assessments,
  ...findings,
  ...validation,
  ...reports,
  ...exportApi,
  ...audit,
};

export { axiosInstance, WebSocketManager };
export { API_BASE_URL, WS_BASE_URL, apiUrl, apiUrlHelper, wsUrl };

export type {
  AssessmentCreate,
  AssessmentResponse,
  AssessmentStatusResponse,
  FindingResponse,
  FindingValidationRequest,
  ExportRequest,
  ExportResponse,
  HealthResponse,
  WebSocketMessage,
  ProgressUpdate,
  FindingUpdate,
} from '../lib/models';

export type { AuditEvent, AuditEventType } from './audit';