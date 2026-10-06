/**
 * Configured axios instance for the Cybog backend API.
 *
 * Base URL comes from `src/api/config.ts` (which already includes the
 * `/api/v1` prefix the backend mounts under). Domain modules in this
 * directory call functions that take path-relative segments only.
 */

import axios from 'axios';
import { API_BASE_URL, apiUrl } from './config';

export const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Request interceptor: attach a bearer token when one is available in
// localStorage. No token/credential is ever written to env or client code.
axiosInstance.interceptors.request.use(
  (config) => {
    if (typeof window !== 'undefined') {
      const token = window.localStorage.getItem('cybog_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: normalise every API error into a plain Error whose
// `.message` is always a **string**.  This prevents React from crashing with
// "Objects are not valid as a React child" when a component renders `err.message`.
//
// The backend can return several error shapes:
//   • FastAPI HTTPException  → { "detail": "some string" }
//   • global_exception_handler → { "error": "Internal server error", "detail": null }
//   • Pydantic validation     → { "detail": [ { "loc": [...], "msg": "...", ... } ] }
//
// We extract the most useful human-readable string from any of them.
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const data = error.response.data;
      let msg: string | undefined;

      if (data != null) {
        // data.detail can be a string, an array, an object, or null
        const detail = (data as any)?.detail;
        // data.error is used by the global_exception_handler
        const errorField = (data as any)?.error;

        if (typeof detail === 'string' && detail.length > 0) {
          msg = detail;
        } else if (Array.isArray(detail)) {
          // Pydantic validation errors
          msg = detail.map((d: any) => d?.msg ?? JSON.stringify(d)).join('; ');
        } else if (typeof errorField === 'string' && errorField.length > 0) {
          msg = errorField;
        } else if (typeof data === 'string' && data.length > 0) {
          msg = data;
        }
        // else: leave msg undefined → fall through to error.message below
      }

      error.message = msg ?? error.message ?? 'Request failed';
    }
    return Promise.reject(error);
  }
);

/** Convenience: full URL for a path-relative segment. */
export { apiUrl };