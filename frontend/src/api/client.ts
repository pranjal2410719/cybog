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

// Response interceptor: surface HTTP/network failures as a structured error
// so callers can distinguish an empty-but-successful list from a failure.
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const detail = (error.response.data as any)?.detail ?? error.response.data;
      error.message = detail ?? error.message;
    }
    return Promise.reject(error);
  }
);

/** Convenience: full URL for a path-relative segment. */
export { apiUrl };