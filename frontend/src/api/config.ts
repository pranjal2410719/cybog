/**
 * Single source of truth for all backend URLs.
 *
 * No component may hardcode a host, port, or `/api/v1` prefix. Everything
 * goes through `apiUrl()` / `wsUrl()` so the base path lives in exactly one
 * place. Values come from `VITE_*` env vars with sensible localhost defaults
 * so the app works with no `.env` present.
 */

function stripTrailingSlash(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

const envApiBaseUrl = import.meta.env.VITE_API_BASE_URL as string | undefined;
const envWsBaseUrl = import.meta.env.VITE_WS_BASE_URL as string | undefined;

/** Base URL for the REST API, INCLUDING the `/api/v1` prefix the backend mounts under. */
export const API_BASE_URL: string = stripTrailingSlash(
  envApiBaseUrl ?? 'http://localhost:8000/api/v1'
);

/** Base URL for WebSocket connections (no path prefix; paths are appended by `wsUrl`). */
export const WS_BASE_URL: string = stripTrailingSlash(
  envWsBaseUrl ?? 'ws://localhost:8000'
);

/** Build a full API URL from a path-relative segment. Never concatenate by hand. */
export function apiUrl(path: string): string {
  const clean = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE_URL}${clean}`;
}

/** Build a full WebSocket URL from a path-relative segment. */
export function wsUrl(path: string): string {
  const clean = path.startsWith('/') ? path : `/${path}`;
  return `${WS_BASE_URL}${clean}`;
}