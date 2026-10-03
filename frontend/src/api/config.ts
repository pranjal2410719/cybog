/**
 * Single source of truth for all backend URLs.
 *
 * No component may hardcode a host, port, or `/api/v1` prefix. Everything
 * goes through `apiUrl()` / `wsUrl()` so the base path lives in exactly one
 * place. Values come from `VITE_*` env vars with sensible localhost defaults
 * so the app works with no `.env` present.
 *
 * Two modes are supported:
 *  - Absolute bases (`http://localhost:8000/api/v1`, `ws://localhost:8000`),
 *    the default. The app talks to the backend host directly and CORS governs
 *    access.
 *  - Relative bases (`/api/v1`, `/`), used when `vite dev` puts its reverse
 *    proxy in front (see `vite.config.ts` `server.proxy`). The browser then
 *    calls the API and the WebSocket same-origin on the host it already loaded
 *    the page from, so no CORS allowlist is required. A relative WS base is
 *    resolved against the page origin because the native `WebSocket`
 *    constructor only accepts absolute `ws://` / `wss://` URLs.
 */

function stripTrailingSlash(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

/**
 * Resolve a relative base against the current page origin.
 *
 * The native `WebSocket` constructor requires an absolute ws:// or wss:// URL,
 * so a relative base (e.g. `/` or `/api/v1`) cannot be handed to it directly.
 * The scheme is derived from the page: https -> wss, anything else -> ws.
 * Absolute bases are returned untouched.
 */
function resolveAgainstPageOrigin(value: string): string {
  if (!value.startsWith('/')) return value;
  if (typeof window === 'undefined') return value;
  const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${scheme}://${window.location.host}${value}`;
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
  return resolveAgainstPageOrigin(`${WS_BASE_URL}${clean}`);
}
