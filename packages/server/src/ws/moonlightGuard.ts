import { queryAll } from '../db/helpers.js';
import { wsCanAccess } from '../services/permissions.js';
import { parseMoonlightExtra } from '../services/moonlightPairing.js';

/**
 * moonlight-web has a single shared user, so it cannot tell Gatwy users apart:
 * every host and every stream is reachable by anyone who gets a request through.
 * Gatwy therefore decides what may reach it, fail-closed:
 *   - the browser-facing surface is a small allowlist (static files, two read-only
 *     API calls, the stream WebSocket);
 *   - the stream WebSocket carries `host_id` in its first message, which is checked
 *     against the connections the user can access before anything reaches upstream.
 * Host management, pairing, wake, users, roles and WebRTC are never reachable
 * through /mlw (Gatwy manages hosts itself, server-side, via services/moonlightWeb.ts).
 */

const PREFIX = '/mlw';
const STREAM_WS_SUFFIX = '/api/host/stream/web_socket';
export const MLW_STREAM_WS_PATH = `${PREFIX}${STREAM_WS_SUFFIX}`;

/** `<METHOD> <path under /mlw>` of the only /api calls the stream page makes. */
const API_ALLOWLIST = new Set([
  'GET /api/authenticate',
  'GET /api/role',
]);

/** Plain path segments only: no percent-encoding, no dot-segments, no separators. */
const SAFE_SEGMENT = /^[A-Za-z0-9._~@+,=-]+$/;

export type MoonlightRouteDecision =
  | { kind: 'http'; path: string; search: string }
  | { kind: 'stream-ws'; path: string }
  | { kind: 'deny'; status: 403 | 405; reason: string };

function deny(status: 403 | 405, reason: string): MoonlightRouteDecision {
  return { kind: 'deny', status, reason };
}

/**
 * Decide whether a /mlw request may be forwarded, and under which path.
 * The returned path is the one that must be forwarded upstream (never the raw URL),
 * so the thing checked here is the thing moonlight-web routes on.
 * `mountPrefix` is the full public mount (BASE_PATH + /mlw); moonlight-web runs under
 * that same prefix, so the returned path keeps it.
 */
export function classifyMoonlightRequest(
  method: string,
  rawUrl: string,
  isUpgrade: boolean,
  mountPrefix: string = PREFIX,
): MoonlightRouteDecision {
  const q = rawUrl.indexOf('?');
  const path = q === -1 ? rawUrl : rawUrl.slice(0, q);
  const search = q === -1 ? '' : rawUrl.slice(q);

  if (path !== mountPrefix && !path.startsWith(`${mountPrefix}/`)) return deny(403, 'Not a Moonlight path');

  // One trailing slash is fine for static files (`/mlw/`); an empty segment anywhere else is not.
  const rest = path.slice(mountPrefix.length);
  const trailingSlash = rest.endsWith('/');
  const body = trailingSlash ? rest.slice(0, -1) : rest;
  const clean = body === '' ? [] : body.slice(1).split('/');
  for (const seg of clean) {
    if (seg === '.' || seg === '..' || !SAFE_SEGMENT.test(seg)) return deny(403, 'Invalid path');
  }

  const normalized = `${mountPrefix}${clean.length ? `/${clean.join('/')}` : ''}${trailingSlash ? '/' : ''}`;
  const isApi = clean[0]?.toLowerCase() === 'api';

  if (isUpgrade) {
    const streamPath = `${mountPrefix}${STREAM_WS_SUFFIX}`;
    return path === streamPath ? { kind: 'stream-ws', path: streamPath } : deny(403, 'WebSocket path not allowed');
  }

  if (isApi) {
    const key = `${method} /${clean.join('/')}`;
    return API_ALLOWLIST.has(key) && !trailingSlash
      ? { kind: 'http', path: normalized, search }
      : deny(403, 'Moonlight API endpoint not allowed');
  }

  if (method !== 'GET' && method !== 'HEAD') return deny(405, 'Method not allowed');
  return { kind: 'http', path: normalized, search };
}

/** The `host_id` a client may stream from: one of its accessible Moonlight connections. */
export function canAccessMoonlightHost(userId: string, hostId: number): boolean {
  const access = wsCanAccess(userId);
  const rows = queryAll<{ extra_config_json: string | null }>(
    `SELECT extra_config_json FROM connections WHERE protocol = 'moonlight' AND ${access.where}`,
    access.params,
  );
  return rows.some((row) => parseMoonlightExtra(row.extra_config_json).mlHostId === hostId);
}

export const MAX_STREAM_REQUEST_BYTES = 4096;

export type StreamRequestResult =
  | { ok: true; hostId: number; forward: string }
  | { ok: false; reason: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Parse the first WebSocket message of a stream (`{"Request": {"host_id": n, ...}}`).
 * `forward` is the re-serialized message: what was validated is exactly what upstream sees.
 */
export function parseStreamRequest(text: string): StreamRequestResult {
  if (Buffer.byteLength(text, 'utf8') > MAX_STREAM_REQUEST_BYTES) return { ok: false, reason: 'Request too large' };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, reason: 'Invalid JSON' };
  }
  if (!isPlainObject(parsed)) return { ok: false, reason: 'Invalid message' };
  const keys = Object.keys(parsed);
  if (keys.length !== 1 || keys[0] !== 'Request') return { ok: false, reason: 'Expected a stream request' };
  const request = parsed.Request;
  if (!isPlainObject(request)) return { ok: false, reason: 'Invalid stream request' };
  const hostId = request.host_id;
  if (typeof hostId !== 'number' || !Number.isInteger(hostId) || hostId < 0 || hostId > 0xffffffff) {
    return { ok: false, reason: 'Invalid host_id' };
  }
  return { ok: true, hostId, forward: JSON.stringify(parsed) };
}

/** True for a text message carrying a stream `Request` (never valid after the first message). */
export function isStreamRequestMessage(text: string): boolean {
  try {
    const parsed: unknown = JSON.parse(text);
    return isPlainObject(parsed) && Object.prototype.hasOwnProperty.call(parsed, 'Request');
  } catch {
    return false;
  }
}
