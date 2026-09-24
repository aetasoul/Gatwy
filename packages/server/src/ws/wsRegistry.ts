/**
 * Registry of active WebSocket connections keyed by token hash.
 * Used to forcibly close open sessions when a login session is revoked.
 */
import type WebSocket from 'ws';

const registry = new Map<string, Set<WebSocket>>();
const alive = new WeakMap<WebSocket, boolean>();

const HEARTBEAT_INTERVAL_MS = 30000;

export function registerWs(tokenHash: string, ws: WebSocket): void {
  if (!registry.has(tokenHash)) registry.set(tokenHash, new Set());
  registry.get(tokenHash)!.add(ws);
  alive.set(ws, true);
  ws.on('pong', () => alive.set(ws, true));
}

export function unregisterWs(tokenHash: string, ws: WebSocket): void {
  const set = registry.get(tokenHash);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) registry.delete(tokenHash);
}


setInterval(() => {
  for (const set of registry.values()) {
    for (const ws of set) {
      if (alive.get(ws) === false) { ws.terminate(); continue; }
      alive.set(ws, false);
      try { ws.ping(); } catch { /* ignore */ }
    }
  }
}, HEARTBEAT_INTERVAL_MS).unref();

/** Close all open WebSocket connections for a given token hash (4001 = session revoked). */
export function closeSessionConnections(tokenHash: string): void {
  const set = registry.get(tokenHash);
  if (!set) return;
  for (const ws of set) {
    try { ws.close(4001, 'Session revoked'); } catch { /* ignore */ }
  }
  registry.delete(tokenHash);
}
