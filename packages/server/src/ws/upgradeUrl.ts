import type { IncomingMessage } from 'http';

/**
 * Parse the request target of a WebSocket upgrade into a URL, or return null if it cannot be
 * parsed. The proxies only read the path and the query string, so the base is a fixed placeholder:
 * building it from the client supplied Host header made `new URL` throw on a malformed Host
 * (for example `a%zz`), and that exception ended the whole process. A request target can also be
 * unparseable on its own (`//a%zz`), hence the try/catch.
 */
export function parseUpgradeUrl(req: IncomingMessage): URL | null {
  try {
    return new URL(req.url || '', 'https://localhost');
  } catch {
    return null;
  }
}
