import http from 'http';
import type { Server, IncomingMessage } from 'http';
import type { Duplex } from 'stream';
import { WebSocketServer, WebSocket, type RawData } from 'ws';
import {
  ensureMoonlightWeb,
  getMoonlightRuntimeError,
  isMoonlightWebAvailable,
  MOONLIGHT_UNAVAILABLE_BODY,
  moonlightProxyHeader,
  moonlightUpstream,
} from '../services/moonlightWeb.js';
import { authorizeMoonlightAccess } from './moonlightAuth.js';
import {
  canAccessMoonlightHost,
  classifyMoonlightRequest,
  isStreamRequestMessage,
  parseStreamRequest,
} from './moonlightGuard.js';
import { logAudit } from '../services/audit.js';
import { resolveClientIp } from '../services/ip.js';
import { injectGatwyMoonlightChrome, shouldThemeMoonlightHtml } from './moonlightChrome.js';

const PREFIX = '/mlw';

/**
 * CSP for proxied /mlw documents only. STUN/TURN stay off the global helmet
 * policy in index.ts so WebRTC ICE cannot probe topology from the main app.
 */
export const MLW_FRAME_CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline'",
  "connect-src 'self' wss: ws: blob: stun: turn:",
  "img-src 'self' data: blob:",
  "media-src 'self' blob:",
  "style-src 'self' 'unsafe-inline'",
  "worker-src 'self' blob:",
  "frame-ancestors 'self'",
].join('; ');

function shouldProxy(url: string | undefined, prefix: string): boolean {
  if (!url) return false;
  return url === prefix || url.startsWith(`${prefix}/`) || url.startsWith(`${prefix}?`);
}

function unavailableBody() {
  const runtimeError = getMoonlightRuntimeError();
  if (!runtimeError) return MOONLIGHT_UNAVAILABLE_BODY;
  return { ...MOONLIGHT_UNAVAILABLE_BODY, error: runtimeError };
}

function writeUpgradeError(socket: Duplex, status: number, reason: string): void {
  socket.write(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`);
  socket.destroy();
}

const FIRST_MESSAGE_TIMEOUT_MS = 10_000;
/** Client messages buffered while the upstream socket is still connecting. */
const MAX_PENDING_BYTES = 1024 * 1024;
/** Unflushed upstream->client bytes at which the upstream socket is paused / resumed. */
const HIGH_WATER_BYTES = 8 * 1024 * 1024;
const LOW_WATER_BYTES = 2 * 1024 * 1024;

function rawBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data);
}

/**
 * Terminate the stream WebSocket in Gatwy instead of piping raw bytes: moonlight-web reads
 * `host_id` from the first message and cannot tell Gatwy users apart, so Gatwy holds the
 * client until that message is validated against the user's accessible connections and
 * only then opens the upstream socket and forwards the re-serialized message.
 */
export function bridgeStream(
  client: WebSocket,
  userId: string,
  req: IncomingMessage,
  path: string,
  header: { name: string; value: string },
  target: { host: string; port: number } = moonlightUpstream(),
): void {
  let upstream: WebSocket | null = null;
  let started = false;
  let upstreamOpen = false;
  const pending: { data: RawData; isBinary: boolean }[] = [];
  let pendingBytes = 0;
  let inflight = 0;
  let paused = false;

  const reject = (reason: string) => {
    clearTimeout(timer);
    if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CONNECTING) {
      client.close(1008, reason);
    }
    upstream?.terminate();
  };
  const timer = setTimeout(() => reject('No stream request'), FIRST_MESSAGE_TIMEOUT_MS);

  const connectUpstream = (forward: string) => {
    const headers: Record<string, string> = { [header.name]: header.value };
    if (typeof req.headers.origin === 'string') headers.origin = req.headers.origin;
    if (typeof req.headers['user-agent'] === 'string') headers['user-agent'] = req.headers['user-agent'];

    const ws = new WebSocket(`ws://${target.host}:${target.port}${path}`, { headers, perMessageDeflate: false });
    upstream = ws;

    ws.on('open', () => {
      upstreamOpen = true;
      ws.send(forward);
      for (const m of pending.splice(0)) ws.send(m.data, { binary: m.isBinary });
      pendingBytes = 0;
    });
    ws.on('message', (data, isBinary) => {
      if (client.readyState !== WebSocket.OPEN) return;
      const length = rawBuffer(data).length;
      inflight += length;
      client.send(data, { binary: isBinary }, () => {
        inflight -= length;
        if (paused && inflight <= LOW_WATER_BYTES) {
          paused = false;
          ws.resume();
        }
      });
      if (!paused && inflight >= HIGH_WATER_BYTES) {
        paused = true;
        ws.pause();
      }
    });
    ws.on('close', () => {
      if (client.readyState === WebSocket.OPEN) client.close();
    });
    ws.on('unexpected-response', () => reject('Moonlight upstream refused the stream'));
    ws.on('error', () => reject('Moonlight upstream error'));
  };

  client.on('message', (data, isBinary) => {
    if (!started) {
      started = true;
      clearTimeout(timer);
      if (isBinary) { reject('Expected a stream request'); return; }
      const request = parseStreamRequest(rawBuffer(data).toString('utf8'));
      if (!request.ok) { reject(request.reason); return; }
      if (!canAccessMoonlightHost(userId, request.hostId)) {
        // `path` is the classified path (never the raw URL), so no query string reaches the log.
        logAudit({
          userId, eventType: 'session.moonlight.denied',
          target: path,
          details: { hostId: request.hostId, reason: 'Host not permitted' },
          ipAddress: resolveClientIp(req),
        });
        reject('Host not permitted');
        return;
      }
      connectUpstream(request.forward);
      return;
    }

    // The target host is fixed by the first message; a later request is never legitimate.
    if (!isBinary && isStreamRequestMessage(rawBuffer(data).toString('utf8'))) {
      reject('Unexpected stream request');
      return;
    }

    if (upstream && upstreamOpen) {
      upstream.send(data, { binary: isBinary });
      return;
    }
    pendingBytes += rawBuffer(data).length;
    if (pendingBytes > MAX_PENDING_BYTES) { reject('Too much data before the stream started'); return; }
    pending.push({ data, isBinary });
  });
  client.on('close', () => {
    clearTimeout(timer);
    upstream?.terminate();
  });
  client.on('error', () => reject('Client error'));
}

/**
 * Reverse-proxy moonlight-web (HTTP + WebSocket) under /mlw.
 * HTTP GET/HEAD/POST /mlw/* and the WS upgrade use the same authorizeMoonlightAccess()
 * check: JWT cookie (or Bearer) + login session + protocols.moonlight + runtime.
 */
export function setupMoonlightProxy(server: Server, app: import('express').Express, basePath = ''): void {
  const header = moonlightProxyHeader();
  const mountPrefix = `${basePath}${PREFIX}`;

  app.use(mountPrefix, async (req, res) => {
    const auth = authorizeMoonlightAccess(req);
    if (!auth.ok) {
      if (auth.status === 503) {
        res.status(503).json(unavailableBody());
        return;
      }
      res.status(auth.status).json({ error: auth.error });
      return;
    }

    if (!isMoonlightWebAvailable()) {
      res.status(503).json(unavailableBody());
      return;
    }

    // Fail-closed allowlist; the normalized path is what gets forwarded, never the raw URL.
    const decision = classifyMoonlightRequest(req.method, req.originalUrl, false, mountPrefix);
    if (decision.kind !== 'http') {
      res.status(decision.kind === 'deny' ? decision.status : 403).json({ error: 'Forbidden' });
      return;
    }

    try {
      await ensureMoonlightWeb();
    } catch (err) {
      res.status(503).json({
        error: err instanceof Error ? err.message : 'Moonlight unavailable',
        available: false,
      });
      return;
    }

    const upstream = moonlightUpstream();
    // decision.path carries the full mount prefix: moonlight-web runs with BASE_PATH + /mlw.
    const targetPath = `${decision.path}${decision.search}`;

    const headers: http.OutgoingHttpHeaders = { ...req.headers, host: `${upstream.host}:${upstream.port}` };
    headers[header.name] = header.value;
    // Don't forward Gatwy credentials to the third-party binary.
    delete headers['authorization'];
    delete headers['cookie'];
    delete headers['content-length'];

    const proxyReq = http.request(
      {
        host: upstream.host,
        port: upstream.port,
        path: targetPath,
        method: req.method,
        headers,
      },
      (proxyRes) => {
        const outHeaders: http.OutgoingHttpHeaders = { ...proxyRes.headers };
        delete outHeaders['content-security-policy'];
        delete outHeaders['content-security-policy-report-only'];
        outHeaders['content-security-policy'] = MLW_FRAME_CSP;

        const contentType = String(proxyRes.headers['content-type'] || '');
        const encoding = String(proxyRes.headers['content-encoding'] || '');
        // stream.html only: inject Gatwy HUD CSS/script before moonlight-web JS runs.
        const themeHtml = shouldThemeMoonlightHtml(targetPath)
          && contentType.includes('text/html')
          && (!encoding || encoding === 'identity');

        if (!themeHtml) {
          res.writeHead(proxyRes.statusCode ?? 502, outHeaders);
          proxyRes.pipe(res);
          return;
        }

        const chunks: Buffer[] = [];
        proxyRes.on('data', (chunk) => chunks.push(chunk));
        proxyRes.on('end', () => {
          const html = injectGatwyMoonlightChrome(Buffer.concat(chunks).toString('utf8'), basePath);
          const body = Buffer.from(html, 'utf8');
          outHeaders['content-length'] = body.length;
          res.writeHead(proxyRes.statusCode ?? 502, outHeaders);
          res.end(body);
        });
      },
    );

    proxyReq.on('error', (err) => {
      if (!res.headersSent) {
        res.status(502).json({ error: `Moonlight proxy error: ${err.message}` });
      } else {
        res.end();
      }
    });

    req.pipe(proxyReq);
  });

  const streamWss = new WebSocketServer({ noServer: true, perMessageDeflate: false });

  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    const url = req.url ?? '';
    if (!shouldProxy(url, mountPrefix)) return;

    const auth = authorizeMoonlightAccess(req);
    if (!auth.ok) {
      const reason = auth.status === 403 ? 'Forbidden'
        : auth.status === 503 ? 'Service Unavailable'
          : 'Unauthorized';
      writeUpgradeError(socket, auth.status, reason);
      return;
    }

    if (!isMoonlightWebAvailable()) {
      writeUpgradeError(socket, 503, 'Service Unavailable');
      return;
    }

    // Only the stream WebSocket is reachable; the host it targets is checked in bridgeStream().
    const decision = classifyMoonlightRequest(req.method ?? 'GET', url, true, mountPrefix);
    if (decision.kind !== 'stream-ws') {
      writeUpgradeError(socket, 403, 'Forbidden');
      return;
    }

    void (async () => {
      try {
        await ensureMoonlightWeb();
      } catch {
        writeUpgradeError(socket, 503, 'Service Unavailable');
        return;
      }

      streamWss.handleUpgrade(req, socket, head, (client) => {
        bridgeStream(client, auth.userId, req, decision.path, header);
      });
    })();
  });
}
