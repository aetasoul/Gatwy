import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import http, { type Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-prebody-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'prebody-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { initEncryption } = await import('../src/services/encryption.js');
const { default: sftpRouter } = await import('../src/routes/sftp.js');
const { default: smbRouter } = await import('../src/routes/smb.js');
const { default: ftpRouter } = await import('../src/routes/ftp.js');
const { default: sessionsRouter } = await import('../src/routes/sessions.js');
const { default: backupRouter } = await import('../src/routes/backup.js');
const { default: settingsRouter } = await import('../src/routes/settings.js');
const { default: connectionsRouter } = await import('../src/routes/connections.js');
const { createGlobalJsonParser } = await import('../src/middleware/bodyParsers.js');
const { default: express } = await import('express');
const { default: cookieParser } = await import('cookie-parser');

const OWNER = 'user-pb-owner';
const OTHER = 'user-pb-other';
const ADMIN = 'user-pb-admin';
const CONN = 'conn-pb-sftp';
const SESSION = '00000000-0000-4000-8000-0000000000aa';

const PREFIX = '/sys/ftp';

let server: Server;
let base: string;
let prefixedServer: Server;
let prefixedBase: string;
let ownerToken: string;
let otherToken: string;
let adminToken: string;

before(async () => {
  await initDb();
  initJwt();
  initEncryption();
  for (const id of [OWNER, OTHER]) {
    execute(`INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, 'user')`, [id, id, 'x', id]);
  }
  execute(`INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, 'admin')`, [ADMIN, ADMIN, 'x', ADMIN]);
  adminToken = signToken({ userId: ADMIN, username: ADMIN, role: 'admin' });
  ownerToken = signToken({ userId: OWNER, username: OWNER, role: 'user' });
  otherToken = signToken({ userId: OTHER, username: OTHER, role: 'user' });
  execute(
    `INSERT INTO connections (id, user_id, group_id, name, protocol, host, port, shared) VALUES (?, ?, NULL, ?, 'sftp', '127.0.0.1', 1, 0)`,
    [CONN, OWNER, CONN],
  );
  execute(
    `INSERT INTO sessions (id, user_id, connection_id, protocol, username, connection_name) VALUES (?, ?, ?, 'rdp', ?, ?)`,
    [SESSION, OWNER, CONN, OWNER, CONN],
  );

  // Same wiring as index.ts; `bp` is config.basePathPrefix ('' at root, '/sys/ftp' behind a proxy prefix).
  const buildApp = (bp: string) => {
    const app = express();
    app.use(createGlobalJsonParser(bp));
    app.use(cookieParser());
    app.post(`${bp}/api/v1/auth/login`, (_req, res) => { res.json({ ok: true }); }); // stand-in for any pre-auth JSON route
    app.use(`${bp}/api/v1/settings`, settingsRouter);
    app.use(`${bp}/api/v1/connections`, connectionsRouter);
    app.use(`${bp}/api/v1/sessions`, sessionsRouter);
    app.use(`${bp}/api/v1/backup`, backupRouter);
    app.use(`${bp}/api/v1/smb`, smbRouter);
    app.use(`${bp}/api/v1/sftp`, sftpRouter);
    app.use(`${bp}/api/v1/ftp`, ftpRouter);
    return app;
  };
  const listen = (app: ReturnType<typeof buildApp>) => new Promise<Server>(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const url = (s: Server) => `http://127.0.0.1:${(s.address() as { port: number }).port}`;
  server = await listen(buildApp(''));
  base = url(server);
  prefixedServer = await listen(buildApp(PREFIX));
  prefixedBase = url(prefixedServer);
});

after(async () => {
  await new Promise<void>(resolve => server.close(() => resolve()));
  await new Promise<void>(resolve => prefixedServer.close(() => resolve()));
  closeDb();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

function post(url: string, token?: string): Promise<Response> {
  return fetch(base + url, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: Buffer.alloc(1024, 1),
  });
}

describe('raw-body routes reject before buffering', () => {
  for (const proto of ['sftp', 'smb', 'ftp']) {
    it(`${proto} upload: anonymous → 401`, async () => {
      assert.equal((await post(`/api/v1/${proto}/${CONN}/upload?path=/x`)).status, 401);
    });
  }
  it('backup import: anonymous → 401, role without settings.backup → 403', async () => {
    assert.equal((await post('/api/v1/backup/import')).status, 401);
    assert.equal((await post('/api/v1/backup/import', ownerToken)).status, 403);
  });
  it('sftp upload to another user\'s private connection → 404', async () => {
    assert.equal((await post(`/api/v1/sftp/${CONN}/upload?path=/x`, otherToken)).status, 404);
  });
  it('smb/ftp upload against a connection of another protocol → 404', async () => {
    assert.equal((await post(`/api/v1/smb/${CONN}/upload?path=/x`, ownerToken)).status, 404);
    assert.equal((await post(`/api/v1/ftp/${CONN}/upload?path=/x`, ownerToken)).status, 404);
  });
  it('sftp upload to own connection passes the guard (fails later, on the unreachable host)', async () => {
    assert.equal((await post(`/api/v1/sftp/${CONN}/upload?path=/x`, ownerToken)).status, 500);
  });
  it('recording chunk: non-owner → 403, unknown → 404, bad id → 400, owner → 200', async () => {
    assert.equal((await post(`/api/v1/sessions/${SESSION}/recording/chunk`, otherToken)).status, 403);
    assert.equal((await post('/api/v1/sessions/00000000-0000-4000-8000-0000000000bb/recording/chunk', ownerToken)).status, 404);
    assert.equal((await post('/api/v1/sessions/not-a-uuid/recording/chunk', ownerToken)).status, 400);
    assert.equal((await post(`/api/v1/sessions/${SESSION}/recording/chunk`, ownerToken)).status, 200);
  });
});

// Sends a request whose body is declared (or streamed) far beyond what we are willing to buffer
// and reports the status plus how many body bytes the client had written when the response
// arrived — a server that buffers first cannot answer until the whole body is in. (The server may
// keep draining and discarding the rest afterwards; that is not buffering.)
function bigRequest(opts: { method: string; url: string; token?: string; chunked?: boolean; base?: string }): Promise<{ status: number; written: number; reset: boolean }> {
  const CHUNK = Buffer.alloc(64 * 1024, 0x61);
  const TOTAL = 64 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    let written = 0;
    let writtenAtResponse = -1;
    let status = 0;
    let finished = false;
    let reset = false;
    const done = () => { if (!finished) { finished = true; resolve({ status, reset, written: writtenAtResponse < 0 ? written : writtenAtResponse }); } };
    const req = http.request((opts.base ?? base) + opts.url, {
      method: opts.method,
      headers: {
        'content-type': 'application/json',
        ...(opts.chunked ? {} : { 'content-length': String(TOTAL) }),
        ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      },
    }, res => { status = res.statusCode ?? 0; writtenAtResponse = written; res.resume(); res.on('end', done); res.on('close', done); });
    req.on('error', err => { // the server may cut the connection right after (or instead of) answering
      if ((err as NodeJS.ErrnoException).code === 'ECONNRESET' || (err as NodeJS.ErrnoException).code === 'EPIPE') { reset = true; done(); } else if (!finished) reject(err);
    });
    const pump = () => {
      while (!finished && writtenAtResponse < 0 && written < TOTAL) {
        written += CHUNK.length;
        if (!req.write(CHUNK)) { req.once('drain', pump); return; }
      }
      req.end();
    };
    pump();
    setTimeout(() => { req.destroy(); done(); }, 8000).unref();
  });
}

describe('JSON body parsing is bounded before authentication', () => {
  // A 64 MB body must be refused long before it has been consumed (anything under ~16 MB sent is "early").
  const EARLY = 16 * 1024 * 1024;

  it('anonymous request with an oversized Content-Length → 413, body not consumed', async () => {
    const r = await bigRequest({ method: 'POST', url: '/api/v1/auth/login' });
    assert.ok(r.status === 413 || r.reset, `status ${r.status}, reset ${r.reset}`);
    assert.ok(r.written < EARLY, `client had written ${r.written} bytes when the response arrived`);
  });
  it('anonymous chunked (no Content-Length) request → rejected once the limit is passed', async () => {
    const r = await bigRequest({ method: 'POST', url: '/api/v1/auth/login', chunked: true });
    assert.ok(r.status === 413 || r.reset, `status ${r.status}, reset ${r.reset}`);
    assert.ok(r.written < EARLY, `client had written ${r.written} bytes when the response arrived`);
  });
  it('a body just over the default limit is refused, a small one is accepted', async () => {
    const big = await fetch(base + '/api/v1/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ x: 'a'.repeat(200 * 1024) }) });
    assert.equal(big.status, 413);
    const small = await fetch(base + '/api/v1/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ x: 'a' }) });
    assert.equal(small.status, 200);
  });
  it('settings PUT (logo route): anonymous → 401 and non-admin → 403 without consuming the body', async () => {
    const anon = await bigRequest({ method: 'PUT', url: '/api/v1/settings' });
    assert.equal(anon.status, 401);
    assert.ok(anon.written < EARLY, `client wrote ${anon.written} bytes before the rejection`);
    const user = await bigRequest({ method: 'PUT', url: '/api/v1/settings', token: ownerToken });
    assert.equal(user.status, 403);
    assert.ok(user.written < EARLY, `client wrote ${user.written} bytes before the rejection`);
  });
  it('settings PUT keeps the larger logo limit for an admin (5 MB ok, past 6 MB → 413)', async () => {
    const put = (len: number) => fetch(base + '/api/v1/settings', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ 'app.logo': 'a'.repeat(len) }),
    });
    assert.equal((await put(5 * 1024 * 1024)).status, 200);
    assert.equal((await put(7 * 1024 * 1024)).status, 413);
  });
  it('the logo-route exemption is not bypassed by case or a trailing slash', async () => {
    for (const url of ['/API/v1/Settings', '/api/v1/settings/']) {
      const r = await bigRequest({ method: 'PUT', url });
      assert.equal(r.status, 401, url);
      assert.ok(r.written < EARLY, `${url}: client wrote ${r.written} bytes`);
    }
  });
});

describe('behind a reverse-proxy path prefix (BASE_PATH)', () => {
  const EARLY = 16 * 1024 * 1024;
  const json = (path: string, method: string, len: number, token?: string) => fetch(prefixedBase + path, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ 'app.logo': 'a'.repeat(len) }),
  });

  it('the global limit still applies to pre-auth routes', async () => {
    assert.equal((await json(`${PREFIX}/api/v1/auth/login`, 'POST', 200 * 1024)).status, 413);
    assert.equal((await json(`${PREFIX}/api/v1/auth/login`, 'POST', 10)).status, 200);
  });
  it('settings PUT keeps the larger logo limit for an admin (300 KB and 5 MB ok, past 6 MB → 413)', async () => {
    for (const len of [300 * 1024, 5 * 1024 * 1024]) {
      assert.equal((await json(`${PREFIX}/api/v1/settings`, 'PUT', len, adminToken)).status, 200, `${len} bytes`);
    }
    assert.equal((await json(`${PREFIX}/api/v1/settings`, 'PUT', 7 * 1024 * 1024, adminToken)).status, 413);
  });
  it('connections import is not capped by the global parser (300 KB reaches the handler)', async () => {
    const r = await json(`${PREFIX}/api/v1/connections/import`, 'POST', 300 * 1024, adminToken);
    assert.notEqual(r.status, 413);
  });
  it('the exemption does not leak: anonymous / non-admin settings PUT is refused without consuming the body', async () => {
    const anon = await bigRequest({ method: 'PUT', url: `${PREFIX}/api/v1/settings`, base: prefixedBase });
    assert.equal(anon.status, 401);
    assert.ok(anon.written < EARLY, `client wrote ${anon.written} bytes before the rejection`);
    const user = await bigRequest({ method: 'PUT', url: `${PREFIX}/api/v1/settings`, token: ownerToken, base: prefixedBase });
    assert.equal(user.status, 403);
    assert.ok(user.written < EARLY, `client wrote ${user.written} bytes before the rejection`);
  });
  it('case and trailing slash do not bypass the exemption under a prefix either', async () => {
    for (const url of [`${PREFIX.toUpperCase()}/API/v1/Settings`, `${PREFIX}/api/v1/settings/`]) {
      const r = await bigRequest({ method: 'PUT', url, base: prefixedBase });
      assert.equal(r.status, 401, url);
      assert.ok(r.written < EARLY, `${url}: client wrote ${r.written} bytes`);
    }
  });
});
