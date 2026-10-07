import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

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
const { default: express } = await import('express');
const { default: cookieParser } = await import('cookie-parser');

const OWNER = 'user-pb-owner';
const OTHER = 'user-pb-other';
const CONN = 'conn-pb-sftp';
const SESSION = '00000000-0000-4000-8000-0000000000aa';

let server: Server;
let base: string;
let ownerToken: string;
let otherToken: string;

before(async () => {
  await initDb();
  initJwt();
  initEncryption();
  for (const id of [OWNER, OTHER]) {
    execute(`INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, 'user')`, [id, id, 'x', id]);
  }
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

  const app = express();
  app.use(express.json({ limit: '6mb' }));
  app.use(cookieParser());
  app.use('/api/v1/sessions', sessionsRouter);
  app.use('/api/v1/backup', backupRouter);
  app.use('/api/v1/smb', smbRouter);
  app.use('/api/v1/sftp', sftpRouter);
  app.use('/api/v1/ftp', ftpRouter);
  await new Promise<void>(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});

after(async () => {
  await new Promise<void>(resolve => server.close(() => resolve()));
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
