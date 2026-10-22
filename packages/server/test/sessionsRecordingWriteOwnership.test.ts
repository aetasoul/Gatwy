import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-recording-write-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'recording-write-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { initEncryption } = await import('../src/services/encryption.js');
const { default: sessionsRouter } = await import('../src/routes/sessions.js');
const { default: express } = await import('express');

const OWNER = 'u-rw-owner';
const AUDITOR = 'u-rw-auditor';
const CONN = 'c-rw';
const ORIGINAL = Buffer.from('original recording bytes');

let server: Server;
let baseUrl: string;
let ownerToken: string;
let auditorToken: string;

// Each test gets its own session and recording file, so one test's writes never leak into another's.
function seedSession(id: string): string {
  const file = path.join(dataDir, `${id}.webm`);
  fs.writeFileSync(file, ORIGINAL);
  execute(
    `INSERT INTO sessions (id, user_id, connection_id, protocol, username, connection_name, recording_path) VALUES (?, ?, ?, 'rdp', ?, ?, ?)`,
    [id, OWNER, CONN, OWNER, CONN, file],
  );
  return file;
}

before(async () => {
  await initDb();
  initJwt();
  initEncryption();

  // Can read everyone's recordings, but is not an admin: a read permission, not a write one.
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['auditor', 'Auditor', 'views all recordings', JSON.stringify(['sessions.view_own', 'sessions.view_any'])],
  );
  execute(`INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, 'user')`, [OWNER, OWNER, 'x', OWNER]);
  execute(`INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, 'auditor')`, [AUDITOR, AUDITOR, 'x', AUDITOR]);
  ownerToken = signToken({ userId: OWNER, username: OWNER, role: 'user' });
  auditorToken = signToken({ userId: AUDITOR, username: AUDITOR, role: 'auditor' });

  const app = express();
  app.use(express.json());
  app.use('/api/v1/sessions', sessionsRouter);
  await new Promise<void>((resolve) => { server = app.listen(0, resolve); });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}/api/v1/sessions`;
});

after(() => new Promise<void>((resolve) => server.close(() => {
  closeDb();
  fs.rmSync(dataDir, { recursive: true, force: true });
  resolve();
})));

const chunk = (token: string, id: string) =>
  fetch(`${baseUrl}/${id}/recording/chunk`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream' },
    body: Buffer.from('injected'),
  });

const finalize = (token: string, id: string) =>
  fetch(`${baseUrl}/${id}/recording/finalize`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });

describe('recording writes are owner-only, view_any stays read-only', () => {
  it('chunk from a view_any role is 403 and the recording file is left untouched', async () => {
    const id = '00000000-0000-4000-8000-0000000000c1';
    const file = seedSession(id);
    assert.equal((await chunk(auditorToken, id)).status, 403);
    assert.deepEqual(fs.readFileSync(file), ORIGINAL);
  });

  it('finalize from a view_any role is 403 and the session is not ended', async () => {
    const id = '00000000-0000-4000-8000-0000000000c2';
    seedSession(id);
    assert.equal((await finalize(auditorToken, id)).status, 403);
    assert.equal(queryOne<{ ended_at: string | null }>('SELECT ended_at FROM sessions WHERE id = ?', [id])?.ended_at, null);
  });

  it('view_any still reads: recording download and activity events are 200', async () => {
    const id = '00000000-0000-4000-8000-0000000000c3';
    seedSession(id);
    const rec = await fetch(`${baseUrl}/${id}/recording`, { headers: { Authorization: `Bearer ${auditorToken}` } });
    assert.equal(rec.status, 200);
    const events = await fetch(`${baseUrl}/${id}/recording/events`, { headers: { Authorization: `Bearer ${auditorToken}` } });
    assert.equal(events.status, 200);
  });

  it('the owner can still write: chunk then finalize are 200 and the session is ended', async () => {
    const id = '00000000-0000-4000-8000-0000000000c4';
    const file = seedSession(id);
    assert.equal((await chunk(ownerToken, id)).status, 200);
    assert.notDeepEqual(fs.readFileSync(file), ORIGINAL);
    assert.equal((await finalize(ownerToken, id)).status, 200);
    assert.ok(queryOne<{ ended_at: string | null }>('SELECT ended_at FROM sessions WHERE id = ?', [id])?.ended_at);
  });
});
