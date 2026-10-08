import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-filesessions-csv-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'file-sessions-csv-export-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: fileSessionsRouter } = await import('../src/routes/file-sessions.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let token: string;
const userId = 'user-fs-csv';
const sessionId = 'fs-csv-session';

before(async () => {
  await initDb();
  initJwt();

  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    [userId, '=cmd|calc', 'x', 'FS CSV', 'admin'],
  );
  token = signToken({ userId, username: '=cmd|calc', role: 'admin' });
  execute(
    `INSERT INTO connections (id, user_id, group_id, name, protocol, host, port)
     VALUES ('conn-fs-csv', ?, NULL, '+HYPERLINK("x")', 'sftp', 'h', 22)`,
    [userId],
  );
  execute(
    `INSERT INTO file_sessions (id, user_id, connection_id, protocol, started_at) VALUES (?, ?, 'conn-fs-csv', 'sftp', '2026-10-07 10:00:00')`,
    [sessionId, userId],
  );
  execute(
    `INSERT INTO file_session_events (id, session_id, action, path, detail_json) VALUES
       ('ev-1', ?, 'upload', '=HYPERLINK("http://evil.example","x")', '{"size":1}'),
       ('ev-2', ?, 'download', '/home/user/report.txt', NULL)`,
    [sessionId, sessionId],
  );

  const app = express();
  app.use('/api/v1/file-sessions', fileSessionsRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, resolve);
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}/api/v1/file-sessions`;
});

after(() => new Promise<void>((resolve) => {
  server.close(() => {
    closeDb();
    fs.rmSync(dataDir, { recursive: true, force: true });
    resolve();
  });
  server.closeAllConnections();
}));

describe('file-sessions CSV export', () => {
  it('prefixes formula-looking path, connection and username so spreadsheets read them as text', async () => {
    const res = await fetch(`${baseUrl}/${sessionId}/export?format=csv`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const lines = (await res.text()).split('\n');
    assert.equal(lines.length, 3);
    const upload = lines.find((l) => l.includes(',upload,'))!;
    assert.ok(upload.includes(`"'=HYPERLINK(""http://evil.example"",""x"")"`), upload);
    assert.ok(upload.includes(`"'+HYPERLINK(""x"")"`), 'connection name must be neutralised');
    assert.ok(upload.includes(`"'=cmd|calc"`), 'username must be neutralised');
  });

  it('leaves the JSON export unchanged (formula characters are data there)', async () => {
    const res = await fetch(`${baseUrl}/${sessionId}/export?format=json`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await res.json() as { events: Array<{ path: string }> };
    assert.ok(body.events.some((e) => e.path === '=HYPERLINK("http://evil.example","x")'));
  });
});
