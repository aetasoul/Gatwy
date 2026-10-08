import assert from 'node:assert/strict';
import { describe, it, before, after, afterEach } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-rdp-in-use-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'rdp-in-use-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute } = await import('../src/db/helpers.js');
const { getPermissionsForRole } = await import('../src/services/permissions.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: sessionsRouter } = await import('../src/routes/sessions.js');
const { addActiveSession, listActiveSessions, removeActiveSession, targetKey } = await import('../src/ws/activeSessions.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let aliceToken: string;
let noRdpToken: string;

before(async () => {
  await initDb();
  initJwt();

  for (const [id, role] of [['u-alice', 'user'], ['u-bob', 'user']] as const) {
    execute(`INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`, [id, id, 'x', id, role]);
  }
  aliceToken = signToken({ userId: 'u-alice', username: 'u-alice', role: 'user' });
  // A role that may use connections but not the RDP protocol: the proxy would refuse it, so must this route.
  execute(`INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES ('no-rdp', 'No RDP', '', 0, ?)`,
    [JSON.stringify(getPermissionsForRole('user').filter((p: string) => p !== 'protocols.rdp'))]);
  execute(`INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`, ['u-nordp', 'u-nordp', 'x', 'u-nordp', 'no-rdp']);
  noRdpToken = signToken({ userId: 'u-nordp', username: 'u-nordp', role: 'no-rdp' });

  const conn = (id: string, owner: string, protocol: string, host: string, port: number) =>
    execute(`INSERT INTO connections (id, user_id, name, protocol, host, port) VALUES (?, ?, ?, ?, ?, ?)`, [id, owner, id, protocol, host, port]);
  conn('c-alice-rdp', 'u-alice', 'rdp', 'Win-Host.lan', 3389);
  conn('c-bob-same-host', 'u-bob', 'rdp', 'win-host.LAN', 3389); // another record, same machine
  conn('c-alice-ssh', 'u-alice', 'ssh', 'win-host.lan', 22);
  conn('c-bob-private', 'u-bob', 'rdp', 'private-host', 3389); // Alice cannot open this one
  conn('c-bob-shared-all', 'u-bob', 'rdp', 'shared-all-host', 3389);
  execute(`UPDATE connections SET shared = 1 WHERE id = 'c-bob-shared-all'`);
  conn('c-bob-shared-user', 'u-bob', 'rdp', 'shared-user-host', 3389);
  execute(`INSERT INTO resource_shares (id, resource_type, resource_id, share_type, target_id, capability) VALUES ('rs-1', 'connection', 'c-bob-shared-user', 'user', 'u-alice', 'view')`);
  conn('c-nordp', 'u-nordp', 'rdp', 'win-host.lan', 3389);

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

afterEach(() => { for (const s of listActiveSessions()) removeActiveSession(s.id); });

const ask = (connectionId?: string, token = aliceToken) =>
  fetch(`${baseUrl}/rdp-in-use${connectionId === undefined ? '' : `?connectionId=${connectionId}`}`,
    { headers: { Authorization: `Bearer ${token}` } });

function session(id: string, userId: string, protocol: 'rdp' | 'ssh', host: string, port: number) {
  addActiveSession({ id, userId, connectionId: 'x', connectionName: 'x', protocol, target: targetKey(host, port), end: () => {} });
}

describe('GET /rdp-in-use', () => {
  it('requires a connectionId', async () => {
    assert.equal((await ask()).status, 400);
  });

  it('answers 404 for a connection the caller cannot open, so existence is not revealed', async () => {
    session('s1', 'u-bob', 'rdp', 'private-host', 3389);
    assert.equal((await ask('c-bob-private')).status, 404);
    assert.equal((await ask('does-not-exist')).status, 404);
  });

  it('answers 404 for a connection that is not RDP', async () => {
    assert.equal((await ask('c-alice-ssh')).status, 404);
  });

  it('says false when nobody else is on the host', async () => {
    const res = await ask('c-alice-rdp');
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { inUse: false });
  });

  it('says true when another user is connected to the same host and port, through any connection record', async () => {
    session('s2', 'u-bob', 'rdp', 'win-host.lan', 3389);
    assert.deepEqual(await (await ask('c-alice-rdp')).json(), { inUse: true });
  });

  it('matches the host without regard to case', async () => {
    session('s3', 'u-bob', 'rdp', 'WIN-HOST.LAN', 3389);
    assert.deepEqual(await (await ask('c-alice-rdp')).json(), { inUse: true });
  });

  it('ignores the caller\'s own session', async () => {
    session('s4', 'u-alice', 'rdp', 'win-host.lan', 3389);
    assert.deepEqual(await (await ask('c-alice-rdp')).json(), { inUse: false });
  });

  it('ignores another port and other protocols on the same host', async () => {
    session('s5', 'u-bob', 'rdp', 'win-host.lan', 3390);
    session('s6', 'u-bob', 'ssh', 'win-host.lan', 3389);
    assert.deepEqual(await (await ask('c-alice-rdp')).json(), { inUse: false });
  });

  it('works for a connection shared with everyone and for one shared with the caller by user', async () => {
    session('s8', 'u-bob', 'rdp', 'shared-all-host', 3389);
    session('s9', 'u-bob', 'rdp', 'shared-user-host', 3389);
    assert.deepEqual(await (await ask('c-bob-shared-all')).json(), { inUse: true });
    assert.deepEqual(await (await ask('c-bob-shared-user')).json(), { inUse: true });
  });

  it('is refused with 403 for a role that may not use RDP, like the proxy', async () => {
    session('s10', 'u-bob', 'rdp', 'win-host.lan', 3389);
    assert.equal((await ask('c-nordp', noRdpToken)).status, 403);
  });

  it('reveals nothing but the flag', async () => {
    session('s7', 'u-bob', 'rdp', 'win-host.lan', 3389);
    const body = await (await ask('c-alice-rdp')).json() as Record<string, unknown>;
    assert.deepEqual(Object.keys(body), ['inUse']);
  });
});
