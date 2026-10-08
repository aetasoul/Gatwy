import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-moonlight-planting-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'moonlight-planting-test-secret';
process.env.GATWY_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

// Routes treat Moonlight as unavailable unless the runtime binary exists at /opt/moonlight-web.
// Pretend it does (that path only), so the real create/update handlers run on any machine.
const realExistsSync = fs.existsSync;
fs.existsSync = ((p: fs.PathLike) => {
  const normalized = String(p).replaceAll('\\', '/');
  return normalized.endsWith('/opt/moonlight-web/web-server') || realExistsSync(p);
}) as typeof fs.existsSync;

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { initEncryption } = await import('../src/services/encryption.js');
const { default: connectionsRouter } = await import('../src/routes/connections.js');
const { canAccessMoonlightHost } = await import('../src/ws/moonlightGuard.js');
const { stripServerManagedExtra } = await import('../src/services/moonlightPairing.js');
const { default: express } = await import('express');

const ATTACKER = 'user-planting-attacker';
const VICTIM = 'user-planting-victim';
const VICTIM_HOST = 4242;
const OWN_HOST = 7;

let server: Server;
let baseUrl: string;
let attackerToken: string;

before(async () => {
  await initDb();
  initJwt();
  initEncryption();

  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['planting-role', 'Planting Role', 'plain connection owner', JSON.stringify(['connections.create', 'connections.edit_own'])],
  );
  for (const [id, name] of [[ATTACKER, 'attacker'], [VICTIM, 'victim']]) {
    execute(
      `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
      [id, name, 'x', name, 'planting-role'],
    );
  }
  attackerToken = signToken({ userId: ATTACKER, username: 'attacker', role: 'planting-role' });

  // The victim's paired host: private, owned by someone else.
  execute(
    `INSERT INTO connections (id, user_id, name, protocol, host, port, extra_config_json, shared) VALUES (?, ?, ?, 'moonlight', ?, ?, ?, 0)`,
    ['conn-victim', VICTIM, 'Victim PC', '10.0.0.9', 47989, JSON.stringify({ paired: true, mlHostId: VICTIM_HOST })],
  );

  const app = express();
  app.use(express.json());
  app.use('/api/v1/connections', connectionsRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, resolve);
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}/api/v1/connections`;
});

after(() => new Promise<void>((resolve) => server.close(() => {
  fs.existsSync = realExistsSync;
  closeDb();
  fs.rmSync(dataDir, { recursive: true, force: true });
  resolve();
})));

function attackerFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attackerToken}`, ...(init.headers ?? {}) },
  });
}

function storedExtra(id: string): Record<string, unknown> {
  const row = queryOne<{ extra_config_json: string | null }>('SELECT extra_config_json FROM connections WHERE id = ?', [id]);
  return row?.extra_config_json ? JSON.parse(row.extra_config_json) as Record<string, unknown> : {};
}

describe('stripServerManagedExtra', () => {
  it('drops mlHostId and keeps everything else', () => {
    assert.deepEqual(stripServerManagedExtra({ mlHostId: 1, paired: true, fps: 60 }), { paired: true, fps: 60 });
  });

  it('passes non-objects through untouched', () => {
    assert.equal(stripServerManagedExtra(null), null);
    assert.equal(stripServerManagedExtra(undefined), undefined);
    assert.equal(stripServerManagedExtra('x'), 'x');
    assert.deepEqual(stripServerManagedExtra([1]), [1]);
  });
});

describe('a client cannot plant another user\'s mlHostId through the connection API', () => {
  it('sanity: the victim host is not reachable by the attacker to begin with', () => {
    assert.equal(canAccessMoonlightHost(VICTIM, VICTIM_HOST), true);
    assert.equal(canAccessMoonlightHost(ATTACKER, VICTIM_HOST), false);
  });

  it('POST / does not store a submitted mlHostId, so the stream check still refuses', async () => {
    const res = await attackerFetch(baseUrl, {
      method: 'POST',
      body: JSON.stringify({
        name: 'planted-on-create', protocol: 'moonlight', host: '10.0.0.1', port: 47989,
        extraConfig: { paired: true, mlHostId: VICTIM_HOST, fps: 30 },
      }),
    });
    assert.equal(res.status, 201);
    const { id } = await res.json() as { id: string };

    const extra = storedExtra(id);
    assert.equal('mlHostId' in extra, false, 'mlHostId must not be persisted from a client request');
    assert.equal(extra.fps, 30, 'other fields are still stored');

    assert.equal(canAccessMoonlightHost(ATTACKER, VICTIM_HOST), false);
  });

  it('PUT /:id does not merge a submitted mlHostId into a Moonlight connection', async () => {
    execute(
      `INSERT INTO connections (id, user_id, name, protocol, host, port, extra_config_json, shared) VALUES (?, ?, ?, 'moonlight', ?, ?, ?, 0)`,
      ['conn-attacker-ml', ATTACKER, 'Attacker PC', '10.0.0.2', 47989, JSON.stringify({ paired: true, mlHostId: OWN_HOST })],
    );
    assert.equal(canAccessMoonlightHost(ATTACKER, OWN_HOST), true);

    const res = await attackerFetch(`${baseUrl}/conn-attacker-ml`, {
      method: 'PUT',
      body: JSON.stringify({ extraConfig: { mlHostId: VICTIM_HOST, fps: 120 } }),
    });
    assert.equal(res.status, 200);

    const extra = storedExtra('conn-attacker-ml');
    assert.equal(extra.mlHostId, OWN_HOST, 'the server-managed value is left as the pairing flow set it');
    assert.equal(extra.fps, 120, 'other fields are still merged');
    assert.equal(canAccessMoonlightHost(ATTACKER, VICTIM_HOST), false);
    assert.equal(canAccessMoonlightHost(ATTACKER, OWN_HOST), true);
  });

  it('PUT /:id cannot plant mlHostId on a connection that has none yet', async () => {
    execute(
      `INSERT INTO connections (id, user_id, name, protocol, host, port, extra_config_json, shared) VALUES (?, ?, ?, 'moonlight', ?, ?, NULL, 0)`,
      ['conn-attacker-unpaired', ATTACKER, 'Unpaired PC', '10.0.0.3', 47989],
    );

    const res = await attackerFetch(`${baseUrl}/conn-attacker-unpaired`, {
      method: 'PUT',
      body: JSON.stringify({ extraConfig: { paired: true, mlHostId: VICTIM_HOST } }),
    });
    assert.equal(res.status, 200);

    assert.equal('mlHostId' in storedExtra('conn-attacker-unpaired'), false);
    assert.equal(canAccessMoonlightHost(ATTACKER, VICTIM_HOST), false);
  });

  it('PUT /:id keeps a round-tripped mlHostId from the client harmless (edit dialog resends the config)', async () => {
    const res = await attackerFetch(`${baseUrl}/conn-attacker-ml`, {
      method: 'PUT',
      body: JSON.stringify({ extraConfig: { mlHostId: OWN_HOST, fps: 90 } }),
    });
    assert.equal(res.status, 200);
    const extra = storedExtra('conn-attacker-ml');
    assert.equal(extra.mlHostId, OWN_HOST);
    assert.equal(extra.fps, 90);
  });
  it('PUT /:id cannot revive an mlHostId planted on a non-moonlight row by switching it to moonlight', async () => {
    for (const [id, body] of [
      ['conn-attacker-ssh-a', { protocol: 'moonlight', extraConfig: { fps: 60 } }],
      ['conn-attacker-ssh-b', { protocol: 'moonlight' }],
    ] as const) {
      // State left behind by an install that predates the strip: mlHostId on an ssh row.
      execute(
        `INSERT INTO connections (id, user_id, name, protocol, host, port, extra_config_json, shared) VALUES (?, ?, ?, 'ssh', ?, ?, ?, 0)`,
        [id, ATTACKER, id, '10.0.0.4', 22, JSON.stringify({ mlHostId: VICTIM_HOST })],
      );
      const res = await attackerFetch(`${baseUrl}/${id}`, { method: 'PUT', body: JSON.stringify(body) });
      assert.equal(res.status, 200);
      assert.equal('mlHostId' in storedExtra(id), false, id);
    }
    assert.equal(canAccessMoonlightHost(ATTACKER, VICTIM_HOST), false);
  });
});
