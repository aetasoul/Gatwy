import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';


const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-connshare-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'connections-share-permission-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: connectionsRouter } = await import('../src/routes/connections.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let noShareToken: string;
let withShareToken: string;
let editAnyNoShareToken: string;

before(async () => {
  await initDb();
  initJwt();

  // Has connections.create/edit_own/import_export but NOT connections.share.
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['no-share', 'No Share', 'can manage own connections, cannot share', JSON.stringify([
      'connections.create', 'connections.edit_own', 'connections.import_export',
    ])],
  );
  // Same as above, plus connections.share — the control group.
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['with-share', 'With Share', 'can also share', JSON.stringify([
      'connections.create', 'connections.edit_own', 'connections.import_export', 'connections.share',
    ])],
  );
  // Can edit ANYONE's connection but still not share — for the downgrade case.
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['edit-any-no-share', 'Edit Any No Share', 'admin-ish, cannot share', JSON.stringify([
      'connections.edit_any',
    ])],
  );

  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    ['user-no-share', 'no-share-user', 'x', 'No Share User', 'no-share'],
  );
  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    ['user-with-share', 'with-share-user', 'x', 'With Share User', 'with-share'],
  );
  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    ['user-edit-any-no-share', 'edit-any-no-share-user', 'x', 'Edit Any No Share User', 'edit-any-no-share'],
  );

  noShareToken = signToken({ userId: 'user-no-share', username: 'no-share-user', role: 'no-share' });
  withShareToken = signToken({ userId: 'user-with-share', username: 'with-share-user', role: 'with-share' });
  editAnyNoShareToken = signToken({ userId: 'user-edit-any-no-share', username: 'edit-any-no-share-user', role: 'edit-any-no-share' });

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
  // Without this the autosave interval (see closeDb in db/index.ts) keeps node --test alive.
  closeDb();
  fs.rmSync(dataDir, { recursive: true, force: true });
  resolve();
})));

function authedFetch(token: string, url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
  });
}

describe('POST / — connections.share required only to create as globally shared', () => {
  it('rejects shared:true without connections.share', async () => {
    const res = await authedFetch(noShareToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'c1', protocol: 'ssh', host: 'h', port: 22, shared: true }),
    });
    assert.equal(res.status, 403);
  });

  it('allows shared:true with connections.share', async () => {
    const res = await authedFetch(withShareToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'c2', protocol: 'ssh', host: 'h', port: 22, shared: true }),
    });
    assert.equal(res.status, 201);
    const body = await res.json() as { id: string };
    const row = queryOne<{ shared: number }>('SELECT shared FROM connections WHERE id = ?', [body.id]);
    assert.equal(row?.shared, 1);
  });

  it('allows creating a connection without connections.share when `shared` is omitted', async () => {
    const res = await authedFetch(noShareToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'c3', protocol: 'ssh', host: 'h', port: 22 }),
    });
    assert.equal(res.status, 201);
  });

  // The real client (ConnectionModal.tsx) always sends `shared` in the body, even for a
  // brand-new connection where sharing was never enabled (defaults to false) — a role
  // without connections.share must still be able to create connections at all.
  it('allows shared:false explicitly without connections.share (client always sends this field)', async () => {
    const res = await authedFetch(noShareToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'c4', protocol: 'ssh', host: 'h', port: 22, shared: false }),
    });
    assert.equal(res.status, 201);
  });
});

describe('PUT /:id — connections.share required only when `shared` actually changes', () => {
  let ownConnectionId: string;

  before(async () => {
    const res = await authedFetch(noShareToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'own-conn', protocol: 'ssh', host: 'h', port: 22 }),
    });
    const body = await res.json() as { id: string };
    ownConnectionId = body.id;
  });

  it('rejects setting shared:true on own connection without connections.share', async () => {
    const res = await authedFetch(noShareToken, `${baseUrl}/${ownConnectionId}`, {
      method: 'PUT',
      body: JSON.stringify({ shared: true }),
    });
    assert.equal(res.status, 403);
    const row = queryOne<{ shared: number }>('SELECT shared FROM connections WHERE id = ?', [ownConnectionId]);
    assert.equal(row?.shared, 0, 'shared flag must not have been flipped by the rejected request');
  });

  // This is the regression case: the real edit form always sends `shared` on every save,
  // including a no-op save where it's already false. A role without connections.share must
  // still be able to save the connection — only an actual change to `shared` needs the permission.
  it('allows shared:false when the connection is already shared=0 (no-op, matches the real edit form)', async () => {
    const res = await authedFetch(noShareToken, `${baseUrl}/${ownConnectionId}`, {
      method: 'PUT',
      body: JSON.stringify({ name: 'still-not-shared', shared: false }),
    });
    assert.equal(res.status, 200);
  });

  it('allows editing other fields without connections.share when `shared` is omitted entirely', async () => {
    const res = await authedFetch(noShareToken, `${baseUrl}/${ownConnectionId}`, {
      method: 'PUT',
      body: JSON.stringify({ name: 'renamed-own-conn' }),
    });
    assert.equal(res.status, 200);
  });

  it('rejects downgrading shared:true -> false without connections.share (edit_any, not owner)', async () => {
    const createRes = await authedFetch(withShareToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'already-shared', protocol: 'ssh', host: 'h', port: 22, shared: true }),
    });
    const { id: sharedConnId } = await createRes.json() as { id: string };

    const res = await authedFetch(editAnyNoShareToken, `${baseUrl}/${sharedConnId}`, {
      method: 'PUT',
      body: JSON.stringify({ shared: false }),
    });
    assert.equal(res.status, 403);
    const row = queryOne<{ shared: number }>('SELECT shared FROM connections WHERE id = ?', [sharedConnId]);
    assert.equal(row?.shared, 1, 'shared flag must not have been flipped by the rejected downgrade');
  });
});

describe('POST /import — connections.share required only when an imported connection is shared', () => {
  it('rejects a batch containing shared:1 without connections.share', async () => {
    const res = await authedFetch(noShareToken, `${baseUrl}/import`, {
      method: 'POST',
      body: JSON.stringify({ connections: [{ name: 'imp1', protocol: 'ssh', host: 'h', port: 22, shared: 1 }] }),
    });
    assert.equal(res.status, 403);
  });

  it('allows a batch with no `shared` field without connections.share', async () => {
    const res = await authedFetch(noShareToken, `${baseUrl}/import`, {
      method: 'POST',
      body: JSON.stringify({ connections: [{ name: 'imp2', protocol: 'ssh', host: 'h', port: 22 }] }),
    });
    assert.equal(res.status, 200);
  });

  it('allows a batch with shared:0 explicitly without connections.share', async () => {
    const res = await authedFetch(noShareToken, `${baseUrl}/import`, {
      method: 'POST',
      body: JSON.stringify({ connections: [{ name: 'imp3', protocol: 'ssh', host: 'h', port: 22, shared: 0 }] }),
    });
    assert.equal(res.status, 200);
  });
});
