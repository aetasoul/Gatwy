// Regression test for a fixed vulnerability: a pre-2FA `mfaToken` (issued after password
// verification, before the TOTP/passkey step) used to pass authRequired as a full session
// token, because verifyToken() never checked the JWT's `type` claim and authRequired's
// fail-open on an untracked (`not_found`) login_sessions row let it through. See
// services/jwt.ts (verifyToken) for the fix.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, before, after } from 'node:test';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-mfa-test-'));
process.env.DATA_DIR = tmpDir;

const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { execute } = await import('../src/db/helpers.js');
const { initJwt, signToken, signMfaToken, verifyToken } = await import('../src/services/jwt.js');
const { authRequired } = await import('../src/middleware/auth.js');
const { v4: uuid } = await import('uuid');

let userId: string;

before(async () => {
  await initDb();
  initJwt();
  userId = uuid();
  execute(
    `INSERT INTO users (id, username, display_name, password_hash, role) VALUES (?, 'victim', 'Victim', 'x', 'user')`,
    [userId],
  );
});

after(() => {
  stopAutoSave();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function fakeExpressCall(token: string) {
  const req = { headers: { authorization: `Bearer ${token}` }, cookies: {}, query: {} } as unknown as Parameters<typeof authRequired>[0];
  let status: number | null = null;
  let nextCalled = false;
  const res = {
    status(code: number) { status = code; return this; },
    json() { return this; },
  } as unknown as Parameters<typeof authRequired>[1];
  authRequired(req, res, () => { nextCalled = true; });
  return { status, nextCalled };
}

describe('verifyToken rejects special-purpose tokens', () => {
  it('throws on a pre-2FA mfaToken', () => {
    const mfaToken = signMfaToken(userId);
    assert.throws(() => verifyToken(mfaToken), /Invalid token type/);
  });

  it('still accepts a normal session token', () => {
    const sessionToken = signToken({ userId, username: 'victim', role: 'user' });
    assert.doesNotThrow(() => verifyToken(sessionToken));
  });
});

describe('authRequired: MFA bypass is closed', () => {
  it('rejects an mfaToken with 401 and never calls next()', () => {
    const mfaToken = signMfaToken(userId);
    const { status, nextCalled } = fakeExpressCall(mfaToken);
    assert.equal(nextCalled, false);
    assert.equal(status, 401);
  });

  it('still accepts a normal session token (no regression)', () => {
    const sessionToken = signToken({ userId, username: 'victim', role: 'user' });
    const { nextCalled } = fakeExpressCall(sessionToken);
    assert.equal(nextCalled, true);
  });
});
