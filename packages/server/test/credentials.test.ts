import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';

// config reads DATA_DIR at import time, so point it at a scratch dir first.
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-cred-test-'));
process.env.DATA_DIR = dataDir;
process.env.GATWY_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

const { initDb, getDb, closeDb } = await import('../src/db/index.js');
const { execute } = await import('../src/db/helpers.js');
const { applyCredential, checkCredentialAssignable, isConnectionShared, sharedCredentialsInUseByOthers } = await import('../src/services/credentials.js');

const ALICE = 'user-alice';
const BOB = 'user-bob';

function addUser(id: string) {
  execute("INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, 'x', ?, 'user')", [id, id, id]);
}

function addCredential(id: string, ownerId: string, shared: boolean, over: Record<string, unknown> = {}) {
  execute(
    `INSERT INTO credentials (id, user_id, name, type, username, encrypted_password, private_key, encrypted_passphrase, shared)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id, ownerId, id, over.type ?? 'password', over.username ?? `${id}-user`,
      over.encrypted_password ?? 'enc-password', over.private_key ?? null,
      over.encrypted_passphrase ?? null, shared ? 1 : 0,
    ],
  );
}

function addConnection(id: string, ownerId: string, opts: { shared?: boolean; credentialId?: string | null } = {}) {
  execute(
    `INSERT INTO connections (id, user_id, name, protocol, host, port, username, encrypted_password, shared, credential_id)
     VALUES (?, ?, ?, 'ssh', 'host', 22, 'inline-user', 'inline-enc', ?, ?)`,
    [id, ownerId, id, opts.shared ? 1 : 0, opts.credentialId ?? null],
  );
}

function connRow(id: string) {
  const stmt = getDb().prepare('SELECT * FROM connections WHERE id = ?');
  stmt.bind([id]);
  stmt.step();
  const row = stmt.getAsObject() as Record<string, unknown>;
  stmt.free();
  return row as { user_id: string; credential_id: string | null; username: string | null; encrypted_password: string | null; private_key: string | null };
}

describe('credential rules', () => {
  before(async () => {
    await initDb();
    addUser(ALICE);
    addUser(BOB);
    addCredential('cred-alice-private', ALICE, false);
    addCredential('cred-alice-shared', ALICE, true);
    addCredential('cred-bob-private', BOB, false);
    addCredential('cred-alice-key', ALICE, false, {
      type: 'key', private_key: 'enc-key', encrypted_passphrase: 'enc-passphrase', encrypted_password: null,
    });
  });

  after(() => {
    closeDb();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  describe('checkCredentialAssignable', () => {
    it('lets an owner use their own private credential on a private connection', () => {
      assert.equal(checkCredentialAssignable('cred-alice-private', ALICE, false, false), null);
    });

    it('refuses a private credential on a shared connection', () => {
      assert.match(
        checkCredentialAssignable('cred-alice-private', ALICE, true, false)!,
        /shared connections can only use shared credentials/i,
      );
    });

    it('allows a shared credential on a shared connection', () => {
      assert.equal(checkCredentialAssignable('cred-alice-shared', ALICE, true, false), null);
    });

    it("hides another user's private credential", () => {
      assert.match(checkCredentialAssignable('cred-bob-private', ALICE, false, false)!, /not found/i);
    });

    it("requires credentials.use_shared for another user's shared credential", () => {
      assert.match(checkCredentialAssignable('cred-alice-shared', BOB, false, false)!, /not permitted/i);
      assert.equal(checkCredentialAssignable('cred-alice-shared', BOB, false, true), null);
    });

    it('reports an unknown credential', () => {
      assert.match(checkCredentialAssignable('cred-missing', ALICE, false, true)!, /not found/i);
    });
  });

  describe('isConnectionShared', () => {
    it('is true for a globally shared connection', () => {
      addConnection('conn-global', ALICE, { shared: true });
      assert.equal(isConnectionShared('conn-global', 1), true);
    });

    it('is true when shared with a user or role, despite the flag being off', () => {
      addConnection('conn-targeted', ALICE);
      execute("INSERT INTO connection_shares (id, connection_id, share_type, target_id) VALUES ('s1', 'conn-targeted', 'user', ?)", [BOB]);
      assert.equal(isConnectionShared('conn-targeted', 0), true);
    });

    it('is false for a private connection', () => {
      addConnection('conn-private', ALICE);
      assert.equal(isConnectionShared('conn-private', 0), false);
    });
  });

  describe('applyCredential', () => {
    it('leaves inline credentials alone when no credential is linked', () => {
      addConnection('conn-inline', ALICE);
      const res = applyCredential(connRow('conn-inline'), ALICE);
      assert.equal(res.username, 'inline-user');
      assert.equal(res.encrypted_password, 'inline-enc');
    });

    it('replaces inline credentials with the linked ones', () => {
      addConnection('conn-linked', ALICE, { credentialId: 'cred-alice-private' });
      const res = applyCredential(connRow('conn-linked'), ALICE);
      assert.equal(res.username, 'cred-alice-private-user');
      assert.equal(res.encrypted_password, 'enc-password');
      assert.equal(res.private_key, null);
    });

    it('passes a key credential through with its passphrase, and no password', () => {
      addConnection('conn-key', ALICE, { credentialId: 'cred-alice-key' });
      const res = applyCredential(connRow('conn-key'), ALICE) as { private_key: string | null; encrypted_passphrase?: string | null; encrypted_password: string | null };
      assert.equal(res.private_key, 'enc-key');
      assert.equal(res.encrypted_passphrase, 'enc-passphrase');
      assert.equal(res.encrypted_password, null);
    });

    it('resolves a shared credential for another user', () => {
      addConnection('conn-shared-cred', ALICE, { shared: true, credentialId: 'cred-alice-shared' });
      const res = applyCredential(connRow('conn-shared-cred'), BOB);
      assert.equal(res.username, 'cred-alice-shared-user');
      assert.equal(res.encrypted_password, 'enc-password');
    });

    // Defence in depth: a connection that became shared after linking must not
    // hand its owner's private credential to anyone else.
    it('withholds a private credential from another user', () => {
      addConnection('conn-leaky', ALICE, { shared: true, credentialId: 'cred-alice-private' });
      const res = applyCredential(connRow('conn-leaky'), BOB);
      assert.equal(res.username, null);
      assert.equal(res.encrypted_password, null);
      assert.equal(res.private_key, null);
    });

    it('yields no credentials when the link is dangling', () => {
      addConnection('conn-dangling', ALICE, { credentialId: 'cred-gone' });
      const res = applyCredential(connRow('conn-dangling'), ALICE);
      assert.equal(res.username, null);
      assert.equal(res.encrypted_password, null);
    });

    // System callers (auto-backup, DB pools) pass null: no per-user check, but
    // the credential must still belong to the connection's owner.
    it('resolves owner-held credentials for system callers', () => {
      addConnection('conn-system', ALICE, { credentialId: 'cred-alice-private' });
      assert.equal(applyCredential(connRow('conn-system'), null).username, 'cred-alice-private-user');
    });
  });

  describe('sharedCredentialsInUseByOthers', () => {
    it('is empty when nothing of the owner\'s is shared', () => {
      assert.deepEqual(sharedCredentialsInUseByOthers(BOB), []);
    });

    it('ignores a shared credential only used by its own owner', () => {
      addConnection('conn-owner-shared-cred', ALICE, { credentialId: 'cred-alice-shared' });
      assert.deepEqual(sharedCredentialsInUseByOthers(ALICE), []);
    });

    it('reports a shared credential used by another user\'s connection', () => {
      addConnection('conn-other-shared-cred', BOB, { shared: true, credentialId: 'cred-alice-shared' });
      const blockers = sharedCredentialsInUseByOthers(ALICE);
      assert.equal(blockers.length, 1);
      assert.equal(blockers[0]!.id, 'cred-alice-shared');
      assert.deepEqual(blockers[0]!.connections.map((c) => c.id), ['conn-other-shared-cred']);
    });
  });
});
