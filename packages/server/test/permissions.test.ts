import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';

// config reads DATA_DIR at import time, so point it at a scratch dir first.
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-perm-test-'));
process.env.DATA_DIR = dataDir;
process.env.GATWY_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

const { initDb, getDb, closeDb } = await import('../src/db/index.js');
const { execute, queryAll } = await import('../src/db/helpers.js');
const { accessibleSharedGroupIds, connectionAccessWhere, descendantGroupIds, groupOwnedBy } = await import('../src/services/permissions.js');

const ALICE = 'user-alice';
const BOB = 'user-bob';
const CAROL = 'user-carol';

function addUser(id: string, role = 'user') {
  execute("INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, 'x', ?, ?)", [id, id, id, role]);
}

function addGroup(id: string, ownerId: string, parentId: string | null = null) {
  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, ?)', [id, ownerId, id, parentId]);
}

function shareGroup(groupId: string, shareType: 'user' | 'role', targetId: string) {
  execute(
    'INSERT INTO group_shares (id, group_id, share_type, target_id) VALUES (?, ?, ?, ?)',
    [`share-${groupId}-${targetId}`, groupId, shareType, targetId],
  );
}

function addConnection(id: string, ownerId: string, groupId: string | null = null) {
  execute(
    `INSERT INTO connections (id, user_id, group_id, name, protocol, host, port)
     VALUES (?, ?, ?, ?, 'ssh', 'host', 22)`,
    [id, ownerId, groupId, id],
  );
}

function connIdsAccessibleTo(userId: string, role: string): string[] {
  const access = connectionAccessWhere('connections', userId, role);
  const rows = queryAll<{ id: string }>(`SELECT id FROM connections WHERE ${access.where} ORDER BY id`, access.params);
  return rows.map((r) => r.id);
}

describe('permissions', () => {
  before(async () => {
    await initDb();
    addUser(ALICE);
    addUser(BOB);
    addUser(CAROL);
  });

  after(() => {
    closeDb();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  describe('groupOwnedBy', () => {
    it('is true when the group exists and belongs to the given owner', () => {
      addGroup('g-owned', ALICE);
      assert.equal(groupOwnedBy('g-owned', ALICE), true);
    });

    it('is false when the group belongs to someone else', () => {
      assert.equal(groupOwnedBy('g-owned', BOB), false);
    });

    it('is false when the group does not exist', () => {
      assert.equal(groupOwnedBy('g-missing', ALICE), false);
    });
  });

  describe('accessibleSharedGroupIds', () => {
    it('is empty when nothing is shared to the user or role', () => {
      assert.deepEqual(accessibleSharedGroupIds(BOB, 'user'), []);
    });

    it('returns a directly-shared group', () => {
      addGroup('g-direct', ALICE);
      shareGroup('g-direct', 'user', BOB);
      assert.deepEqual(accessibleSharedGroupIds(BOB, 'user'), ['g-direct']);
    });

    it('inherits into descendants owned by the same owner', () => {
      addGroup('g-parent', ALICE);
      addGroup('g-child', ALICE, 'g-parent');
      addGroup('g-grandchild', ALICE, 'g-child');
      shareGroup('g-parent', 'user', CAROL);
      const ids = accessibleSharedGroupIds(CAROL, 'user').sort();
      assert.deepEqual(ids, ['g-child', 'g-grandchild', 'g-parent']);
    });

    it('does not descend into a child grafted under a different owner', () => {
      addGroup('g-planted-parent', ALICE);
      addGroup('g-planted-child', BOB, 'g-planted-parent'); // grafted: parent_id points cross-owner
      shareGroup('g-planted-parent', 'user', 'user-dave');
      execute("INSERT INTO users (id, username, password_hash, display_name, role) VALUES ('user-dave', 'user-dave', 'x', 'dave', 'user')");
      const ids = accessibleSharedGroupIds('user-dave', 'user');
      assert.deepEqual(ids, ['g-planted-parent']);
      assert.ok(!ids.includes('g-planted-child'));
    });

    it('resolves a share made to a role, independent of the specific user', () => {
      addGroup('g-role-shared', ALICE);
      shareGroup('g-role-shared', 'role', 'admin');
      addUser('user-erin', 'admin');
      assert.deepEqual(accessibleSharedGroupIds('user-erin', 'admin'), ['g-role-shared']);
      assert.deepEqual(accessibleSharedGroupIds('user-erin', 'user'), []);
    });
  });

  describe('descendantGroupIds', () => {
    it('includes the root and its owner-scoped descendants', () => {
      addGroup('d-root', ALICE);
      addGroup('d-child', ALICE, 'd-root');
      addGroup('d-grandchild', ALICE, 'd-child');
      assert.deepEqual(descendantGroupIds('d-root').sort(), ['d-child', 'd-grandchild', 'd-root']);
    });

    it('excludes a child grafted under a different owner', () => {
      addGroup('d-root2', ALICE);
      addGroup('d-planted', BOB, 'd-root2');
      assert.deepEqual(descendantGroupIds('d-root2'), ['d-root2']);
    });

    it('is empty for a group that does not exist', () => {
      assert.deepEqual(descendantGroupIds('d-missing'), []);
    });
  });

  describe('connectionAccessWhere — folder-share inheritance and planted-connection defence', () => {
    it('lets the owner access their own connection', () => {
      addGroup('g-own', ALICE);
      addConnection('conn-own', ALICE, 'g-own');
      assert.ok(connIdsAccessibleTo(ALICE, 'user').includes('conn-own'));
    });

    it('grants access to a connection filed under a shared folder', () => {
      addGroup('g-shared-folder', ALICE);
      shareGroup('g-shared-folder', 'user', BOB);
      addConnection('conn-in-shared-folder', ALICE, 'g-shared-folder');
      assert.ok(connIdsAccessibleTo(BOB, 'user').includes('conn-in-shared-folder'));
    });

    it('withholds a connection whose owner does not match its folder\'s owner (planted connection)', () => {
      // g-shared-folder is owned by ALICE and shared with BOB (from the previous test).
      // A connection "planted" into it by a different owner must not leak via the share,
      // even though its group_id still matches — defence in depth against a bug elsewhere
      // (or a direct DB write) that lets a connection's group_id diverge from its owner.
      addConnection('conn-planted', CAROL, 'g-shared-folder');
      assert.ok(!connIdsAccessibleTo(BOB, 'user').includes('conn-planted'));
      // The actual owner can still see their own connection, regardless of the folder mismatch.
      assert.ok(connIdsAccessibleTo(CAROL, 'user').includes('conn-planted'));
    });

    it('does not grant access to an unrelated user', () => {
      assert.ok(!connIdsAccessibleTo('user-erin', 'user').includes('conn-in-shared-folder'));
    });
  });
});
