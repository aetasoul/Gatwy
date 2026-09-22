import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';

// config reads DATA_DIR at import time, so point it at a scratch dir first.
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-migration-test-'));
process.env.DATA_DIR = dataDir;
process.env.GATWY_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

const { initDb, getDb, closeDb, restoreDbFromBytes } = await import('../src/db/index.js');

describe('migration upgrade path', () => {
  before(async () => {
    await initDb();
  });

  after(() => {
    closeDb();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it('creates group_shares for a DB that was already at v21 before it existed', () => {
    // Simulate a deployed instance that upgraded through the old, broken numbering:
    // it already has schema_version rows through v21 (credentials + domain applied)
    // but never got group_shares, because that migration used to be numbered v20 —
    // a version <= its already-applied v21, so runMigrations skipped it entirely.
    const db = getDb();
    db.run('DROP TABLE IF EXISTS group_shares');
    db.run('DELETE FROM schema_version WHERE version > 21');

    const maxBefore = db.exec('SELECT MAX(version) as v FROM schema_version')[0]!.values[0]![0];
    assert.equal(maxBefore, 21);
    const tableBefore = db.exec("SELECT name FROM sqlite_master WHERE type='table' AND name='group_shares'");
    assert.equal(tableBefore.length, 0);

    // restoreDbFromBytes re-runs runMigrations against the restored bytes, exactly as
    // happens on every real app startup against the persisted file.
    const bytes = Buffer.from(db.export());
    restoreDbFromBytes(bytes);

    const after = getDb();
    const tableAfter = after.exec("SELECT name FROM sqlite_master WHERE type='table' AND name='group_shares'");
    assert.equal(tableAfter.length, 1, 'group_shares table must be created when upgrading from v21');
    const maxAfter = after.exec('SELECT MAX(version) as v FROM schema_version')[0]!.values[0]![0];
    assert.equal(maxAfter, 22);
  });
});
