import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ftpsSecureOptions } from '../src/routes/ftp.js';


describe('ftpsSecureOptions', () => {
  it('returns undefined when FTPS is not enabled (plain FTP)', () => {
    assert.equal(ftpsSecureOptions(false, 1), undefined);
    assert.equal(ftpsSecureOptions(false, 0), undefined);
  });

  it('validates certificates by default for FTPS (skip_cert_validation = 0)', () => {
    const opts = ftpsSecureOptions(true, 0);
    assert.equal(opts?.rejectUnauthorized, true);
    assert.equal('checkServerIdentity' in (opts ?? {}), false);
  });

  it('skips certificate validation only when explicitly opted in (skip_cert_validation = 1)', () => {
    const opts = ftpsSecureOptions(true, 1);
    assert.equal(opts?.rejectUnauthorized, false);
    assert.equal(typeof opts?.checkServerIdentity, 'function');
  });

  it('treats any non-1 value as "validate" (fail closed), not just 0', () => {
    // skip_cert_validation is stored as an arbitrary SQLite INTEGER column; only the
    // exact opt-in value (1) should disable validation.
    const opts = ftpsSecureOptions(true, 2);
    assert.equal(opts?.rejectUnauthorized, true);
  });
});
