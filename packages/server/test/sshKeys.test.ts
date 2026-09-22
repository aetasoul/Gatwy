import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';
import ssh2 from 'ssh2';
import { friendlyKeyError, prepareKey, validatePrivateKey } from '../src/services/sshKeys.js';

function keyPem(
  type: 'rsa' | 'ed25519' | 'ec',
  format: 'pkcs8' | 'pkcs1' | 'sec1',
  passphrase?: string,
): string {
  const opts = type === 'rsa' ? { modulusLength: 2048 } : type === 'ec' ? { namedCurve: 'P-256' } : {};
  const { privateKey } = crypto.generateKeyPairSync(type as 'rsa', opts as crypto.RSAKeyPairOptions<'pem', 'pem'>);
  return (privateKey as unknown as crypto.KeyObject).export({
    type: format,
    format: 'pem',
    ...(passphrase ? { cipher: 'aes-256-cbc', passphrase } : {}),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any) as string;
}

/**
 * SPKI DER of a private key's public half, for comparing converted keys.
 * OpenSSH-format keys go through ssh2, which Node's crypto cannot parse.
 */
function publicDer(privateKeyPem: string): Buffer {
  if (privateKeyPem.includes('OPENSSH PRIVATE KEY')) {
    const parsed = ssh2.utils.parseKey(privateKeyPem);
    assert.ok(!(parsed instanceof Error), 'converted key does not parse');
    return crypto.createPublicKey((parsed as { getPublicPEM(): string }).getPublicPEM())
      .export({ type: 'spki', format: 'der' });
  }
  return crypto.createPublicKey(crypto.createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'der' });
}

describe('validatePrivateKey', () => {
  it('accepts a PKCS#1 key', () => {
    assert.equal(validatePrivateKey(keyPem('rsa', 'pkcs1')), null);
  });

  it('reports encrypted keys given no passphrase', () => {
    const err = validatePrivateKey(keyPem('rsa', 'pkcs1', 'secret'));
    assert.match(err!, /encrypted .* passphrase is required/i);
  });

  it('reports a wrong passphrase', () => {
    const err = validatePrivateKey(keyPem('rsa', 'pkcs1', 'secret'), 'wrong');
    assert.match(err!, /incorrect passphrase/i);
  });

  it('accepts an encrypted key with the right passphrase', () => {
    assert.equal(validatePrivateKey(keyPem('rsa', 'pkcs1', 'secret'), 'secret'), null);
  });

  it('rejects text that is not a key', () => {
    assert.match(validatePrivateKey('not a key')!, /invalid private key/i);
  });
});

describe('friendlyKeyError', () => {
  it('maps ssh2 wording to actionable messages', () => {
    assert.match(friendlyKeyError('Encrypted OpenSSH private key detected, but no passphrase given'), /passphrase is required/i);
    assert.match(friendlyKeyError('OpenSSH key integrity check failed -- bad passphrase?'), /incorrect passphrase/i);
    assert.equal(friendlyKeyError('Unsupported key format'), 'Invalid private key: Unsupported key format');
  });
});

describe('prepareKey', () => {
  it('leaves a key ssh2 already understands untouched', () => {
    const pem = keyPem('rsa', 'pkcs1');
    const res = prepareKey(pem);
    assert.ok('key' in res);
    assert.equal(res.key.converted, false);
    assert.equal(res.key.privateKey, pem);
  });

  it('keeps the passphrase for an encrypted non-PKCS#8 key', () => {
    const res = prepareKey(keyPem('rsa', 'pkcs1', 'secret'), 'secret');
    assert.ok('key' in res);
    assert.equal(res.key.converted, false);
    assert.equal(res.key.passphrase, 'secret');
  });

  // ssh2 cannot read PKCS#8, which OpenSSL 3 and many cloud consoles emit.
  for (const [type, header] of [
    ['rsa', '-----BEGIN RSA PRIVATE KEY-----'],
    ['ec', '-----BEGIN EC PRIVATE KEY-----'],
    ['ed25519', '-----BEGIN OPENSSH PRIVATE KEY-----'],
  ] as const) {
    it(`converts a PKCS#8 ${type} key, preserving the key itself`, () => {
      const pem = keyPem(type, 'pkcs8');
      const res = prepareKey(pem);
      assert.ok('key' in res, 'error' in res ? res.error : '');
      assert.equal(res.key.converted, true);
      assert.ok(res.key.privateKey.startsWith(header), res.key.privateKey.split('\n')[0]);
      assert.equal(validatePrivateKey(res.key.privateKey), null);
      assert.ok(publicDer(pem).equals(publicDer(res.key.privateKey)), 'public key changed during conversion');
    });
  }

  it('decrypts an encrypted PKCS#8 key and drops the now-unneeded passphrase', () => {
    const pem = keyPem('rsa', 'pkcs8', 'secret');
    const res = prepareKey(pem, 'secret');
    assert.ok('key' in res);
    assert.equal(res.key.converted, true);
    assert.equal(res.key.passphrase, undefined);
    assert.equal(validatePrivateKey(res.key.privateKey), null);
  });

  it('reports an encrypted PKCS#8 key with no or wrong passphrase', () => {
    const pem = keyPem('rsa', 'pkcs8', 'secret');
    const missing = prepareKey(pem);
    assert.ok('error' in missing);
    assert.match(missing.error, /passphrase is required/i);
    const wrong = prepareKey(pem, 'nope');
    assert.ok('error' in wrong);
    assert.match(wrong.error, /incorrect passphrase/i);
  });

  it('rejects key types ssh2 cannot use', () => {
    const dsa = crypto.generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 })
      .privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const res = prepareKey(dsa);
    assert.ok('error' in res);
    assert.match(res.error, /unsupported key type: dsa/i);
  });

  it('rejects a malformed PKCS#8 key without leaking OpenSSL internals', () => {
    const res = prepareKey('-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----');
    assert.ok('error' in res);
    assert.match(res.error, /could not be decoded/i);
  });
});
