import crypto from 'crypto';
import ssh2 from 'ssh2';

// ssh2 is CommonJS; `utils` isn't exposed as a named ESM export.
const { utils } = ssh2;

/** Turn ssh2 key-parsing errors into messages a user can act on. */
export function friendlyKeyError(message: string): string {
  if (/no passphrase given/i.test(message)) {
    return 'This private key is encrypted — a passphrase is required';
  }
  if (/bad passphrase/i.test(message)) {
    return 'Incorrect passphrase for this private key';
  }
  return `Invalid private key: ${message}`;
}

/**
 * Check that `privateKey` parses (and decrypts with `passphrase`, if encrypted).
 * Returns a user-facing error message, or null when the key is usable.
 */
export function validatePrivateKey(privateKey: string, passphrase?: string): string | null {
  let parsed: ReturnType<typeof utils.parseKey>;
  try {
    parsed = utils.parseKey(privateKey, passphrase);
  } catch (err) {
    return friendlyKeyError((err as Error).message);
  }
  return parsed instanceof Error ? friendlyKeyError(parsed.message) : null;
}

// ── PKCS#8 conversion ────────────────────────────────────────────────────────
// ssh2 can't read PKCS#8 ("BEGIN PRIVATE KEY" / "BEGIN ENCRYPTED PRIVATE KEY"),
// which OpenSSL 3 and many cloud consoles emit by default. Node's crypto can,
// so decode it there and re-emit a format ssh2 understands.

const PKCS8_RE = /-----BEGIN (ENCRYPTED )?PRIVATE KEY-----/;

function sshString(data: Buffer | string): Buffer {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length);
  return Buffer.concat([len, buf]);
}

/** Unencrypted OpenSSH-format Ed25519 key — the only Ed25519 encoding ssh2 reads. */
function ed25519ToOpenSsh(key: crypto.KeyObject): string {
  const jwk = key.export({ format: 'jwk' });
  const seed = Buffer.from(jwk.d!, 'base64url');
  const pub = Buffer.from(jwk.x!, 'base64url');
  const pubBlob = Buffer.concat([sshString('ssh-ed25519'), sshString(pub)]);

  const check = crypto.randomBytes(4);
  let priv = Buffer.concat([
    check, check,
    sshString('ssh-ed25519'), sshString(pub), sshString(Buffer.concat([seed, pub])),
    sshString(''), // comment
  ]);
  for (let i = 1; priv.length % 8 !== 0; i++) priv = Buffer.concat([priv, Buffer.from([i])]);

  const count = Buffer.alloc(4);
  count.writeUInt32BE(1);
  const blob = Buffer.concat([
    Buffer.from('openssh-key-v1\0'),
    sshString('none'), sshString('none'), sshString(''),
    count, sshString(pubBlob), sshString(priv),
  ]);
  const b64 = blob.toString('base64').match(/.{1,70}/g)!.join('\n');
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

/** Decode a PKCS#8 key and re-encode it unencrypted in a format ssh2 reads. */
function convertPkcs8(privateKey: string, passphrase?: string): { key: string } | { error: string } {
  const encrypted = PKCS8_RE.exec(privateKey)?.[1] !== undefined;
  if (encrypted && !passphrase) return { error: 'This private key is encrypted — a passphrase is required' };

  let key: crypto.KeyObject;
  try {
    key = crypto.createPrivateKey({ key: privateKey, format: 'pem', ...(encrypted ? { passphrase } : {}) });
  } catch (err) {
    if (encrypted && /bad decrypt/i.test((err as Error).message)) {
      return { error: 'Incorrect passphrase for this private key' };
    }
    return { error: 'Invalid private key: the PKCS#8 key could not be decoded' };
  }

  switch (key.asymmetricKeyType) {
    case 'rsa': return { key: key.export({ type: 'pkcs1', format: 'pem' }) as string };
    case 'ec': return { key: key.export({ type: 'sec1', format: 'pem' }) as string };
    case 'ed25519': return { key: ed25519ToOpenSsh(key) };
    default: return { error: `Unsupported key type: ${key.asymmetricKeyType ?? 'unknown'}` };
  }
}

export interface PreparedKey {
  privateKey: string;
  passphrase?: string;
  /** True when a PKCS#8 key was converted — the result is unencrypted, so no passphrase is needed. */
  converted: boolean;
}

/**
 * Get a private key ready for ssh2: converts PKCS#8 keys, then checks the key
 * parses (and decrypts with `passphrase`). Returns the key to use, or a
 * user-facing error.
 */
export function prepareKey(privateKey: string, passphrase?: string): { key: PreparedKey } | { error: string } {
  let prepared: PreparedKey = { privateKey, passphrase, converted: false };
  if (PKCS8_RE.test(privateKey)) {
    const res = convertPkcs8(privateKey, passphrase);
    if ('error' in res) return res;
    prepared = { privateKey: res.key, converted: true };
  }
  const err = validatePrivateKey(prepared.privateKey, prepared.passphrase);
  return err ? { error: err } : { key: prepared };
}
