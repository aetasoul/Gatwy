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
