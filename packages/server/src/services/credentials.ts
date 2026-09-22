import { queryAll, queryOne } from '../db/helpers.js';

export const CREDENTIAL_TYPES = ['password', 'key'] as const;
export type CredentialType = typeof CREDENTIAL_TYPES[number];

export interface CredentialRow {
  id: string;
  user_id: string;
  name: string;
  type: CredentialType;
  username: string | null;
  encrypted_password: string | null;
  private_key: string | null;
  encrypted_passphrase: string | null;
  shared: number;
}

/** Minimal shape of a connection row needed to resolve its credentials. */
interface CredentialSource {
  user_id?: string;
  credential_id?: string | null;
  username: string | null;
  encrypted_password: string | null;
  private_key?: string | null;
  /** Set only when resolved from a key-type library credential. */
  encrypted_passphrase?: string | null;
}

/**
 * Whether a connection is visible to anyone besides its owner — shared globally
 * or via connection_shares. Such connections may only use shared credentials.
 */
export function isConnectionShared(connectionId: string, sharedFlag: number | boolean): boolean {
  if (sharedFlag) return true;
  return !!queryOne<{ id: string }>(
    'SELECT id FROM connection_shares WHERE connection_id = ? LIMIT 1', [connectionId],
  );
}

/**
 * Validate that `credentialId` can be attached to a connection owned by
 * `ownerId`. Private credentials must belong to the connection owner and can't
 * back a shared connection; shared credentials require credentials.use_shared
 * unless the caller owns them. Returns an error message, or null when allowed.
 */
export function checkCredentialAssignable(
  credentialId: string,
  ownerId: string,
  connectionShared: boolean,
  canUseShared: boolean,
): string | null {
  const cred = queryOne<CredentialRow>('SELECT * FROM credentials WHERE id = ?', [credentialId]);
  if (!cred) return 'Credential not found';
  if (cred.shared) {
    if (cred.user_id !== ownerId && !canUseShared) return 'Not permitted to use shared credentials';
    return null;
  }
  if (cred.user_id !== ownerId) return 'Credential not found';
  if (connectionShared) return 'Shared connections can only use shared credentials';
  return null;
}

export interface SharedCredentialBlocker {
  id: string;
  name: string;
  connections: { id: string; name: string; userId: string }[];
}

/**
 * Shared credentials owned by `ownerId` that other users' connections still
 * reference — deleting this user would cascade-delete these credentials and
 * silently strip those connections of their working auth. Used to block user
 * deletion until the credentials are reassigned, un-shared, or those
 * connections are updated.
 */
export function sharedCredentialsInUseByOthers(ownerId: string): SharedCredentialBlocker[] {
  const creds = queryAll<CredentialRow>('SELECT * FROM credentials WHERE user_id = ? AND shared = 1', [ownerId]);
  const blockers: SharedCredentialBlocker[] = [];
  for (const cred of creds) {
    const conns = queryAll<{ id: string; name: string; user_id: string }>(
      'SELECT id, name, user_id FROM connections WHERE credential_id = ? AND user_id != ? ORDER BY name COLLATE NOCASE',
      [cred.id, ownerId],
    );
    if (conns.length) {
      blockers.push({ id: cred.id, name: cred.name, connections: conns.map((c) => ({ id: c.id, name: c.name, userId: c.user_id })) });
    }
  }
  return blockers;
}

/**
 * Return a copy of `conn` whose username / encrypted_password / private_key come
 * from its linked library credential (values stay encrypted — callers decrypt
 * exactly as they do for inline credentials). Connections without a credential
 * are returned unchanged.
 *
 * Defence in depth: a private credential only ever resolves for its owner, so a
 * connection that became shared after linking can't leak it to other users.
 */
export function applyCredential<T extends CredentialSource>(conn: T, requesterId: string | null): T {
  if (!conn.credential_id) return conn;
  const cred = queryOne<CredentialRow>('SELECT * FROM credentials WHERE id = ?', [conn.credential_id]);
  const usable = !!cred && (
    cred.shared === 1
    || (cred.user_id === conn.user_id && (requesterId === null || requesterId === cred.user_id))
  );
  if (!cred || !usable) {
    return { ...conn, username: null, encrypted_password: null, private_key: null, encrypted_passphrase: null };
  }
  const isKey = cred.type === 'key';
  return {
    ...conn,
    username: cred.username,
    encrypted_password: isKey ? null : cred.encrypted_password,
    private_key: isKey ? cred.private_key : null,
    encrypted_passphrase: isKey ? cred.encrypted_passphrase : null,
  };
}
