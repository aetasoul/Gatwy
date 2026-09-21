import { queryOne, queryAll } from '../db/helpers.js';

/** All recognised permission keys */
export const ALL_PERMISSIONS = [
  'connections.create', 'connections.edit_own', 'connections.delete_own',
  'connections.edit_any', 'connections.delete_any', 'connections.share', 'connections.import_export',
  'sessions.view_own', 'sessions.view_any', 'sessions.delete',
  'audit.view_own', 'audit.view_any',
  'users.manage', 'settings.manage', 'settings.auth_providers', 'settings.security', 'settings.backup', 'settings.notifications',
  'roles.manage',
  'protocols.ssh', 'protocols.rdp', 'protocols.vnc', 'protocols.moonlight', 'protocols.smb', 'protocols.ftp', 'protocols.telnet',
  'protocols.postgres', 'protocols.mysql',
] as const;

export type PermissionKey = typeof ALL_PERMISSIONS[number];

/** Default permissions for built-in roles */
export const DEFAULT_BUILTIN_PERMISSIONS: Record<string, PermissionKey[]> = {
  admin: [...ALL_PERMISSIONS],
  user: [
    'connections.create', 'connections.edit_own', 'connections.delete_own', 'connections.share', 'connections.import_export',
    'sessions.view_own',
    'audit.view_own',
    'protocols.ssh', 'protocols.rdp', 'protocols.vnc', 'protocols.moonlight', 'protocols.smb', 'protocols.ftp', 'protocols.telnet',
    'protocols.postgres', 'protocols.mysql',
  ],
};

/** Human-friendly permission groups for UI */
export const PERMISSION_GROUPS: Record<string, { label: string; permissions: { key: PermissionKey; label: string }[] }> = {
  connections: {
    label: 'Connections',
    permissions: [
      { key: 'connections.create', label: 'Create connections' },
      { key: 'connections.edit_own', label: 'Edit own connections' },
      { key: 'connections.delete_own', label: 'Delete own connections' },
      { key: 'connections.edit_any', label: 'Edit any connection' },
      { key: 'connections.delete_any', label: 'Delete any connection' },
      { key: 'connections.share', label: 'Share connections' },
      { key: 'connections.import_export', label: 'Import / Export connections' },
    ],
  },
  sessions: {
    label: 'Sessions & Recordings',
    permissions: [
      { key: 'sessions.view_own', label: 'View own recordings' },
      { key: 'sessions.view_any', label: 'View all recordings' },
      { key: 'sessions.delete', label: 'Delete / purge recordings' },
    ],
  },
  audit: {
    label: 'Audit Log',
    permissions: [
      { key: 'audit.view_own', label: 'View own audit entries' },
      { key: 'audit.view_any', label: 'View all audit entries' },
    ],
  },
  admin: {
    label: 'Administration',
    permissions: [
      { key: 'users.manage', label: 'Manage users' },
      { key: 'settings.manage', label: 'Global settings' },
      { key: 'settings.auth_providers', label: 'Auth providers' },
      { key: 'settings.security', label: 'Security settings' },
      { key: 'settings.backup', label: 'Backup & restore' },
      { key: 'settings.notifications', label: 'Notifications' },
      { key: 'roles.manage', label: 'Manage roles' },
    ],
  },
  protocols: {
    label: 'Protocols',
    permissions: [
      { key: 'protocols.ssh', label: 'SSH' },
      { key: 'protocols.rdp', label: 'RDP' },
      { key: 'protocols.vnc', label: 'VNC' },
      { key: 'protocols.moonlight', label: 'Moonlight / Sunshine' },
      { key: 'protocols.smb', label: 'SMB' },
      { key: 'protocols.ftp', label: 'FTP' },
      { key: 'protocols.telnet', label: 'Telnet' },
      { key: 'protocols.postgres', label: 'PostgreSQL' },
      { key: 'protocols.mysql', label: 'MySQL / MariaDB' },
    ],
  },
};

/**
 * Resolve the permission set for a given role ID.
 * Returns the parsed JSON array from the roles table.
 */
export function getPermissionsForRole(roleId: string): string[] {
  const row = queryOne<{ permissions_json: string }>('SELECT permissions_json FROM roles WHERE id = ?', [roleId]);
  if (!row) return [];
  try {
    return JSON.parse(row.permissions_json) as string[];
  } catch {
    return [];
  }
}

/**
 * Check whether a role has a specific permission.
 */
export function roleHasPermission(roleId: string, perm: PermissionKey): boolean {
  return getPermissionsForRole(roleId).includes(perm);
}

/**
 * Check whether a user (by ID) has a specific permission.
 * Looks up their role from the users table then checks the role's permissions.
 */
export function userHasPermission(userId: string, perm: PermissionKey): boolean {
  const user = queryOne<{ role: string }>('SELECT role FROM users WHERE id = ?', [userId]);
  if (!user) return false;
  return roleHasPermission(user.role, perm);
}

/**
 * All connection_group IDs reachable via a folder share to this user/role: the directly
 * shared groups plus every descendant. Resolved fresh on every call (never materialized
 * into per-connection rows), so a new sub-folder or a new connection dropped into an
 * already-shared folder inherits access immediately — no share row needs to be copied.
 */
export function accessibleSharedGroupIds(userId: string, role: string): string[] {
  const directRows = queryAll<{ group_id: string }>(
    `SELECT DISTINCT group_id FROM group_shares WHERE (share_type = 'user' AND target_id = ?) OR (share_type = 'role' AND target_id = ?)`,
    [userId, role],
  );
  if (directRows.length === 0) return [];

  const allGroups = queryAll<{ id: string; parent_id: string | null; user_id: string }>(
    'SELECT id, parent_id, user_id FROM connection_groups',
  );
  const ownerOf = new Map(allGroups.map((g) => [g.id, g.user_id]));
  const childrenOf = new Map<string, string[]>();
  for (const g of allGroups) {
    if (!g.parent_id) continue;
    const list = childrenOf.get(g.parent_id) ?? [];
    list.push(g.id);
    childrenOf.set(g.parent_id, list);
  }

  // Only descend into a child whose owner matches its parent's owner — a group grafted
  // (via parent_id) under someone else's folder must never inherit that folder's share.
  const result = new Set<string>();
  const queue = directRows.map((r) => r.group_id);
  while (queue.length > 0) {
    const gid = queue.pop()!;
    if (result.has(gid)) continue;
    result.add(gid);
    const owner = ownerOf.get(gid);
    for (const child of childrenOf.get(gid) ?? []) {
      if (ownerOf.get(child) === owner) queue.push(child);
    }
  }
  return [...result];
}

/**
 * Build a SQL WHERE fragment + params: true when a connection is owned by, globally
 * shared to, individually shared to, or reachable via a shared parent folder for, the
 * given user/role. Single source of truth for connection access — every route that
 * gates connection access (SFTP/FTP/SMB/DB, sessions, WS proxies, the connections list)
 * must go through this rather than re-deriving the condition.
 */
export function connectionAccessWhere(alias: string, userId: string, role: string): { where: string; params: unknown[] } {
  const sharedGroups = accessibleSharedGroupIds(userId, role);
  // Require the connection's owner to match its folder's actual owner, not just group_id
  // membership — otherwise a connection "planted" (by direct DB write, or a bug elsewhere)
  // into someone else's shared folder would be reachable by everyone that folder is shared
  // with. Write-side routes already reject a mismatched groupId; this is defense in depth.
  const groupClause = sharedGroups.length > 0
    ? ` OR (${alias}.group_id IN (${sharedGroups.map(() => '?').join(',')}) AND ${alias}.user_id = (SELECT cg.user_id FROM connection_groups cg WHERE cg.id = ${alias}.group_id))`
    : '';
  return {
    where: `(${alias}.user_id = ? OR ${alias}.shared = 1 OR ${alias}.id IN (SELECT cs.connection_id FROM connection_shares cs WHERE (cs.share_type = 'user' AND cs.target_id = ?) OR (cs.share_type = 'role' AND cs.target_id = ?))${groupClause})`,
    params: [userId, userId, role, ...sharedGroups],
  };
}

/**
 * Build SQL WHERE clause + params for connection access (used by WS proxies).
 * Checks ownership, shared=1, connection_shares, and shared-folder inheritance.
 */
export function wsCanAccess(userId: string): { where: string; params: unknown[] } {
  const user = queryOne<{ role: string }>('SELECT role FROM users WHERE id = ?', [userId]);
  const role = user?.role ?? '';
  return connectionAccessWhere('connections', userId, role);
}
