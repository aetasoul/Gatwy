import { useEffect, useState, type FormEvent } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { showToast } from '../../hooks/useToast';
import { fetchCredentials, type CredentialSummary, type CredentialType } from '../../lib/credentials';

const inputCls = 'w-full px-3 py-2 bg-surface border border-border rounded text-text-primary focus:outline-none focus:ring-2 focus:ring-accent text-sm';

interface InUseInfo {
  name: string;
  connections: { id: string; name: string }[];
  otherCount: number;
  message: string;
}

function KeyGlyph() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="7.5" cy="15.5" r="5.5" />
      <path d="M21 2l-9.6 9.6M15.5 7.5l3 3L22 7l-3-3" />
    </svg>
  );
}

function LockGlyph() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

export function CredentialsSettings() {
  const { user } = useAuth();
  const canShare = !!user?.permissions.includes('credentials.share');

  const [creds, setCreds] = useState<CredentialSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Create / edit form (editing === null + formOpen → create)
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<CredentialSummary | null>(null);
  const [name, setName] = useState('');
  const [type, setType] = useState<CredentialType>('password');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [clearPassphrase, setClearPassphrase] = useState(false);
  const [shared, setShared] = useState(false);
  const [formError, setFormError] = useState('');
  const [saving, setSaving] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<CredentialSummary | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [inUse, setInUse] = useState<InUseInfo | null>(null);

  function load() {
    fetchCredentials()
      .then((c) => { setCreds(c); setError(''); })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  function openCreate() {
    setEditing(null);
    setName(''); setType('password'); setUsername(''); setPassword('');
    setPrivateKey(''); setPassphrase(''); setClearPassphrase(false); setShared(false);
    setFormError('');
    setFormOpen(true);
  }

  function openEdit(c: CredentialSummary) {
    setEditing(c);
    setName(c.name); setType(c.type); setUsername(c.username ?? ''); setPassword('');
    setPrivateKey(''); setPassphrase(''); setClearPassphrase(false); setShared(c.shared);
    setFormError('');
    setFormOpen(true);
  }

  function closeForm() {
    setFormOpen(false);
    setEditing(null);
  }

  function readInUse(data: { error?: string; connections?: { id: string; name: string }[]; otherCount?: number }, credName: string) {
    setInUse({
      name: credName,
      connections: data.connections ?? [],
      otherCount: data.otherCount ?? 0,
      message: data.error ?? 'Credential is in use',
    });
  }

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setFormError('');
    if (!editing && type === 'key' && !privateKey.trim()) { setFormError('Private key is required'); return; }
    setSaving(true);
    try {
      const body: Record<string, unknown> = { name, username };
      if (!editing) body.type = type;
      if (type === 'password' && password) body.password = password;
      if (type === 'key') {
        if (privateKey.trim()) body.privateKey = privateKey;
        if (passphrase) body.passphrase = passphrase;
        else if (clearPassphrase) body.clearPassphrase = true;
      }
      if (canShare) body.shared = shared;

      const res = await fetch(editing ? `/api/v1/credentials/${editing.id}` : '/api/v1/credentials', {
        method: editing ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 409 && editing) { closeForm(); readInUse(data, editing.name); return; }
      if (!res.ok) throw new Error(data.error || `Server error (${res.status})`);
      showToast(editing ? 'Credential updated' : 'Credential created');
      closeForm();
      load();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      const res = await fetch(`/api/v1/credentials/${deleteTarget.id}`, { method: 'DELETE', credentials: 'include' });
      const data = await res.json().catch(() => ({}));
      if (res.status === 409) { readInUse(data, deleteTarget.name); setDeleteTarget(null); return; }
      if (!res.ok) throw new Error(data.error || `Server error (${res.status})`);
      showToast('Credential deleted');
      setDeleteTarget(null);
      load();
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Delete failed', 'error');
    } finally {
      setDeleting(false);
    }
  }

  if (loading) return <p className="text-text-secondary text-sm">Loading…</p>;
  if (error) return <p className="text-red-500 text-sm">{error}</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-text-primary">Credential Library</h2>
          <p className="text-xs text-text-secondary mt-0.5">
            Save usernames with passwords or SSH keys once, then pick them when creating connections.
            Updating a credential updates every connection that uses it.
          </p>
        </div>
        <button
          onClick={openCreate}
          className="px-3 py-1.5 bg-accent text-white rounded hover:bg-accent-hover text-sm font-medium shrink-0"
        >
          + New Credential
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left">
              <th className="pb-2 pr-4 text-text-secondary font-medium">Name</th>
              <th className="pb-2 pr-4 text-text-secondary font-medium">Type</th>
              <th className="pb-2 pr-4 text-text-secondary font-medium">Username</th>
              <th className="pb-2 pr-4 text-text-secondary font-medium">Visibility</th>
              <th className="pb-2 pr-4 text-text-secondary font-medium">Used by</th>
              <th className="pb-2 text-text-secondary font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {creds.map((c) => (
              <tr key={c.id} className="border-b border-border last:border-b-0">
                <td className="py-3 pr-4 text-text-primary font-medium">{c.name}</td>
                <td className="py-3 pr-4">
                  <span className="inline-flex items-center gap-1.5 text-text-secondary text-xs">
                    {c.type === 'key' ? <KeyGlyph /> : <LockGlyph />}
                    {c.type === 'key' ? `SSH key${c.hasPassphrase ? ' + passphrase' : ''}` : 'Password'}
                  </span>
                </td>
                <td className="py-3 pr-4 text-text-secondary font-mono text-xs">{c.username || '—'}</td>
                <td className="py-3 pr-4">
                  {c.shared ? (
                    <span className="px-2 py-0.5 rounded text-xs bg-accent/15 text-accent font-medium">
                      Shared{!c.isOwner && c.ownerUsername ? ` · ${c.ownerUsername}` : ''}
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-xs bg-surface-hover text-text-secondary">Private</span>
                  )}
                </td>
                <td className="py-3 pr-4 text-text-secondary text-xs">
                  {c.usageCount === 0 ? '—' : `${c.usageCount} connection${c.usageCount !== 1 ? 's' : ''}`}
                </td>
                <td className="py-3">
                  {c.canEdit ? (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => openEdit(c)}
                        className="px-2 py-1 text-xs border border-border rounded text-text-secondary hover:bg-surface-hover"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => setDeleteTarget(c)}
                        className="px-2 py-1 text-xs border border-red-500/30 rounded text-red-400 hover:bg-red-500/10"
                      >
                        Delete
                      </button>
                    </div>
                  ) : (
                    <span className="text-text-secondary text-xs">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {creds.length === 0 && (
          <p className="text-text-secondary text-sm py-6 text-center">No saved credentials yet.</p>
        )}
      </div>

      {/* Create / Edit modal */}
      {formOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
          onClick={(e) => { if (e.target === e.currentTarget) closeForm(); }}>
          <div className="bg-surface-alt border border-border rounded-lg shadow-xl w-full max-w-md p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-text-primary">
                {editing ? `Edit Credential — ${editing.name}` : 'New Credential'}
              </h3>
              <button onClick={closeForm} className="p-1 rounded hover:bg-surface-hover text-text-secondary hover:text-text-primary">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            <form onSubmit={handleSave} className="space-y-3">
              <div>
                <label className="block text-xs text-text-secondary mb-1">Name</label>
                <input type="text" required autoFocus value={name} onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Homelab root key" className={inputCls} />
              </div>

              <div>
                <label className="block text-xs text-text-secondary mb-1">Type</label>
                <div className="flex gap-2">
                  {(['password', 'key'] as const).map((t) => (
                    <button
                      key={t}
                      type="button"
                      disabled={!!editing}
                      onClick={() => setType(t)}
                      className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 text-xs rounded border transition-colors disabled:cursor-not-allowed ${
                        type === t
                          ? 'border-accent bg-accent/10 text-accent font-medium'
                          : 'border-border text-text-secondary hover:bg-surface-hover disabled:opacity-40'
                      }`}
                    >
                      {t === 'key' ? <KeyGlyph /> : <LockGlyph />}
                      {t === 'key' ? 'Username + SSH key' : 'Username + password'}
                    </button>
                  ))}
                </div>
                {type === 'key' && (
                  <p className="text-[11px] text-text-secondary mt-1">
                    SSH keys work with SSH and SFTP connections. OpenSSH, PEM and PKCS#8 keys (RSA, ECDSA, Ed25519) are accepted.
                  </p>
                )}
              </div>

              <div>
                <label className="block text-xs text-text-secondary mb-1">Username</label>
                <input type="text" value={username} onChange={(e) => setUsername(e.target.value)}
                  placeholder="user" autoComplete="off" className={inputCls} />
              </div>

              {type === 'password' ? (
                <div>
                  <label className="block text-xs text-text-secondary mb-1">Password</label>
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                    autoComplete="new-password"
                    placeholder={editing?.hasPassword ? '(unchanged)' : ''} className={inputCls} />
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-xs text-text-secondary mb-1">Private Key</label>
                    <textarea
                      value={privateKey}
                      onChange={(e) => setPrivateKey(e.target.value)}
                      rows={5}
                      placeholder={editing ? '(unchanged — paste a new key to replace)' : '-----BEGIN OPENSSH PRIVATE KEY-----'}
                      className={`${inputCls} font-mono text-xs resize-none`}
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-text-secondary mb-1">
                      Key Passphrase <span className="font-normal">(optional)</span>
                    </label>
                    <input type="password" value={passphrase}
                      onChange={(e) => { setPassphrase(e.target.value); if (e.target.value) setClearPassphrase(false); }}
                      autoComplete="new-password"
                      placeholder={editing?.hasPassphrase && !clearPassphrase ? '(unchanged)' : ''} className={inputCls} />
                    {editing?.hasPassphrase && !passphrase && (
                      <label className="flex items-center gap-2 mt-1.5 cursor-pointer">
                        <input type="checkbox" checked={clearPassphrase} onChange={(e) => setClearPassphrase(e.target.checked)} className="accent-accent" />
                        <span className="text-xs text-text-secondary">Remove stored passphrase</span>
                      </label>
                    )}
                  </div>
                </>
              )}

              {canShare && (
                <div className="flex items-start gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => setShared((v) => !v)}
                    className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${
                      shared ? 'bg-accent' : 'bg-surface-hover border border-border'
                    }`}
                  >
                    <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${shared ? 'translate-x-4' : 'translate-x-0.5'}`} />
                  </button>
                  <div>
                    <span className="text-xs text-text-primary">Shared credential</span>
                    <p className="text-[11px] text-text-secondary leading-tight mt-0.5">
                      Can be used by shared connections, and by users allowed to use shared credentials.
                      The secret is never shown, but anyone who can use it can connect with it.
                    </p>
                  </div>
                </div>
              )}

              {formError && <p className="text-red-500 text-xs">{formError}</p>}

              <div className="flex gap-2 pt-1">
                <button type="submit" disabled={saving}
                  className="flex-1 py-2 px-4 bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50 font-medium text-sm">
                  {saving ? 'Saving…' : editing ? 'Save Changes' : 'Create Credential'}
                </button>
                <button type="button" onClick={closeForm}
                  className="px-4 py-2 border border-border rounded text-text-secondary hover:bg-surface-hover text-sm">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete confirmation */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
          onClick={(e) => { if (e.target === e.currentTarget) setDeleteTarget(null); }}>
          <div className="bg-surface-alt border border-border rounded-lg shadow-xl w-full max-w-md p-6 space-y-4">
            <div>
              <h3 className="text-base font-semibold text-text-primary">Delete credential?</h3>
              <p className="text-sm text-text-secondary mt-1">
                Delete <strong className="text-text-primary">{deleteTarget.name}</strong>? This cannot be undone.
              </p>
            </div>
            <div className="flex gap-2 pt-1">
              <button onClick={confirmDelete} disabled={deleting}
                className="flex-1 py-2 px-4 bg-red-500 text-white rounded hover:bg-red-600 disabled:opacity-50 font-medium text-sm">
                {deleting ? 'Deleting…' : 'Yes, delete'}
              </button>
              <button onClick={() => setDeleteTarget(null)}
                className="px-4 py-2 border border-border rounded text-text-secondary hover:bg-surface-hover text-sm">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Blocked because connections still depend on the credential */}
      {inUse && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
          onClick={(e) => { if (e.target === e.currentTarget) setInUse(null); }}>
          <div className="bg-surface-alt border border-border rounded-lg shadow-xl w-full max-w-md p-6 space-y-4">
            <div>
              <h3 className="text-base font-semibold text-text-primary">“{inUse.name}” is in use</h3>
              <p className="text-sm text-text-secondary mt-1">
                {inUse.message}. Switch these connections to another credential first:
              </p>
            </div>
            <ul className="text-sm text-text-primary space-y-1 max-h-48 overflow-y-auto">
              {inUse.connections.map((c) => <li key={c.id}>• {c.name}</li>)}
              {inUse.otherCount > 0 && (
                <li className="text-text-secondary">
                  • {inUse.otherCount} connection{inUse.otherCount !== 1 ? 's' : ''} owned by other users
                </li>
              )}
            </ul>
            <button onClick={() => setInUse(null)}
              className="w-full py-2 px-4 border border-border rounded text-text-secondary hover:bg-surface-hover text-sm">
              OK
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
