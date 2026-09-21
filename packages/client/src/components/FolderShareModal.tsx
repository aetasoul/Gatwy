import { useEffect, useState } from 'react';

interface FolderShareModalProps {
  groupId: string;
  groupName: string;
  onClose: () => void;
}

export function FolderShareModal({ groupId, groupName, onClose }: FolderShareModalProps) {
  const [shareRoles, setShareRoles] = useState<{ id: string; name: string }[]>([]);
  const [shareUsers, setShareUsers] = useState<{ id: string; username: string }[]>([]);
  const [selectedRoles, setSelectedRoles] = useState<string[]>([]);
  const [selectedUsers, setSelectedUsers] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch('/api/v1/roles', { credentials: 'include' })
      .then(r => r.json())
      .then(d => { if (Array.isArray(d)) setShareRoles(d.map((r: { id: string; name: string }) => ({ id: r.id, name: r.name }))); })
      .catch(() => {});
    fetch('/api/v1/users', { credentials: 'include' })
      .then(r => r.json())
      .then(d => { if (d?.users && Array.isArray(d.users)) setShareUsers(d.users.map((u: { id: string; username: string }) => ({ id: u.id, username: u.username }))); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetch(`/api/v1/connections/groups/${groupId}/shares`, { credentials: 'include' })
      .then(r => r.json())
      .then((d: { shareType: string; targetId: string }[]) => {
        if (!Array.isArray(d)) return;
        setSelectedRoles(d.filter(s => s.shareType === 'role').map(s => s.targetId));
        setSelectedUsers(d.filter(s => s.shareType === 'user').map(s => s.targetId));
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [groupId]);

  async function handleSave() {
    setSaving(true);
    setError('');
    try {
      const shares = [
        ...selectedRoles.map(id => ({ shareType: 'role', targetId: id })),
        ...selectedUsers.map(id => ({ shareType: 'user', targetId: id })),
      ];
      const res = await fetch(`/api/v1/connections/groups/${groupId}/shares`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ shares }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        setError(d.error || 'Failed to save');
        setSaving(false);
        return;
      }
      onClose();
    } catch {
      setError('Failed to save');
      setSaving(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className="bg-surface-alt border border-border rounded-lg shadow-xl w-full max-w-sm max-h-[85vh] flex flex-col overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="px-5 pt-4 pb-2 border-b border-border">
          <h2 className="text-base font-bold text-text-primary">Share Folder</h2>
          <p className="text-xs text-text-secondary mt-0.5 truncate">
            "{groupName}" — sub-folders and connections are included, now and later
          </p>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-3">
          {loading ? (
            <p className="text-xs text-text-secondary">Loading…</p>
          ) : (
            <>
              <div>
                <label className="block text-[10px] font-medium text-text-secondary mb-1">Share with roles</label>
                <div className="space-y-1">
                  {shareRoles.map(r => (
                    <label key={r.id} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedRoles.includes(r.id)}
                        onChange={() => setSelectedRoles(prev =>
                          prev.includes(r.id) ? prev.filter(x => x !== r.id) : [...prev, r.id]
                        )}
                        className="accent-accent"
                      />
                      <span className="text-xs text-text-primary">{r.name}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-[10px] font-medium text-text-secondary mb-1">Share with users</label>
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {shareUsers.map(u => (
                    <label key={u.id} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedUsers.includes(u.id)}
                        onChange={() => setSelectedUsers(prev =>
                          prev.includes(u.id) ? prev.filter(x => x !== u.id) : [...prev, u.id]
                        )}
                        className="accent-accent"
                      />
                      <span className="text-xs text-text-primary">{u.username}</span>
                    </label>
                  ))}
                </div>
              </div>
            </>
          )}

          {error && <p className="text-red-500 text-xs">{error}</p>}
        </div>

        <div className="flex gap-2 px-5 pb-4 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="flex-1 py-1.5 text-sm border border-border rounded text-text-secondary hover:bg-surface-hover"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={saving || loading}
            className="flex-1 py-1.5 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50 font-medium"
          >
            {saving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}
