/**
 * Management Users Page
 *
 * Lists all users and allows creating new users.
 * Requires MANAGEMENT role (enforced server-side).
 *
 * Note: The backend currently supports GET /users and POST /users only.
 * Edit/delete/user activation are future capabilities.
 */

import { useState, useEffect, useCallback } from 'react';
import { axiosInstance } from '../../api/client';
import { Role } from '../../lib/models';

interface UserRecord {
  id: string;
  uid: string;
  name: string;
  role: Role;
  active: boolean;
  created_at: string;
}

function IconSearch({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" />
    </svg>
  );
}

export function UserManagementPage() {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState<Role>(Role.OPERATOR);
  const [password, setPassword] = useState('');
  const [creating, setCreating] = useState(false);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await axiosInstance.get('/users');
      setUsers(res.data || []);
    } catch (err: any) {
      setError(err?.message || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const filteredUsers = users.filter((u) => {
    if (!search.trim()) return true;
    const term = search.toLowerCase();
    return (
      u.uid.toLowerCase().includes(term) ||
      u.name.toLowerCase().includes(term) ||
      u.role.toLowerCase().includes(term)
    );
  });

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    try {
      const res = await axiosInstance.post('/users', { name, role, password });
      if (res.data?.uid) {
        alert(`User created.\nUID: ${res.data.uid}\nShare the UID and password over a secure channel.`);
      }
      setName('');
      setPassword('');
      setRole(Role.OPERATOR);
      fetchUsers();
    } catch (err: any) {
      alert(`Failed to create user: ${err?.response?.data?.detail || err.message}`);
    } finally {
      setCreating(false);
    }
  };

  const roleBadge = (role: Role) => {
    const styles: Record<string, { bg: string; text: string }> = {
      OPERATOR:   { bg: '#016a71', text: '#fff' },
      VALIDATOR:  { bg: '#fff0e0', text: '#c06000' },
      MANAGEMENT: { bg: '#ede8f8', text: '#6d4fc9' },
    };
    const s = styles[role] || styles.OPERATOR;
    return (
      <span
        className="px-2 py-0.5 rounded-chip text-[11px] font-medium"
        style={{ background: s.bg, color: s.text }}
      >
        {role}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-[22px] font-medium text-ink">Users</h1>
        <p className="text-[14px] text-graphite mt-1">
          Manage operator, validator, and management accounts. Role-based access control is enforced server-side.
        </p>
      </div>

      {/* Error banner */}
      {error && (
        <div
          className="rounded-card border p-3 text-[13px]"
          style={{ background: '#fdf3f3', borderColor: '#f5c6c6', color: '#c0392b' }}
        >
          {error}
          <button onClick={fetchUsers} className="ml-3 underline text-[13px]">Retry</button>
        </div>
      )}

      {/* ── Create Form ── */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle p-4"
        style={{ background: '#fdfbfa' }}
      >
        <h3 className="text-[16px] font-medium text-graphite mb-3">Create New User</h3>
        <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-5 gap-3 items-end">
          <div className="sm:col-span-1">
            <label className="block text-[12px] text-graphite font-medium mb-1.5">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Jane Doe"
              className="input-glow w-full px-3 py-2 rounded-input text-[14px] text-ink outline-none"
              style={{ background: '#faf8f5' }}
              required
              disabled={creating}
            />
          </div>
          <div className="sm:col-span-1">
            <label className="block text-[12px] text-graphite font-medium mb-1.5">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className="input-glow w-full px-3 py-2 rounded-input text-[14px] text-ink outline-none"
              style={{ background: '#faf8f5' }}
              disabled={creating}
            >
              <option value={Role.OPERATOR}>Operator</option>
              <option value={Role.VALIDATOR}>Validator</option>
              <option value={Role.MANAGEMENT}>Management</option>
            </select>
          </div>
          <div className="sm:col-span-2">
            <label className="block text-[12px] text-graphite font-medium mb-1.5">Initial Password (min 12 chars)</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input-glow w-full px-3 py-2 rounded-input text-[14px] text-ink outline-none"
              style={{ background: '#faf8f5' }}
              minLength={12}
              autoComplete="new-password"
              required
              disabled={creating}
            />
          </div>
          <div className="sm:col-span-1">
            <button
              type="submit"
              disabled={creating || !name.trim() || password.length < 12}
              className="w-full px-4 py-2 text-[14px] font-medium text-parchment rounded-input transition-opacity hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: '#27251e' }}
            >
              {creating ? 'Creating…' : 'Create User'}
            </button>
          </div>
        </form>
      </div>

      {/* ── User List ── */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle overflow-hidden"
        style={{ background: '#fdfbfa' }}
      >
        {/* Search */}
        <div className="p-4 border-b border-warm-mist">
          <div className="relative">
            <IconSearch className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-graphite" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by UID, name, or role..."
              className="input-glow w-full px-3 pl-10 py-2 rounded-input text-[14px] text-ink outline-none"
              style={{ background: '#faf8f5' }}
            />
          </div>
          <p className="text-[12px] text-graphite mt-2">
            {filteredUsers.length} of {users.length} users shown
          </p>
        </div>

        {/* Table */}
        {loading ? (
          <div className="p-4">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-12 rounded-[4px] animate-pulse mb-2" style={{ background: '#e8e5e0' }} />
            ))}
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="text-center py-10">
            <p className="text-[14px] text-graphite">
              {users.length === 0 ? 'No users found. Create one above.' : 'No matching users found.'}
            </p>
          </div>
        ) : (
          <table className="w-full text-[13px] border-collapse">
            <thead>
              <tr style={{ borderBottom: '1px solid #e8e5e0' }}>
                {['UID', 'Name', 'Role', 'Status', 'Created'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-[11px] font-medium text-graphite uppercase tracking-wide">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map(u => (
                <tr key={u.id} style={{ borderBottom: '1px solid #f0eee9' }}>
                  <td className="px-4 py-3 font-mono text-[12px] text-graphite truncate max-w-[140px]">{u.uid}</td>
                  <td className="px-4 py-3 text-ink font-medium">{u.name}</td>
                  <td className="px-4 py-3">{roleBadge(u.role)}</td>
                  <td className="px-4 py-3">
                    <span
                      className="px-2 py-0.5 rounded-chip text-[11px] font-medium"
                      style={{
                        background: u.active ? '#d4edeb' : '#fde8e8',
                        color: u.active ? '#016a71' : '#c0392b',
                      }}
                    >
                      {u.active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-graphite text-[12px]">
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
