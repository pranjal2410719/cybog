import { useState, useEffect } from 'react';
import { Role } from '../../lib/models';
import { axiosInstance } from '../../api/client';

export function UserManagementPage() {
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [role, setRole] = useState<Role>(Role.OPERATOR);
  const [error, setError] = useState('');

  const fetchUsers = async () => {
    try {
      const res = await axiosInstance.get('/users'); // Need to implement this backend endpoint
      setUsers(res.data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await axiosInstance.post('/users', { name, role });
      setName('');
      fetchUsers();
    } catch (err: any) {
      alert(`Failed to create user: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white p-6 rounded-card border border-warm-mist shadow-subtle">
        <h2 className="text-[16px] text-ink font-semibold mb-4">Create New User</h2>
        <form onSubmit={handleCreate} className="flex gap-4 items-end">
          <div className="flex-1">
            <label className="block text-[13px] font-medium text-ink mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 border border-warm-mist rounded-btn text-[14px]"
              required
            />
          </div>
          <div className="flex-1">
            <label className="block text-[13px] font-medium text-ink mb-1">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className="w-full px-3 py-2 border border-warm-mist rounded-btn text-[14px]"
            >
              <option value={Role.OPERATOR}>Operator</option>
              <option value={Role.VALIDATOR}>Validator</option>
              <option value={Role.MANAGEMENT}>Management</option>
            </select>
          </div>
          <button type="submit" className="px-4 py-2 bg-deep-teal text-white rounded-btn text-[14px] font-medium h-[38px]">
            Create User
          </button>
        </form>
      </div>

      <div className="bg-white rounded-card border border-warm-mist shadow-subtle overflow-hidden">
        <table className="w-full text-left text-[14px]">
          <thead className="bg-soft-paper border-b border-warm-mist">
            <tr>
              <th className="px-4 py-3 font-medium text-graphite">UID</th>
              <th className="px-4 py-3 font-medium text-graphite">Name</th>
              <th className="px-4 py-3 font-medium text-graphite">Role</th>
              <th className="px-4 py-3 font-medium text-graphite">Created</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={4} className="px-4 py-4 text-center">Loading...</td></tr>
            ) : users.map(u => (
              <tr key={u.uid} className="border-b border-warm-mist last:border-0">
                <td className="px-4 py-3 font-mono text-[13px]">{u.uid}</td>
                <td className="px-4 py-3 font-medium">{u.name}</td>
                <td className="px-4 py-3">
                  <span className="px-2 py-1 bg-warm-mist/30 text-ink rounded-[4px] text-[12px]">
                    {u.role}
                  </span>
                </td>
                <td className="px-4 py-3 text-graphite">{new Date(u.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
