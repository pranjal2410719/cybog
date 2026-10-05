import React, { useState } from 'react';
import { authApi } from '../api/auth';
import { useAuth } from '../context/AuthContext';

export function Login() {
  const [uid, setUid] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uid.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const response = await authApi.login(uid);
      window.localStorage.setItem('cybog_token', response.token);
      window.localStorage.setItem('cybog_user', JSON.stringify(response.user));
      login(response.user);
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#f3f0eb]">
      <div className="bg-white p-8 rounded-[12px] shadow-subtle w-full max-w-sm border border-warm-mist">
        <div className="flex justify-center mb-6 text-ink">
          <svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <h1 className="text-[20px] font-medium text-center text-ink mb-2 tracking-tight">Sign in to Cybor</h1>
        <p className="text-[14px] text-graphite text-center mb-8">Enter your operator, validator, or management UID to continue.</p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="uid" className="block text-[13px] font-medium text-ink mb-1.5">
              User ID
            </label>
            <input
              id="uid"
              type="text"
              value={uid}
              onChange={(e) => setUid(e.target.value)}
              placeholder="e.g. op_0001"
              className="w-full px-3 py-2 bg-transparent border border-warm-mist rounded-btn text-[14px] text-ink placeholder:text-ash focus:outline-none focus:border-deep-teal focus:ring-1 focus:ring-deep-teal"
              autoComplete="username"
              required
            />
          </div>

          {error && (
            <div className="text-[13px] text-red-600 bg-red-50 px-3 py-2 rounded-btn border border-red-100">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full px-4 py-2 bg-deep-teal text-white rounded-btn text-[14px] font-medium hover:bg-ink transition-colors disabled:opacity-50"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
