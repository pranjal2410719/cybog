/**
 * Dedicated Assessments Page
 *
 * Provides comprehensive inspection & management of all security assessments:
 * - Search by name / domain
 * - Status filter
 * - Profile filter
 * - Date & status sorting
 * - Table view with Name, Profile, Status, Stage, Progress, Findings, Actions
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import type { AssessmentResponse } from '../lib/models';

const STAGE_HUMAN_NAMES: Record<string, string> = {
  subfinder: 'Discovering Assets',
  dnsx: 'Resolving DNS',
  httpx: 'Scanning Services',
  naabu: 'Port Discovery',
  katana: 'Finding Endpoints',
  ffuf: 'Content Discovery',
  nuclei: 'Vulnerability Scanning',
};

const statusStyles: Record<string, { bg: string; text: string }> = {
  CREATED:             { bg: '#e8e5e0', text: '#72706b' },
  READY:               { bg: '#e3f2f0', text: '#016a71' },
  QUEUED:              { bg: '#ede8f8', text: '#6d4fc9' },
  RUNNING:             { bg: '#d4edeb', text: '#016a71' },
  COMPLETED:           { bg: '#d4edeb', text: '#016a71' },
  PARTIAL:             { bg: '#fff8e1', text: '#c06000' },
  FAILED:              { bg: '#fde8e8', text: '#c0392b' },
  CANCELLED:           { bg: '#fdf3e3', text: '#9a6700' },
  RESUMING:            { bg: '#ede8f8', text: '#6d4fc9' },
  AWAITING_VALIDATION: { bg: '#fff0e0', text: '#c06000' },
};

function StatusPill({ status }: { status: string }) {
  const s = statusStyles[status] ?? { bg: '#e8e5e0', text: '#72706b' };
  return (
    <span
      className="inline-flex items-center px-2.5 py-0.5 rounded-chip text-[11px] font-medium leading-none"
      style={{ background: s.bg, color: s.text }}
    >
      {status.replace(/_/g, ' ')}
    </span>
  );
}

export default function AssessmentsPage() {
  const navigate = useNavigate();
  const [assessments, setAssessments] = useState<AssessmentResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Controls
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [profileFilter, setProfileFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState<'created_desc' | 'created_asc' | 'progress_desc'>('created_desc');

  const fetchAssessments = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.listAssessments();
      setAssessments(data);
    } catch (err: any) {
      console.error('Failed to fetch assessments:', err);
      setError(err?.message || 'Failed to load assessments');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAssessments();
  }, [fetchAssessments]);

  // Filtering
  const filtered = assessments.filter((a) => {
    if (statusFilter !== 'ALL' && a.status !== statusFilter) return false;
    if (profileFilter !== 'ALL' && a.profile !== profileFilter) return false;
    if (search.trim() !== '') {
      const q = search.toLowerCase();
      const matchName = (a.name || '').toLowerCase().includes(q);
      const matchId = (a.assessment_id || '').toLowerCase().includes(q);
      const matchTarget = (a.artifact_root || '').toLowerCase().includes(q);
      if (!matchName && !matchId && !matchTarget) return false;
    }
    return true;
  });

  // Sorting
  const sorted = [...filtered].sort((a, b) => {
    if (sortBy === 'created_desc') {
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    }
    if (sortBy === 'created_asc') {
      return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
    }
    if (sortBy === 'progress_desc') {
      const pA = a.progress?.completion_percentage ?? 0;
      const pB = b.progress?.completion_percentage ?? 0;
      return pB - pA;
    }
    return 0;
  });

  return (
    <div className="space-y-6 max-w-[1000px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-[22px] font-medium text-ink">Assessments Management</h1>
          <p className="text-[14px] text-graphite mt-0.5">
            Inspect, filter, and manage all security assessments across the system.
          </p>
        </div>
        <button
          onClick={() => navigate('/assessments/new')}
          className="px-4 py-2 text-[14px] font-medium text-parchment rounded-input
                     transition-opacity hover:opacity-90 flex-shrink-0"
          style={{ background: '#27251e' }}
        >
          + New Assessment
        </button>
      </div>

      {/* Filter bar */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle p-4 flex flex-wrap gap-4 items-center justify-between"
        style={{ background: '#fdfbfa' }}
      >
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[240px]">
          {/* Search */}
          <input
            type="text"
            placeholder="Search by name, ID or domain…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-glow px-3.5 py-1.5 rounded-input text-[14px] text-ink outline-none border border-warm-mist flex-1 min-w-[180px]"
            style={{ background: '#faf8f5' }}
          />

          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 text-[13px] text-ink border border-warm-mist rounded-input outline-none"
            style={{ background: '#faf8f5' }}
          >
            <option value="ALL">All Statuses</option>
            <option value="RUNNING">Running</option>
            <option value="QUEUED">Queued</option>
            <option value="COMPLETED">Completed</option>
            <option value="PARTIAL">Partial</option>
            <option value="FAILED">Failed</option>
            <option value="CANCELLED">Cancelled</option>
            <option value="AWAITING_VALIDATION">Awaiting Validation</option>
          </select>

          {/* Profile filter */}
          <select
            value={profileFilter}
            onChange={(e) => setProfileFilter(e.target.value)}
            className="px-3 py-1.5 text-[13px] text-ink border border-warm-mist rounded-input outline-none"
            style={{ background: '#faf8f5' }}
          >
            <option value="ALL">All Profiles</option>
            <option value="standard">Standard</option>
            <option value="quick">Quick</option>
            <option value="full">Full</option>
          </select>
        </div>

        {/* Sort */}
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as any)}
          className="px-3 py-1.5 text-[13px] text-ink border border-warm-mist rounded-input outline-none"
          style={{ background: '#faf8f5' }}
        >
          <option value="created_desc">Sort: Newest First</option>
          <option value="created_asc">Sort: Oldest First</option>
          <option value="progress_desc">Sort: Highest Progress</option>
        </select>
      </div>

      {/* Error notification */}
      {error && (
        <div
          className="rounded-card border p-3 text-[14px] flex items-center justify-between"
          style={{ background: '#fdf3f3', borderColor: '#f5c6c6', color: '#c0392b' }}
        >
          <span>{error}</span>
          <button onClick={fetchAssessments} className="underline text-[13px] font-medium">
            Retry
          </button>
        </div>
      )}

      {/* Assessment Table */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle overflow-hidden"
        style={{ background: '#fdfbfa' }}
      >
        {loading ? (
          <div className="p-8 text-center text-graphite text-[14px]">Loading assessments…</div>
        ) : sorted.length === 0 ? (
          <div className="p-12 text-center text-graphite text-[14px]">
            No assessments match your criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr style={{ borderBottom: '1px solid #d1d1cd' }}>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Assessment</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Profile</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Status</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Current Stage</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Progress</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Findings</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Created</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Action</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((a) => {
                  const pct = a.progress?.completion_percentage ?? 0;
                  const currentStage = a.stage ? STAGE_HUMAN_NAMES[a.stage] || a.stage : 'Ready';

                  return (
                    <tr
                      key={a.assessment_id}
                      className="transition-colors hover:bg-[#faf8f5]"
                      style={{ borderBottom: '1px solid #e8e5e0' }}
                    >
                      <td className="px-4 py-3">
                        <div className="font-medium text-ink max-w-[200px] truncate" title={a.name || a.assessment_id}>
                          {a.name || a.assessment_id}
                        </div>
                        <div className="text-[11px] text-ash font-mono">{a.assessment_id}</div>
                      </td>
                      <td className="px-4 py-3 text-graphite capitalize">{a.profile}</td>
                      <td className="px-4 py-3">
                        <StatusPill status={a.status} />
                      </td>
                      <td className="px-4 py-3 text-graphite">{currentStage}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 rounded-full overflow-hidden" style={{ background: '#e8e5e0' }}>
                            <div
                              className="h-full rounded-full"
                              style={{ width: `${Math.min(100, Math.max(0, pct))}%`, background: '#016a71' }}
                            />
                          </div>
                          <span className="text-[12px] font-mono text-ink">{pct.toFixed(0)}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-graphite font-medium">
                        {a.findings_count ?? 0}
                      </td>
                      <td className="px-4 py-3 text-graphite text-[12px]">
                        {new Date(a.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => navigate(`/assessments/${a.assessment_id}`)}
                          className="px-3 py-1 text-[12px] font-medium text-graphite border border-warm-mist rounded-btn hover:text-ink transition-colors"
                          style={{ background: '#faf8f5' }}
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}