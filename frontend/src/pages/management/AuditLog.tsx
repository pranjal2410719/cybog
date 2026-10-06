/**
 * Management Audit Log Page
 *
 * Displays system-wide audit events with filtering and CSV export.
 * Requires MANAGEMENT role (enforced server-side).
 */

import { useState, useEffect, useCallback } from 'react';
import { api, type AuditEvent } from '../../api';

function IconRefresh({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 12a9 9 0 0 1 9-9 9.7 9.7 0 0 1 6.6 2.7l-2.6 2.6A5 5 0 1 0 12 16a5 5 0 0 0 4.5-3" />
    </svg>
  );
}

function IconDownload({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
    </svg>
  );
}

export function AuditLogPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [selectedAssessment, setSelectedAssessment] = useState('');

  const filteredEvents = (events || [])
    .filter((e) => {
      if (selectedAssessment && e.assessment_id !== selectedAssessment) return false;
      if (search.trim()) {
        const term = search.toLowerCase();
        const actionMatch = (e.action || '').toLowerCase().includes(term);
        const userMatch = (e.user_name || e.user_id || '').toLowerCase().includes(term);
        const detailMatch = (e.detail || '').toLowerCase().includes(term);
        const targetMatch = (e.target || '').toLowerCase().includes(term);
        return actionMatch || userMatch || detailMatch || targetMatch;
      }
      return true;
    });

  const loadEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = selectedAssessment ? { assessment_id: selectedAssessment } : undefined;
      const data = await api.getAuditEvents(params);
      setEvents(data.events || []);
    } catch (err: any) {
      setError(err?.message || 'Failed to load audit events');
    } finally {
      setLoading(false);
    }
  }, [selectedAssessment]);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  const exportCSV = () => {
    const header = ['Timestamp', 'User', 'Action', 'Assessment', 'Target', 'Detail', 'IP'];
    const rows = filteredEvents.map(e => [
      e.timestamp,
      e.user_name || e.user_id || '',
      e.action,
      e.assessment_id || '',
      e.target || '',
      e.detail,
       e.ip_address || '',
    ]);
    const csv = [header, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-events-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const uniqueAssessmentIds = Array.from(new Set((events || []).filter(e => e.assessment_id).map(e => e.assessment_id)));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-[22px] font-medium text-ink">Audit Log</h1>
        <p className="text-[14px] text-graphite mt-1">
          System-wide audit events across all assessments and users.
        </p>
      </div>

      {/* Filters */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle p-4"
        style={{ background: '#fdfbfa' }}
      >
        <div className="flex flex-wrap gap-4 items-end">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-[12px] text-graphite font-medium mb-1.5">Search</label>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by user, action, target, or detail..."
              className="input-glow w-full px-3 py-2 rounded-input text-[14px] text-ink outline-none"
              style={{ background: '#faf8f5' }}
            />
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-[12px] text-graphite font-medium mb-1.5">Assessment Filter</label>
            <select
              value={selectedAssessment}
              onChange={(e) => setSelectedAssessment(e.target.value)}
              className="input-glow w-full px-3 py-2 rounded-input text-[14px] text-ink outline-none"
              style={{ background: '#faf8f5' }}
            >
              <option value="">All assessments</option>
               {uniqueAssessmentIds.map(id => (
                 <option key={id ?? 'null'} value={id ?? ''}>{id ?? '—'}</option>
               ))}
            </select>
          </div>
          <div className="flex gap-2">
            <button
              onClick={loadEvents}
              className="px-3 py-2 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink hover:bg-warm-mist/40 transition-colors"
              disabled={loading}
              aria-label="Refresh"
            >
              <IconRefresh className="w-4 h-4" />
            </button>
            <button
              onClick={exportCSV}
              disabled={filteredEvents.length === 0}
              className="px-3 py-2 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink hover:bg-warm-mist/40 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              aria-label="Export CSV"
            >
              <IconDownload className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div
          className="rounded-card border p-3 text-[13px]"
          style={{ background: '#fdf3f3', borderColor: '#f5c6c6', color: '#c0392b' }}
        >
          {error}
        </div>
      )}

      {/* Results count */}
      <div className="text-[13px] text-graphite">
        {filteredEvents.length} of {events.length} events shown
      </div>

      {/* Events table */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle overflow-hidden"
        style={{ background: '#fdfbfa' }}
      >
        {loading ? (
          <div className="p-4">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-12 rounded-[4px] animate-pulse mb-2" style={{ background: '#e8e5e0' }} />
            ))}
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-[14px] text-graphite">No audit events found.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px] border-collapse">
              <thead>
                <tr style={{ borderBottom: '1px solid #e8e5e0' }}>
                  {['Timestamp', 'User', 'Action', 'Assessment', 'Detail', 'IP'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-[11px] font-medium text-graphite uppercase tracking-wide">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map(e => (
                  <tr key={e.event_id} style={{ borderBottom: '1px solid #f0eee9' }}>
                    <td className="px-4 py-3 text-graphite">{new Date(e.timestamp).toLocaleString()}</td>
                    <td className="px-4 py-3 text-ink">{e.user_name || e.user_id}</td>
                    <td className="px-4 py-3">
                      <span
                        className="px-2 py-0.5 rounded-chip text-[11px] font-medium border"
                        style={{ background: '#e8e5e0', color: '#72706b', border: '1px solid #d1d1cd' }}
                      >
                        {e.action.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-[12px] text-graphite truncate max-w-[120px]">
                      {e.assessment_id || '—'}
                    </td>
                    <td className="px-4 py-3 text-graphite max-w-[250px] truncate">{e.detail || '—'}</td>
                    <td className="px-4 py-3 text-graphite text-[12px]">{e.ip_address || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
