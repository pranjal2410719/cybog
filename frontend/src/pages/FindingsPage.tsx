/**
 * Dedicated Findings Page
 *
 * Displays all security findings across assessments:
 * - Severity filters (All, Critical, High, Medium, Low, Informational)
 * - Status filters (All, Discovered, Needs Validation, Validating, Validated, False Positive, Reportable)
 * - Detailed table listing finding severity, title, target, assessment name, source tool, status pill, confidence, and timestamp
 * - Modal / drawer for Finding Details with real evidence or "No evidence collected."
 */

import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type { FindingResponse, AssessmentResponse } from '../lib/models';

const severityStyles: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: '#fde8e8', text: '#c0392b', border: '#f5c6c6' },
  high:     { bg: '#fff0e0', text: '#c06000', border: '#f5d5a0' },
  medium:   { bg: '#fff8d6', text: '#9a6700', border: '#f5e0a9' },
  low:      { bg: '#e0f2f1', text: '#016a71', border: '#a8d8d2' },
  info:     { bg: '#e8e5e0', text: '#72706b', border: '#d1d1cd' },
};

const valStyles: Record<string, { bg: string; text: string }> = {
  DISCOVERED:          { bg: '#e8e5e0', text: '#72706b' },
  NEEDS_VALIDATION:    { bg: '#fff0e0', text: '#c06000' },
  VALIDATING:          { bg: '#e0e8ff', text: '#2d5be3' },
  VALIDATED:           { bg: '#d4edeb', text: '#016a71' },
  FALSE_POSITIVE:      { bg: '#fde8e8', text: '#c0392b' },
  REPORTABLE:          { bg: '#d4edeb', text: '#016a71' },
};

function SeverityPill({ severity }: { severity: string }) {
  const s = severityStyles[severity.toLowerCase()] ?? { bg: '#e8e5e0', text: '#72706b', border: '#d1d1cd' };
  return (
    <span
      className="inline-flex items-center px-2.5 py-0.5 rounded-chip text-[11px] font-medium leading-none"
      style={{ background: s.bg, color: s.text, border: `1px solid ${s.border}` }}
    >
      {severity.toUpperCase()}
    </span>
  );
}

function ValidationPill({ status }: { status: string }) {
  const s = valStyles[status] ?? { bg: '#e8e5e0', text: '#72706b' };
  return (
    <span
      className="inline-flex items-center px-2.5 py-0.5 rounded-chip text-[11px] font-medium leading-none"
      style={{ background: s.bg, color: s.text }}
    >
      {status.replace(/_/g, ' ')}
    </span>
  );
}

export default function FindingsPage() {
  const [findings, setFindings] = useState<Array<FindingResponse & { assessmentName?: string }>>([]);
  const [assessments, setAssessments] = useState<AssessmentResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Selected finding for modal
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedAssessmentId, setSelectedAssessmentId] = useState('ALL');
  const [search, setSearch] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<(FindingResponse & { assessmentName?: string }) | null>(null);

  const loadFindings = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const list = await api.listAssessments();
      setAssessments(list);

      const all: Array<FindingResponse & { assessmentName?: string }> = [];
      await Promise.all(
        list.map(async (a) => {
          try {
            const fList = await api.getFindings(a.assessment_id);
            fList.forEach((f) => {
              all.push({ ...f, assessmentName: a.name || a.assessment_id });
            });
          } catch {
            // Ignore single assessment finding fetch failure
          }
        })
      );

      setFindings(all);
    } catch (err: any) {
      console.error('Failed to load findings:', err);
      setError(err?.message || 'Failed to load findings');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  // Filter logic
  const filtered = findings.filter((f) => {
    if (severityFilter !== 'ALL' && f.severity.toLowerCase() !== severityFilter.toLowerCase()) return false;
    if (statusFilter !== 'ALL' && f.validation_status !== statusFilter) return false;
    if (selectedAssessmentId !== 'ALL' && f.target_id !== selectedAssessmentId && f.finding_id !== selectedAssessmentId) return false;
    if (search.trim() !== '') {
      const q = search.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchDomain = f.target_domain.toLowerCase().includes(q);
      const matchType = (f.finding_type || '').toLowerCase().includes(q);
      if (!matchTitle && !matchDomain && !matchType) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 max-w-[1000px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-[22px] font-medium text-ink">Security Findings</h1>
          <p className="text-[14px] text-graphite mt-0.5">
            Inspect all discovered vulnerabilities, candidate findings, and evidence across assessments.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle p-4 flex flex-wrap gap-3 items-center justify-between"
        style={{ background: '#fdfbfa' }}
      >
        <div className="flex flex-wrap items-center gap-3 flex-1">
          {/* Search */}
          <input
            type="text"
            placeholder="Search by title, domain or type…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-glow px-3.5 py-1.5 rounded-input text-[14px] text-ink outline-none border border-warm-mist flex-1 min-w-[200px]"
            style={{ background: '#faf8f5' }}
          />

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 text-[13px] text-ink border border-warm-mist rounded-input outline-none"
            style={{ background: '#faf8f5' }}
          >
            <option value="ALL">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Informational</option>
          </select>

          {/* Validation Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 text-[13px] text-ink border border-warm-mist rounded-input outline-none"
            style={{ background: '#faf8f5' }}
          >
            <option value="ALL">All Validation Statuses</option>
            <option value="DISCOVERED">Discovered</option>
            <option value="NEEDS_VALIDATION">Needs Validation</option>
            <option value="VALIDATING">Validating</option>
            <option value="VALIDATED">Validated</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="REPORTABLE">Reportable</option>
          </select>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div
          className="rounded-card border p-3 text-[14px] flex items-center justify-between"
          style={{ background: '#fdf3f3', borderColor: '#f5c6c6', color: '#c0392b' }}
        >
          <span>{error}</span>
          <button onClick={loadFindings} className="underline text-[13px] font-medium">
            Retry
          </button>
        </div>
      )}

      {/* Findings Table */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle overflow-hidden"
        style={{ background: '#fdfbfa' }}
      >
        {loading ? (
          <div className="p-8 text-center text-graphite text-[14px]">Loading security findings…</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-graphite text-[14px]">
            No findings discovered matching your filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr style={{ borderBottom: '1px solid #d1d1cd' }}>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Severity</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Title</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Target Domain</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Assessment</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Source Tool</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Validation Status</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((f) => (
                  <tr
                    key={f.finding_id}
                    className="transition-colors hover:bg-[#faf8f5] cursor-pointer"
                    onClick={() => setSelectedFinding(f)}
                    style={{ borderBottom: '1px solid #e8e5e0' }}
                  >
                    <td className="px-4 py-3">
                      <SeverityPill severity={f.severity} />
                    </td>
                    <td className="px-4 py-3 font-medium text-ink max-w-[220px] truncate" title={f.title}>
                      {f.title}
                    </td>
                    <td className="px-4 py-3 text-graphite">{f.target_domain}</td>
                    <td className="px-4 py-3 text-graphite max-w-[150px] truncate">{f.assessmentName || '—'}</td>
                    <td className="px-4 py-3 text-graphite font-mono text-[12px]">{f.source_tool}</td>
                    <td className="px-4 py-3">
                      <ValidationPill status={f.validation_status} />
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                        className="px-2.5 py-1 text-[12px] text-graphite border border-warm-mist rounded-btn hover:text-ink transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm">
          <div
            className="rounded-card border border-warm-mist shadow-lg w-full max-w-2xl max-h-[85vh] overflow-y-auto p-6 space-y-5"
            style={{ background: '#fdfbfa' }}
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <SeverityPill severity={selectedFinding.severity} />
                  <ValidationPill status={selectedFinding.validation_status} />
                </div>
                <h2 className="text-[18px] font-medium text-ink">{selectedFinding.title}</h2>
                <p className="text-[12px] text-graphite font-mono mt-0.5">{selectedFinding.finding_id}</p>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-[20px] text-graphite hover:text-ink font-bold px-2"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-[13px] text-graphite bg-[#faf8f5] p-3.5 rounded-[8px] border border-warm-mist">
              <div><strong>Target Domain:</strong> {selectedFinding.target_domain}</div>
              <div><strong>Source Tool:</strong> <span className="font-mono">{selectedFinding.source_tool}</span></div>
              <div><strong>URL / Asset:</strong> {selectedFinding.url || '—'}</div>
              <div><strong>Template ID:</strong> {selectedFinding.template_id || '—'}</div>
              <div><strong>First Seen:</strong> {new Date(selectedFinding.first_seen).toLocaleString()}</div>
              <div><strong>Occurrences:</strong> {selectedFinding.occurrence_count}</div>
            </div>

            {selectedFinding.description && (
              <div>
                <h3 className="text-[12px] font-medium text-graphite uppercase tracking-wide mb-1">Description</h3>
                <p className="text-[13px] text-ink">{selectedFinding.description}</p>
              </div>
            )}

            {/* Evidence Section */}
            <div>
              <h3 className="text-[12px] font-medium text-graphite uppercase tracking-wide mb-2">Evidence & Output</h3>
              {selectedFinding.evidence && selectedFinding.evidence.length > 0 ? (
                <div className="space-y-3">
                  {selectedFinding.evidence.map((ev, idx) => (
                    <div key={idx} className="p-3 rounded-[8px] border border-warm-mist bg-white space-y-2">
                      <div className="flex items-center justify-between text-[12px] text-graphite">
                        <span>Tool: <strong className="font-mono">{ev.tool}</strong></span>
                        <span>{new Date(ev.collected_at).toLocaleTimeString()}</span>
                      </div>
                      {ev.request && (
                        <div>
                          <span className="text-[11px] font-medium text-ash uppercase">Request / Curl</span>
                          <pre className="p-2 rounded bg-gray-50 text-[11px] font-mono overflow-x-auto">{ev.request}</pre>
                        </div>
                      )}
                      <div>
                        <span className="text-[11px] font-medium text-ash uppercase">Raw Output</span>
                        <pre className="p-2 rounded bg-gray-50 text-[11px] font-mono overflow-x-auto max-h-48">{ev.raw_output}</pre>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 rounded-[8px] border border-warm-mist bg-[#faf8f5] text-center text-[13px] text-graphite">
                  No evidence collected.
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 text-[13px] font-medium text-graphite border border-warm-mist rounded-btn hover:text-ink"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
