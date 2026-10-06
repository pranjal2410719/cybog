/**
 * Assessment Detail View — Perplexity parchment redesign
 *
 * Three-section layout:
 *  1. Page header (name, status pill, back button, action buttons)
 *  2. Info + progress cards (soft-paper, 16px radius)
 *  3. Findings section (table → card stack on mobile)
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { api, WebSocketManager } from '../api';
import { LiveStatusPanel, useLiveStatus } from './LiveStatusPanel';
import type {
  AssessmentResponse,
  AssessmentStatusResponse,
  FindingResponse,
} from '../lib/models';

// ─── Status pill ──────────────────────────────────────────────────────────────

const statusStyles: Record<string, { bg: string; text: string }> = {
  CREATED:              { bg: '#e8e5e0', text: '#72706b' },
  RUNNING:              { bg: '#d4edeb', text: '#016a71' },
  COMPLETED:            { bg: '#d4edeb', text: '#016a71' },
  FAILED:               { bg: '#fde8e8', text: '#c0392b' },
  CANCELLED:            { bg: '#fdf3e3', text: '#9a6700' },
  RESUMING:             { bg: '#ede8f8', text: '#6d4fc9' },
  AWAITING_VALIDATION:  { bg: '#fff0e0', text: '#c06000' },
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

// ─── Severity pill ─────────────────────────────────────────────────────────────

const severityStyles: Record<string, { bg: string; text: string }> = {
  critical: { bg: '#fde8e8', text: '#c0392b' },
  high:     { bg: '#fff0e0', text: '#c06000' },
  medium:   { bg: '#fff8d6', text: '#9a6700' },
  low:      { bg: '#d4edeb', text: '#016a71' },
  info:     { bg: '#e8e5e0', text: '#72706b' },
};

function SeverityPill({ severity }: { severity: string }) {
  const s = severityStyles[severity.toLowerCase()] ?? { bg: '#e8e5e0', text: '#72706b' };
  return (
    <span
      className="inline-flex items-center px-2.5 py-0.5 rounded-chip text-[11px] font-medium uppercase leading-none"
      style={{ background: s.bg, color: s.text }}
    >
      {severity}
    </span>
  );
}

// ─── Validation pill ──────────────────────────────────────────────────────────

const valStyles: Record<string, { bg: string; text: string }> = {
  DISCOVERED:       { bg: '#e8e5e0', text: '#72706b' },
  NEEDS_VALIDATION: { bg: '#fff0e0', text: '#c06000' },
  VALIDATING:       { bg: '#e0e8ff', text: '#2d5be3' },
  VALIDATED:        { bg: '#d4edeb', text: '#016a71' },
  FALSE_POSITIVE:   { bg: '#fde8e8', text: '#c0392b' },
  REPORTABLE:       { bg: '#d4edeb', text: '#016a71' },
};

function ValidationPill({ status }: { status: string }) {
  const s = valStyles[status] ?? { bg: '#e8e5e0', text: '#72706b' };
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-chip text-[11px] font-medium leading-none"
      style={{ background: s.bg, color: s.text }}
    >
      {status.replace(/_/g, ' ')}
    </span>
  );
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

function ProgressBar({ pct, thin = false }: { pct: number; thin?: boolean }) {
  return (
    <div
      className={`w-full ${thin ? 'h-1' : 'h-2'} rounded-full overflow-hidden`}
      style={{ background: '#e8e5e0' }}
    >
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{
          width: `${Math.min(100, Math.max(0, pct))}%`,
          background: '#016a71',
        }}
      />
    </div>
  );
}

// ─── Info card ────────────────────────────────────────────────────────────────

function InfoCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div
      className="rounded-card border border-warm-mist shadow-subtle p-4"
      style={{ background: '#fdfbfa' }}
    >
      <h3 className="text-[13px] font-medium text-graphite uppercase tracking-wide mb-3">
        {title}
      </h3>
      {children}
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 text-[14px]">
      <span className="text-graphite w-28 flex-shrink-0">{label}</span>
      <span className="text-ink">{value}</span>
    </div>
  );
}

// ─── Action button ────────────────────────────────────────────────────────────

function ActionBtn({
  onClick,
  disabled,
  variant = 'ghost',
  children,
}: {
  onClick: () => void;
  disabled?: boolean;
  variant?: 'ghost' | 'ink' | 'danger';
  children: React.ReactNode;
}) {
  const styles: Record<string, React.CSSProperties> = {
    ghost: {
      background: 'transparent',
      color: '#72706b',
      border: '1px solid #d1d1cd',
    },
    ink: {
      background: '#27251e',
      color: '#faf8f5',
      border: 'none',
    },
    danger: {
      background: 'transparent',
      color: '#c0392b',
      border: '1px solid #f5c6c6',
    },
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="px-4 py-2 text-[13px] font-medium rounded-btn transition-opacity
                 disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-80"
      style={styles[variant]}
    >
      {children}
    </button>
  );
}

// ─── Export state ─────────────────────────────────────────────────────────────

type ExportPhase = 'idle' | 'starting' | 'building' | 'done' | 'error';
interface ExportState { phase: ExportPhase; exportId?: string; message?: string; }

// ─── Helper ───────────────────────────────────────────────────────────────────

function getSeverityBreakdown(findings: FindingResponse[]): string {
  if (findings.length === 0) return '—';
  const counts: Record<string, number> = {};
  findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  return Object.entries(counts)
    .map(([sev, cnt]) => `${sev}: ${cnt}`)
    .join(' · ');
}

// ─── Main component ───────────────────────────────────────────────────────────

interface AssessmentDetailProps {
  assessmentId: string;
  onBack?: () => void;
}

export function AssessmentDetail({ assessmentId, onBack }: AssessmentDetailProps) {
  const [assessment, setAssessment] = useState<AssessmentResponse | null>(null);
  const [status, setStatus] = useState<AssessmentStatusResponse | null>(null);
  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportState, setExportState] = useState<ExportState>({ phase: 'idle' });
  const [pendingInfo, setPendingInfo] = useState<number | null>(null);
  const [pendingError, setPendingError] = useState<string | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const errorStatusRef = useRef<number | null>(null);
  const mountedRef = useRef(true);
  const live = useLiveStatus(assessmentId);
  const isAuthorized = assessment?.authorization?.confirmed === true;

  const fetchAssessment = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [assessmentData, statusData, findingsData] = await Promise.all([
        api.getAssessment(assessmentId),
        api.getAssessmentStatus(assessmentId),
        api.getFindings(assessmentId),
      ]);
      setAssessment(assessmentData);
      setStatus(statusData);
      setFindings(findingsData);
    } catch (err: any) {
      setError(err?.message || 'Failed to load assessment details');
    } finally {
      setLoading(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    }, [assessmentId, live]);

  // Single retry loop with backoff, status-code distinction, and unmount cancellation
  useEffect(() => {
    mountedRef.current = true;
    let retries = 0;
    const maxRetries = 3;
    const initialDelay = 1000; // 1s start
    let timeoutId: NodeJS.Timeout | null = null;

    const attemptFetch = async () => {
      if (retries >= maxRetries) {
        setError('Failed to load assessment after maximum retries');
        return;
      }
      if (!mountedRef.current) return;
      retries++;
      setError(null);
      setLoading(true);
      try {
        const [assessmentData, statusData, findingsData] = await Promise.all([
          api.getAssessment(assessmentId),
          api.getAssessmentStatus(assessmentId),
          api.getFindings(assessmentId),
        ]);
        setAssessment(assessmentData);
        setStatus(statusData);
        setFindings(findingsData);
      } catch (err: any) {
        errorStatusRef.current = err.status ?? null;
        // Do not retry auth errors — show immediately and stop
        if (err.status === 401 || err.status === 403) {
          setError('Authentication failed - please check your credentials');
          mountedRef.current = false;
          return;
        }
        const msg = err?.message || 'Failed to load assessment details';
        setError(msg);
        if (retries < maxRetries) {
          const delay = initialDelay * 2 ** (retries - 1);
          timeoutId = setTimeout(attemptFetch, delay);
        }
      } finally {
        if (mountedRef.current) setLoading(false);
      }
    };

    attemptFetch();

    return () => {
      mountedRef.current = false;
      if (timeoutId) clearTimeout(timeoutId);
    };
  }, [assessmentId, fetchAssessment, live]);

  // Retry with backoff for initial load (handles race condition where
  // assessment state file isn't immediately synced to disk after creation)
  useEffect(() => {
    let retries = 0;
    const maxRetries = 3;
    const initialDelay = 1000; // 1s start

    const attemptFetch = async () => {
      if (retries >= maxRetries) {
        setError('Failed to load assessment after maximum retries');
        return;
      }
      retries++;
      setError(null);
      setLoading(true);
      try {
        const [assessmentData, statusData, findingsData] = await Promise.all([
          api.getAssessment(assessmentId),
          api.getAssessmentStatus(assessmentId),
          api.getFindings(assessmentId),
        ]);
        setAssessment(assessmentData);
        setStatus(statusData);
        setFindings(findingsData);
      } catch (err: any) {
        const msg = err?.message || 'Failed to load assessment details';
        setError(msg);
        if (retries < maxRetries) {
          const delay = initialDelay * 2 ** (retries - 1);
          const timeout = setTimeout(attemptFetch, delay);
          return () => clearTimeout(timeout);
        }
      } finally {
        setLoading(false);
      }
    };

    attemptFetch();
  }, [assessmentId, fetchAssessment]);

  const handleStartAssessment = async () => {
    // T7: preflight is mandatory before start; a NOT READY result surfaces
    // the reasons and the assessment is never marked running.
    try {
      const preflight = await api.preflightAssessment(assessmentId);
      if (!preflight.ready) {
        const reasons = preflight.checks
          .filter((c) => !c.ok)
          .map((c) => `${c.name}: ${c.detail}`)
          .join('; ');
        setError(`Not ready to start: ${reasons}`);
        fetchAssessment();
        return;
      }
      await api.startAssessment(assessmentId);
      fetchAssessment();
    } catch {
      setError('Failed to start assessment');
    }
  };

  const handleResumeAssessment = async () => {
    try { await api.resumeAssessment(assessmentId); fetchAssessment(); }
    catch { setError('Failed to resume assessment'); }
  };

  const handleAuthorizeAssessment = async () => {
    try {
      await api.authorizeAssessment(assessmentId);
      setAuthChecked(false);
      fetchAssessment();
    } catch {
      setError('Failed to confirm authorization');
    }
  };

  const handleBack = () => { if (onBack) onBack(); else window.location.href = '/'; };

  const handleCancelAssessment = async () => {
    try { await api.cancelAssessment(assessmentId); if (onBack) onBack(); else window.location.href = '/'; }
    catch { setError('Failed to cancel assessment'); }
  };

  const handleValidateFinding = async (findingId: string, notes?: string) => {
    try { await api.validateFinding(assessmentId, findingId, notes); fetchAssessment(); }
    catch { setError('Failed to validate finding'); }
  };

  const handleRejectFinding = async (findingId: string, notes?: string) => {
    try { await api.rejectFinding(assessmentId, findingId, notes); fetchAssessment(); }
    catch { setError('Failed to reject finding'); }
  };

  const handleExportAssessment = async () => {
    setExportState({ phase: 'starting' });
    setError(null);
    try {
      const exportData = await api.createExport(assessmentId);
      setExportState({ phase: 'building', exportId: exportData.export_id });
      const deadline = Date.now() + 5 * 60 * 1000;
      let s = await api.getExportStatus(assessmentId, exportData.export_id);
      while (s.status !== 'completed' && s.status !== 'failed') {
        if (Date.now() > deadline) {
          setExportState({ phase: 'error', message: 'Export timed out after 5 minutes' });
          return;
        }
        await new Promise((r) => setTimeout(r, 1000));
        s = await api.getExportStatus(assessmentId, exportData.export_id);
      }
      if (s.status === 'failed') {
        setExportState({ phase: 'error', message: s.error || 'Export failed on the server' });
        return;
      }
      const blob = await api.downloadExport(assessmentId, exportData.export_id);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `assessment-${assessmentId}.zip`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      setExportState({ phase: 'done' });
    } catch {
      setExportState({ phase: 'error', message: 'Failed to create export' });
    }
  };

  // ─── Loading ───────────────────────────────────────────────────────────────

  if (loading && !assessment) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-28 rounded-card border border-warm-mist animate-pulse"
               style={{ background: '#fdfbfa' }} />
        ))}
      </div>
    );
  }

  if (error && !assessment) {
    return (
      <div className="rounded-card border p-4 flex items-center justify-between"
           style={{ background: '#fdf3f3', borderColor: '#f5c6c6' }}>
        <p className="text-[14px]" style={{ color: '#c0392b' }}>{error}</p>
        <button onClick={fetchAssessment}
                className="px-3 py-1 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink transition-colors">
          Retry
        </button>
      </div>
    );
  }

  const pct = status?.progress?.completion_percentage !== undefined
      ? status.status === 'COMPLETED'
        ? 100
        : Math.min(100, Math.max(0, status?.progress?.completion_percentage ?? 0))
      : 0;

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-8">

      {/* Error banner (non-blocking) */}
      {error && (
        <div className="rounded-card border p-3 text-[13px]"
             style={{ background: '#fdf3f3', borderColor: '#f5c6c6', color: '#c0392b' }}>
          {error}
          <button onClick={fetchAssessment} className="ml-3 underline text-[13px]">Retry</button>
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-[22px] font-medium text-ink">
              {assessment?.name || 'Assessment Details'}
            </h1>
            {assessment && <StatusPill status={assessment.status} />}
          </div>
          <p className="text-[13px] text-graphite mt-1 font-mono">{assessmentId}</p>
        </div>
        <button
          onClick={handleBack}
          className="px-3 py-1.5 text-[13px] text-graphite border border-warm-mist
                     rounded-btn hover:text-ink hover:border-ash transition-colors flex-shrink-0"
        >
          ← Back
        </button>
      </div>

      {/* ── Live Status Panel ── */}
      <section
        className="rounded-card border border-warm-mist shadow-subtle p-4"
        style={{ background: '#fdfbfa' }}
      >
        <p className="text-[12px] font-medium text-graphite uppercase tracking-wide mb-3">
          Live Execution
        </p>
        <LiveStatusPanel status={live} onRefresh={fetchAssessment} />
      </section>

      {/* ── Info Cards ── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <InfoCard title="Assessment Info">
          <div className="space-y-2">
            <InfoRow
              label="Created"
              value={assessment ? new Date(assessment.created_at).toLocaleString() : '—'}
            />
            <InfoRow label="Profile" value={<span className="capitalize">{assessment?.profile}</span>} />
            <InfoRow
              label="Root"
              value={assessment?.artifact_root.split('/').pop() || '—'}
            />
          </div>
        </InfoCard>

        <InfoCard title="Progress">
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-[13px] text-graphite mb-1">
                <span>Overall</span>
                <span className="text-ink font-medium">{pct.toFixed(1)}%</span>
              </div>
              <ProgressBar pct={pct} />
            </div>
            {(status?.progress?.targets?.length ?? 0) > 0 && (
              <div className="space-y-2 mt-2">
                {(status!.progress!.targets as any[]).map((t) => (
                  <div key={t.target_id}>
                    <div className="flex justify-between text-[12px] text-graphite mb-0.5">
                      <span className="truncate max-w-[120px]">{t.domain}</span>
                      <StatusPill status={t.status} />
                    </div>
                    <ProgressBar pct={t.completion_percentage ?? 0} thin />
                  </div>
                ))}
              </div>
            )}
          </div>
        </InfoCard>

        <InfoCard title="Statistics">
          <div className="space-y-2">
            <InfoRow label="Findings" value={findings.length} />
            <InfoRow label="Pending" value={status?.pending_validation_count ?? 0} />
            <InfoRow label="Severity" value={getSeverityBreakdown(findings)} />
            <InfoRow
              label="Updated"
              value={status ? new Date(status.updated_at).toLocaleString() : '—'}
            />
          </div>
        </InfoCard>
      </div>

      {/* ── Actions ── */}
      {assessment && (
        <div className="flex flex-wrap gap-2 items-center">
          {assessment.status === 'CREATED' && !isAuthorized && (
            <>
              <label className="flex items-center gap-2 text-[13px] text-ink w-full mb-1">
                <input
                  type="checkbox"
                  checked={authChecked}
                  onChange={(e) => setAuthChecked(e.target.checked)}
                />
                <span>I confirm that I am authorized to assess this target and scope.</span>
              </label>
              <ActionBtn
                onClick={handleAuthorizeAssessment}
                disabled={!authChecked}
                variant="ink"
              >
                Confirm Authorization
              </ActionBtn>
            </>
          )}
          <ActionBtn
            onClick={handleStartAssessment}
            disabled={!['CREATED', 'READY'].includes(assessment.status)}
            variant="ink"
          >
            {assessment.status === 'CREATED' && !isAuthorized ? 'Start (authorize first)' : 'Start'}
          </ActionBtn>
          <ActionBtn
            onClick={handleResumeAssessment}
            disabled={!['FAILED', 'AWAITING_VALIDATION'].includes(assessment.status)}
          >
            Resume
          </ActionBtn>
          <ActionBtn
            onClick={handleCancelAssessment}
            disabled={!['RUNNING', 'RESUMING'].includes(assessment.status)}
            variant="danger"
          >
            Cancel
          </ActionBtn>
          <ActionBtn
            onClick={handleExportAssessment}
            disabled={exportState.phase === 'starting' || exportState.phase === 'building'}
          >
            {exportState.phase === 'starting' && 'Starting export…'}
            {exportState.phase === 'building' && 'Building archive…'}
            {exportState.phase === 'done'     && 'Downloaded ✓'}
            {exportState.phase === 'error'    && 'Retry Export'}
            {exportState.phase === 'idle'     && 'Export ZIP'}
          </ActionBtn>
          {exportState.phase === 'error' && exportState.message && (
            <p className="w-full text-[12px]" style={{ color: '#c0392b' }}>
              {exportState.message}
            </p>
          )}
        </div>
      )}

      {/* ── Findings ── */}
      <section>
        <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <h2 className="text-[18px] font-medium text-ink">
              Findings
            </h2>
            <span
              className="px-2 py-0.5 rounded-chip text-[12px] font-medium"
              style={{ background: '#e8e5e0', color: '#72706b' }}
            >
              {findings.length}
            </span>
            {(status?.pending_validation_count ?? 0) > 0 && (
              <span
                className="px-2 py-0.5 rounded-chip text-[11px] font-medium"
                style={{ background: '#fff0e0', color: '#c06000' }}
              >
                {status!.pending_validation_count} pending
              </span>
            )}
          </div>
          {findings.length > 0 && (
            <button
              onClick={async () => {
                try {
                  const data = await api.getPendingValidation(assessmentId);
                  setPendingInfo(data.pending_count);
                  setPendingError(null);
                } catch {
                  setPendingError('Failed to load pending validation');
                }
              }}
              className="px-3 py-1.5 text-[13px] text-graphite border border-warm-mist
                         rounded-btn hover:text-ink hover:border-ash transition-colors"
            >
              Check Pending
            </button>
          )}
        </div>

        {pendingError && <p className="mb-3 text-[13px]" style={{ color: '#c0392b' }}>{pendingError}</p>}
        {pendingInfo !== null && !pendingError && (
          <div
            className="mb-4 px-4 py-2.5 rounded-card text-[14px]"
            style={{
              background: pendingInfo === 0 ? '#f0faf8' : '#fff8ee',
              border: pendingInfo === 0 ? '1px solid #a8d8d2' : '1px solid #f5d5a0',
              color: pendingInfo === 0 ? '#016a71' : '#9a6700',
            }}
          >
            {pendingInfo === 0
              ? 'No findings are awaiting a validation decision.'
              : `${pendingInfo} finding${pendingInfo === 1 ? '' : 's'} pending validation — use Confirm / Reject below.`}
          </div>
        )}

        {findings.length === 0 ? (
          <div
            className="rounded-card border border-warm-mist shadow-subtle text-center py-12"
            style={{ background: '#fdfbfa' }}
          >
            <p className="text-[14px] text-graphite">No findings discovered yet</p>
            {(assessment?.status === 'RUNNING' || assessment?.status === 'RESUMING') && (
              <p className="mt-1 text-[13px] text-ash">Scan is still in progress…</p>
            )}
          </div>
        ) : (
          <>
            {/* Desktop table */}
            <div className="hidden sm:block overflow-x-auto rounded-card border border-warm-mist shadow-subtle"
                 style={{ background: '#fdfbfa' }}>
              <table className="w-full text-left border-collapse text-[13px]">
                <thead>
                  <tr style={{ borderBottom: '1px solid #d1d1cd' }}>
                    {['Severity', 'Title', 'Target', 'Tool', 'Validation', 'Actions'].map((h) => (
                      <th key={h}
                          className="px-4 py-3 text-[12px] font-medium text-graphite uppercase tracking-wide">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr
                      key={finding.finding_id}
                      className="transition-colors"
                      style={{ borderBottom: '1px solid #e8e5e0' }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = '#f5f2ed')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = '')}
                    >
                      <td className="px-4 py-3">
                        <SeverityPill severity={finding.severity} />
                      </td>
                      <td className="px-4 py-3 max-w-[180px]">
                        <span className="truncate block text-ink" title={finding.title}>
                          {finding.title}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-graphite">{finding.target_domain}</td>
                      <td className="px-4 py-3 text-graphite font-mono text-[12px]">{finding.source_tool}</td>
                      <td className="px-4 py-3">
                        <ValidationPill status={finding.validation_status} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1.5">
                          {finding.validation_status === 'VALIDATING' && (
                            <>
                              <button
                                onClick={() => handleValidateFinding(finding.finding_id)}
                                className="px-2 py-0.5 text-[11px] rounded-btn font-medium transition-opacity hover:opacity-75"
                                style={{ background: '#016a71', color: '#fff' }}
                              >
                                Confirm
                              </button>
                              <button
                                onClick={() => handleRejectFinding(finding.finding_id)}
                                className="px-2 py-0.5 text-[11px] rounded-btn font-medium transition-opacity hover:opacity-75"
                                style={{ background: '#fde8e8', color: '#c0392b', border: '1px solid #f5c6c6' }}
                              >
                                Reject
                              </button>
                            </>
                          )}
                          {finding.validation_status === 'NEEDS_VALIDATION' && (
                            <button
                              onClick={() => {
                                const notes = prompt('Add validation notes (optional):');
                                handleValidateFinding(finding.finding_id, notes ?? undefined);
                              }}
                              className="px-2 py-0.5 text-[11px] rounded-btn font-medium transition-opacity hover:opacity-75"
                              style={{ background: '#e0e8ff', color: '#2d5be3', border: '1px solid #c0ccf8' }}
                            >
                              Validate
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile card stack */}
            <div className="sm:hidden space-y-3">
              {findings.map((finding) => (
                <div
                  key={finding.finding_id}
                  className="rounded-card border border-warm-mist shadow-subtle p-4 space-y-2"
                  style={{ background: '#fdfbfa' }}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <SeverityPill severity={finding.severity} />
                    <ValidationPill status={finding.validation_status} />
                  </div>
                  <p className="text-[14px] text-ink font-medium">{finding.title}</p>
                  <div className="flex gap-4 text-[12px] text-graphite">
                    <span>{finding.target_domain}</span>
                    <span className="font-mono">{finding.source_tool}</span>
                  </div>
                  {finding.validation_status === 'VALIDATING' && (
                    <div className="flex gap-2 pt-1">
                      <button
                        onClick={() => handleValidateFinding(finding.finding_id)}
                        className="flex-1 py-1.5 text-[13px] rounded-btn font-medium"
                        style={{ background: '#016a71', color: '#fff' }}
                      >
                        Confirm
                      </button>
                      <button
                        onClick={() => handleRejectFinding(finding.finding_id)}
                        className="flex-1 py-1.5 text-[13px] rounded-btn font-medium"
                        style={{ background: '#fde8e8', color: '#c0392b', border: '1px solid #f5c6c6' }}
                      >
                        Reject
                      </button>
                    </div>
                  )}
                  {finding.validation_status === 'NEEDS_VALIDATION' && (
                    <button
                      onClick={() => {
                        const notes = prompt('Add validation notes (optional):');
                        handleValidateFinding(finding.finding_id, notes ?? undefined);
                      }}
                      className="w-full py-1.5 text-[13px] rounded-btn font-medium"
                      style={{ background: '#e0e8ff', color: '#2d5be3' }}
                    >
                      Validate
                    </button>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </section>
    </div>
  );
}