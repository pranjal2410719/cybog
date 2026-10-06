/**
 * Validation Finding Detail — Validator Section
 *
 * Full-screen finding review page for the validator workflow.
 * Shows complete finding details including evidence, and provides
 * confirm/reject actions with optional notes.
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../../api';
import type { FindingResponse } from '../../lib/models';

const severityStyles: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: '#fde8e8', text: '#c0392b', border: '#f5c6c6' },
  high:     { bg: '#fff0e0', text: '#c06000', border: '#f5d5a0' },
  medium:   { bg: '#fff8d6', text: '#9a6700', border: '#f5e0a9' },
  low:      { bg: '#e0f2f1', text: '#016a71', border: '#a8d8d2' },
  info:     { bg: '#e8e5e0', text: '#72706b', border: '#d1d1cd' },
};

const valStyles: Record<string, { bg: string; text: string }> = {
  DISCOVERED:          { bg: '#e8e5e0', text: '#72706b' },
  UNVALIDATED:         { bg: '#fff0e0', text: '#c06000' },
  NEEDS_VALIDATION:    { bg: '#fff0e0', text: '#c06000' },
  VALIDATING:          { bg: '#e0e8ff', text: '#2d5be3' },
  VALID:               { bg: '#d4edeb', text: '#016a71' },
  INVALID:             { bg: '#fde8e8', text: '#c0392b' },
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

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 text-[14px]">
      <span className="text-graphite w-32 flex-shrink-0">{label}</span>
      <span className="text-ink">{value}</span>
    </div>
  );
}

interface ValidationFindingDetailProps {
  assessmentId: string;
  findingId: string;
  onBack?: () => void;
  onValidationComplete?: () => void;
}

type DecisionState = 'idle' | 'validating' | 'success';

export function ValidationFindingDetail({
  assessmentId,
  findingId,
  onBack,
  onValidationComplete,
}: ValidationFindingDetailProps) {
  const navigate = useNavigate();
  const [finding, setFinding] = useState<FindingResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [decisionState, setDecisionState] = useState<DecisionState>('idle');

  const loadFinding = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getFinding(assessmentId, findingId);
      setFinding(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load finding');
    } finally {
      setLoading(false);
    }
  }, [assessmentId, findingId]);

  useEffect(() => {
    loadFinding();
  }, [loadFinding]);

  const handleBack = () => {
    if (onBack) onBack();
    else navigate(`/validator/queue/${assessmentId}`);
  };

  const handleValidate = async (notes?: string) => {
    setDecisionState('validating');
    setError(null);
    try {
      await api.validateFinding(assessmentId, findingId, notes);
      setDecisionState('success');
      if (onValidationComplete) onValidationComplete();
    } catch (err: any) {
      setError(err?.message || 'Failed to validate finding');
      setDecisionState('idle');
    }
  };

  const handleReject = async (notes?: string) => {
    setDecisionState('validating');
    setError(null);
    try {
      await api.rejectFinding(assessmentId, findingId, notes);
      setDecisionState('success');
      if (onValidationComplete) onValidationComplete();
    } catch (err: any) {
      setError(err?.message || 'Failed to reject finding');
      setDecisionState('idle');
    }
  };

  const handleDecide = (verdict: 'confirm' | 'reject') => {
    const notes = prompt(`${verdict === 'confirm' ? 'Confirm' : 'Reject'} — add a note (optional):`);
    if (notes === null) return;
    if (verdict === 'confirm') {
      handleValidate(notes?.trim() || undefined);
    } else {
      handleReject(notes?.trim() || undefined);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-12 rounded-card border border-warm-mist animate-pulse" style={{ background: '#fdfbfa' }} />
        <div className="h-24 rounded-card border border-warm-mist animate-pulse" style={{ background: '#fdfbfa' }} />
        <div className="h-40 rounded-card border border-warm-mist animate-pulse" style={{ background: '#fdfbfa' }} />
        <div className="h-24 rounded-card border border-warm-mist animate-pulse" style={{ background: '#fdfbfa' }} />
      </div>
    );
  }

  if (error && !finding) {
    return (
      <div className="rounded-card border p-4 flex items-center justify-between"
           style={{ background: '#fdf3f3', borderColor: '#f5c6c6' }}>
        <p className="text-[14px]" style={{ color: '#c0392b' }}>{error}</p>
        <button
          onClick={loadFinding}
          className="px-3 py-1 text-[13px] rounded-btn border border-warm-mist text-graphite hover:text-ink transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="rounded-card border border-warm-mist shadow-subtle text-center py-12"
           style={{ background: '#fdfbfa' }}>
        <p className="text-[14px] text-graphite">Finding not found.</p>
      </div>
    );
  }

  const rawOutput = finding.evidence?.[0]?.raw_output;

  return (
    <div className="space-y-6 max-w-[900px] mx-auto">
      {/* ── Header ── */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-[22px] font-medium text-ink">
              Validate Finding
            </h1>
            <ValidationPill status={finding.validation_status} />
          </div>
          <p className="text-[13px] text-graphite mt-1 font-mono">{findingId}</p>
        </div>
        <button
          onClick={handleBack}
          className="px-3 py-1.5 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink hover:border-ash transition-colors flex-shrink-0"
        >
          ← Back to Queue
        </button>
      </div>

      {/* ── Error Banner ── */}
      {error && (
        <div
          className="rounded-card border p-3 text-[13px]"
          style={{ background: '#fdf3f3', borderColor: '#f5c6c6', color: '#c0392b' }}
        >
          {error}
        </div>
      )}

      {/* ── Finding Details ── */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle p-4"
        style={{ background: '#fdfbfa' }}
      >
        <div className="flex items-center gap-2 mb-2">
          <SeverityPill severity={finding.severity} />
          <h2 className="text-[18px] font-medium text-ink">{finding.title}</h2>
        </div>

        <p className="text-[14px] text-graphite mb-4">{finding.description}</p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-[13px] text-graphite">
          <InfoRow label="Target Domain" value={<span className="text-ink">{finding.target_domain}</span>} />
          <InfoRow label="Source Tool" value={<span className="text-ink font-mono">{finding.source_tool}</span>} />
          {finding.url && (
            <InfoRow
              label="URL"
              value={
                <a href={finding.url} target="_blank" rel="noopener noreferrer" className="text-deep-teal truncate block max-w-[200px]">
                  {finding.url}
                </a>
              }
            />
          )}
          <InfoRow label="First Seen" value={new Date(finding.first_seen).toLocaleString()} />
          <InfoRow label="Last Seen" value={new Date(finding.last_seen).toLocaleString()} />
          <InfoRow label="Occurrences" value={finding.occurrence_count} />
        </div>

        {/* Raw Output / Evidence */}
        {rawOutput && (
          <div className="mt-4">
            <h3 className="text-[13px] font-medium text-graphite uppercase tracking-wide mb-2">
              Raw Evidence Output
            </h3>
            <pre
              className="p-4 rounded-[8px] overflow-auto text-[12px] font-mono"
              style={{
                background: 'color-mix(in oklch, #000000 3%, #faf8f5)',
                border: '1px solid #e8e5e0',
              }}
            >
              {rawOutput}
            </pre>
          </div>
        )}
      </div>

      {/* ── Validation Decision ── */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle p-4"
        style={{ background: '#fdfbfa' }}
      >
        <h3 className="text-[16px] font-medium text-graphite mb-3">
          Validation Decision
        </h3>

        {decisionState === 'validating' && (
          <p className="text-center py-6 text-graphite text-[14px]">
            Processing your validation decision…
          </p>
        )}

        {decisionState === 'success' && (
          <div className="text-center py-6">
            <p className="text-[14px] font-medium text-ink mb-4">
              Finding has been validated.
            </p>
            <button
              onClick={handleBack}
              className="px-5 py-2 text-[14px] font-medium text-parchment rounded-input transition-opacity hover:opacity-90"
              style={{ background: '#27251e' }}
            >
              Back to Queue
            </button>
          </div>
        )}

        {decisionState === 'idle' && (
          <div className="space-y-3">
            <p className="text-[13px] text-graphite">
              Is this finding a genuine security issue? Your decision is recorded
              and cannot be undone — it affects the final report.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => handleDecide('confirm')}
                className="flex-1 py-3 text-[14px] font-medium text-white rounded-btn transition-opacity hover:opacity-90"
                style={{ background: '#016a71' }}
              >
                Confirm as Valid
              </button>
              <button
                onClick={() => handleDecide('reject')}
                className="flex-1 py-3 text-[14px] font-medium rounded-btn border border-warm-mist transition-colors hover:bg-warm-mist/40"
                style={{ color: '#c0392b' }}
              >
                Reject as Invalid
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
