/**
 * Assessment Dashboard Component
 *
 * Perplexity-style parchment design:
 * - Suggestion-card style assessment rows (soft-paper bg, 16px radius, 1px shadow)
 * - Status pills with deep-teal active state
 * - Ghost buttons for secondary actions, ink-fill for primary
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import type { AssessmentResponse } from '../lib/models';

// ─── Status pill ──────────────────────────────────────────────────────────────

const statusStyles: Record<string, { bg: string; text: string }> = {
  CREATED:              { bg: '#e8e5e0', text: '#72706b' },
  RUNNING:              { bg: 'color-mix(in oklch, #016a71 15%, #faf8f5)', text: '#016a71' },
  COMPLETED:            { bg: '#e3f2f0', text: '#016a71' },
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

// ─── Progress bar ─────────────────────────────────────────────────────────────

function ProgressBar({ pct }: { pct: number }) {
  return (
    <div className="w-full h-1.5 rounded-full overflow-hidden" style={{ background: '#e8e5e0' }}>
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${Math.min(100, Math.max(0, pct))}%`, background: '#016a71' }}
      />
    </div>
  );
}

// ─── Assessment Card ──────────────────────────────────────────────────────────

function AssessmentCard({
  assessment,
  onClick,
  onStart,
  onCancel,
}: {
  assessment: AssessmentResponse;
  onClick: () => void;
  onStart: () => void;
  onCancel: () => void;
}) {
  const pct = assessment.progress?.completion_percentage ?? 0;
  const isRunning = assessment.status === 'RUNNING' || assessment.status === 'RESUMING';

  return (
    <div
      onClick={onClick}
      className="cursor-pointer rounded-card border border-warm-mist shadow-subtle
                 transition-all duration-150 hover:shadow-md hover:border-ash"
      style={{ background: '#fdfbfa', padding: '16px' }}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          {/* Teal dot for running */}
          {isRunning && (
            <span className="flex-shrink-0 w-2 h-2 rounded-full animate-pulse" style={{ background: '#016a71' }} />
          )}
          <h3 className="text-[16px] font-medium text-ink truncate">
            {assessment.name || assessment.assessment_id}
          </h3>
          <StatusPill status={assessment.status} />
        </div>

        {/* Action buttons — stop propagation so card click doesn't fire */}
        <div className="flex items-center gap-2 flex-shrink-0" onClick={(e) => e.stopPropagation()}>
          {assessment.status === 'CREATED' && (
            <button
              onClick={onStart}
              className="px-3 py-1 text-[13px] font-medium rounded-btn border border-warm-mist
                         text-graphite hover:text-ink hover:border-ash transition-colors"
            >
              Start
            </button>
          )}
          {isRunning && (
            <button
              onClick={onCancel}
              className="px-3 py-1 text-[13px] font-medium rounded-btn border border-warm-mist
                         text-graphite hover:text-ink hover:border-ash transition-colors"
            >
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Meta row */}
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[13px] text-graphite">
        <span>
          <span className="text-ash">Created</span>{' '}
          {new Date(assessment.created_at).toLocaleDateString(undefined, {
            day: 'numeric', month: 'short', year: 'numeric',
          })}
        </span>
        <span>
          <span className="text-ash">Profile</span>{' '}
          <span className="capitalize">{assessment.profile}</span>
        </span>
        <span>
          <span className="text-ash">Findings</span>{' '}
          {assessment.findings_count ?? 0}
        </span>
        {(assessment.pending_validation_count ?? 0) > 0 && (
          <span style={{ color: '#c06000' }}>
            {assessment.pending_validation_count} pending validation
          </span>
        )}
      </div>

      {/* Progress */}
      {pct > 0 && (
        <div className="mt-4">
          <div className="flex justify-between text-[12px] text-graphite mb-1">
            <span>Progress</span>
            <span className="text-ink font-medium">{pct.toFixed(1)}%</span>
          </div>
          <ProgressBar pct={pct} />
        </div>
      )}
    </div>
  );
}

// ─── Empty state ──────────────────────────────────────────────────────────────

function EmptyState({ onNew }: { onNew: () => void }) {
  return (
    <div className="rounded-card border border-warm-mist shadow-subtle text-center py-14 px-8"
         style={{ background: '#fdfbfa' }}>
      {/* Icon */}
      <div className="mx-auto mb-4 w-12 h-12 rounded-card flex items-center justify-center"
           style={{ background: '#e8e5e0' }}>
        <svg className="w-6 h-6 text-graphite" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round"
            d="M9 12h6m-3-3v6m-7 4h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
      </div>
      <p className="text-[16px] text-ink font-medium mb-1">No assessments yet</p>
      <p className="text-[14px] text-graphite mb-6">
        Create your first assessment to start scanning targets.
      </p>
      <button
        onClick={onNew}
        className="px-5 py-2 text-[14px] font-medium text-parchment rounded-input
                   transition-colors hover:opacity-90"
        style={{ background: '#27251e' }}
      >
        Create Assessment
      </button>
    </div>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

interface AssessmentDashboardProps {
  onSelectAssessment?: (id: string) => void;
}

export function AssessmentDashboard({ onSelectAssessment }: AssessmentDashboardProps) {
  const navigate = useNavigate();
  const [assessments, setAssessments] = useState<AssessmentResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAssessments = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.listAssessments();
      setAssessments(data);
    } catch (err) {
      console.error('Failed to fetch assessments:', err);
      setError('Failed to load assessments. Is the backend running?');
      setAssessments([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAssessments();
    const interval = setInterval(fetchAssessments, 30000);
    return () => clearInterval(interval);
  }, [fetchAssessments]);

  const handleStartAssessment = async (id: string) => {
    try {
      await api.startAssessment(id);
      fetchAssessments();
    } catch (err) {
      console.error('Failed to start assessment:', err);
    }
  };

  const handleCancelAssessment = async (id: string) => {
    try {
      await api.cancelAssessment(id);
      fetchAssessments();
    } catch (err) {
      console.error('Failed to cancel assessment:', err);
    }
  };

  return (
    <div className="space-y-8">
      {/* Page header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-[22px] font-medium text-ink">Assessments</h1>
          <p className="text-[14px] text-graphite mt-0.5">
            Monitor and manage your security scans.
          </p>
        </div>
        <button
          onClick={() => navigate('/operator/assessments/new')}
          className="px-4 py-2 text-[14px] font-medium text-parchment rounded-input
                     transition-opacity hover:opacity-90 flex-shrink-0"
          style={{ background: '#27251e' }}
        >
          + New Assessment
        </button>
      </div>

      {/* Loading skeleton */}
      {loading && (
        <div
          className="space-y-3"
          role="status"
          aria-label="Loading assessments"
        >
          {[1, 2, 3].map((i) => (
            <div key={i} aria-hidden="true" className="h-24 rounded-card border border-warm-mist animate-pulse"
                 style={{ background: '#fdfbfa' }} />
          ))}
        </div>
      )}

      {/* Error */}
      {!loading && error && (
        <div role="alert" className="rounded-card border border-warm-mist p-4 flex items-center justify-between"
             style={{ background: '#fdf3f3' }}>
          <p className="text-[14px]" style={{ color: '#c0392b' }}>{error}</p>
          <button
            onClick={fetchAssessments}
            className="px-3 py-1 text-[13px] rounded-btn border border-warm-mist text-graphite hover:text-ink transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && assessments.length === 0 && (
        <EmptyState onNew={() => navigate('/operator/assessments/new')} />
      )}

      {/* Assessment cards */}
      {!loading && !error && assessments.length > 0 && (
        <div className="grid gap-3">
          {assessments.map((a) => (
            <AssessmentCard
              key={a.assessment_id}
              assessment={a}
              onClick={() => onSelectAssessment?.(a.assessment_id)}
              onStart={() => handleStartAssessment(a.assessment_id)}
              onCancel={() => handleCancelAssessment(a.assessment_id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}