/**
 * Assessment Reports Page — Operator Section
 *
 * Displays generated reports and scan artifacts for an assessment,
 * and provides export functionality (ZIP/JSON/CSV).
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../api';
import type {
  ExportRequest,
  ExportResponse,
} from '../../lib/models';

interface AssessmentReportsPageProps {
  assessmentId: string;
  onBack?: () => void;
}

type ExportPhase = 'idle' | 'starting' | 'building' | 'done' | 'error';

interface ExportState {
  phase: ExportPhase;
  exportId?: string;
  message?: string;
}

interface ReportFile {
  filename: string;
  type: string;
  path: string;
  size_bytes: number;
  created_at: string;
}

interface ArtifactFile {
  artifact_id: string;
  target_id?: string;
  stage?: string;
  artifact_type: string;
  path: string;
  filename: string;
  size_bytes: number;
  checksum?: string;
  created_at: string;
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 text-[14px]">
      <span className="text-graphite w-32 flex-shrink-0">{label}</span>
      <span className="text-ink">{value}</span>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function AssessmentReportsPage({ assessmentId, onBack }: AssessmentReportsPageProps) {
  const navigate = useNavigate();
  const [reports, setReports] = useState<ReportFile[]>([]);
  const [artifacts, setArtifacts] = useState<ArtifactFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportState, setExportState] = useState<ExportState>({ phase: 'idle' });

  const handleBack = () => {
    if (onBack) onBack();
    else navigate(-1);
  };

  const loadReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [reportsData, artifactsData] = await Promise.all([
        api.getReports(assessmentId),
        api.getArtifacts(assessmentId),
      ]);
      setReports(reportsData.reports);
      setArtifacts(artifactsData.artifacts);
    } catch (err: any) {
      setError(err?.message || 'Failed to load reports and artifacts');
    } finally {
      setLoading(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const handleExport = async (format: 'zip' | 'jsonl' | 'csv') => {
    setExportState({ phase: 'starting' });
    setError(null);
    try {
      const data: ExportRequest = {
        format,
        include_raw: true,
        include_evidence: true,
      };
      const exportData: ExportResponse = await api.createExport(assessmentId, data);
      setExportState({ phase: 'building', exportId: exportData.export_id });

      const deadline = Date.now() + 5 * 60 * 1000;
      let status = await api.getExportStatus(assessmentId, exportData.export_id);
      while (status.status !== 'completed' && status.status !== 'failed') {
        if (Date.now() > deadline) {
          setExportState({ phase: 'error', message: 'Export timed out after 5 minutes' });
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
        status = await api.getExportStatus(assessmentId, exportData.export_id);
      }

      if (status.status === 'failed') {
        setExportState({ phase: 'error', message: status.error || 'Export failed on the server' });
        return;
      }

      const blob = await api.downloadExport(assessmentId, exportData.export_id);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `assessment-${assessmentId}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      setExportState({ phase: 'done' });
    } catch (err: any) {
      setExportState({ phase: 'error', message: err?.message || 'Export failed' });
    }
  };

  if (loading && !reports.length && !artifacts.length) {
    return (
      <div className="space-y-4">
        <div className="h-28 rounded-card border border-warm-mist animate-pulse" style={{ background: '#fdfbfa' }} />
        <div className="h-28 rounded-card border border-warm-mist animate-pulse" style={{ background: '#fdfbfa' }} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Error banner */}
      {error && (
        <div
          className="rounded-card border p-3 text-[13px]"
          style={{ background: '#fdf3f3', borderColor: '#f5c6c6', color: '#c0392b' }}
        >
          {error}
          <button
            onClick={loadReports}
            className="ml-3 underline text-[13px]"
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-[22px] font-medium text-ink">Assessment Reports</h1>
          <p className="text-[14px] text-graphite mt-1">
            View, download, and manage assessment artifacts and reports.
          </p>
        </div>
        <button
          onClick={handleBack}
          className="px-3 py-1.5 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink hover:border-ash transition-colors flex-shrink-0"
        >
          ← Back
        </button>
      </div>

      {/* ── Export Section ── */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle p-4"
        style={{ background: '#fdfbfa' }}
      >
        <h3 className="text-[16px] font-medium text-graphite mb-3">Export Assessment</h3>
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => handleExport('zip')}
              disabled={exportState.phase === 'starting' || exportState.phase === 'building'}
              className="px-4 py-2 text-[14px] font-medium text-parchment rounded-input transition-opacity hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: '#27251e' }}
            >
              {exportState.phase === 'starting' && 'Starting export…'}
              {exportState.phase === 'building' && 'Building archive…'}
              {exportState.phase === 'done' && 'Downloaded ✓'}
              {exportState.phase === 'error' && 'Retry Export'}
              {exportState.phase === 'idle' && 'Export ZIP'}
            </button>
            <button
              onClick={() => handleExport('jsonl')}
              disabled={exportState.phase === 'starting' || exportState.phase === 'building'}
              className="px-4 py-2 text-[14px] font-medium rounded-input border border-warm-mist text-graphite hover:text-ink hover:border-ash transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Export JSONL
            </button>
            <button
              onClick={() => handleExport('csv')}
              disabled={exportState.phase === 'starting' || exportState.phase === 'building'}
              className="px-4 py-2 text-[14px] font-medium rounded-input border border-warm-mist text-graphite hover:text-ink hover:border-ash transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Export CSV
            </button>
          </div>
          {exportState.phase === 'error' && exportState.message && (
            <p className="text-[12px]" style={{ color: '#c0392b' }}>
              {exportState.message}
            </p>
          )}
        </div>
      </div>

      {/* ── Generated Reports ── */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle"
        style={{ background: '#fdfbfa' }}
      >
        <div className="flex items-center justify-between pb-4 border-b border-warm-mist">
          <h3 className="text-[16px] font-medium text-ink">Generated Reports</h3>
          <span
            className="px-2 py-0.5 rounded-chip text-[11px] font-medium"
            style={{ background: '#e8e5e0', color: '#72706b' }}
          >
            {reports.length}
          </span>
        </div>

        {reports.length === 0 ? (
          <div className="text-center py-10">
            <p className="text-[14px] text-graphite">
              No reports generated yet. Reports appear here once an assessment completes.
            </p>
          </div>
        ) : (
          <div className="space-y-3 p-4 pt-0">
            {reports.map((report) => (
              <div
                key={report.filename}
                className="flex items-center justify-between p-3 rounded-[8px]"
                style={{ background: '#faf8f5', border: '1px solid #f0eee9' }}
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-[13px] text-ink">{report.filename}</span>
                  <span className="text-[12px] text-graphite">{report.type}</span>
                </div>
                <div className="flex items-center gap-3 text-[12px] text-graphite">
                  <span>{formatBytes(report.size_bytes)}</span>
                  <span>{new Date(report.created_at).toLocaleDateString()}</span>
                  <a
                    href={report.path}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-2 py-0.5 text-[11px] font-medium rounded-chip border border-warm-mist text-graphite hover:text-ink hover:bg-warm-mist/40 transition-colors"
                  >
                    Download
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Scan Artifacts ── */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle"
        style={{ background: '#fdfbfa' }}
      >
        <div className="flex items-center justify-between pb-4 border-b border-warm-mist">
          <h3 className="text-[16px] font-medium text-ink">Scan Artifacts</h3>
          <span
            className="px-2 py-0.5 rounded-chip text-[11px] font-medium"
            style={{ background: '#e8e5e0', color: '#72706b' }}
          >
            {artifacts.length}
          </span>
        </div>

        {artifacts.length === 0 ? (
          <div className="text-center py-10">
            <p className="text-[14px] text-graphite">
              No artifacts collected yet.
            </p>
          </div>
        ) : (
          <div className="space-y-3 p-4 pt-0">
            {artifacts.map((artifact) => (
              <div
                key={artifact.artifact_id}
                className="rounded-[8px] p-3"
                style={{ background: '#faf8f5', border: '1px solid #f0eee9' }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[13px] text-ink">{artifact.filename}</span>
                    <span
                      className="px-2 py-0.5 rounded-chip text-[11px] font-medium border"
                      style={{ background: '#fff0e0', color: '#c06000' }}
                    >
                      {artifact.artifact_type}
                    </span>
                  </div>
                  <span className="text-[12px] text-graphite">{formatBytes(artifact.size_bytes)}</span>
                </div>
                <div className="mt-2 text-[13px] text-graphite">
                  <InfoRow label="Created" value={artifact.created_at} />
                  {artifact.target_id && <InfoRow label="Target ID" value={<span className="font-mono text-[12px]">{artifact.target_id}</span>} />}
                  {artifact.stage && <InfoRow label="Stage" value={artifact.stage} />}
                  {artifact.checksum && <InfoRow label="SHA-256" value={<span className="font-mono text-[11px] break-all">{artifact.checksum}</span>} />}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
