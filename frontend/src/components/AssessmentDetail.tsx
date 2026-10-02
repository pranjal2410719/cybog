/**
 * Assessment Detail View Component
 * 
 * Shows detailed information about a specific assessment including
 * findings, status, and actions.
 */

import { useState, useEffect, useCallback } from 'react';
import { api, WebSocketManager } from '../api';
import { LiveStatusPanel, useLiveStatus } from './LiveStatusPanel';
import type {
  AssessmentResponse,
  AssessmentStatusResponse,
  FindingResponse,
} from '../lib/models';

// Assessment status badge colors
const statusColors: Record<string, string> = {
  CREATED: 'bg-gray-100 text-gray-800',
  RUNNING: 'bg-blue-100 text-blue-800',
  COMPLETED: 'bg-green-100 text-green-800',
  FAILED: 'bg-red-100 text-red-800',
  CANCELLED: 'bg-yellow-100 text-yellow-800',
  RESUMING: 'bg-purple-100 text-purple-800',
  AWAITING_VALIDATION: 'bg-orange-100 text-orange-800',
};

interface AssessmentDetailProps {
  assessmentId: string;
  onBack?: () => void;
}

type ExportPhase = 'idle' | 'starting' | 'building' | 'done' | 'error';

interface ExportState {
  phase: ExportPhase;
  exportId?: string;
  message?: string;
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
  const live = useLiveStatus(assessmentId);

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
      console.error('Failed to load assessment details:', err);
      setError(err.response?.data?.detail || 'Failed to load assessment details');
    } finally {
      setLoading(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    fetchAssessment();

    // Set up WebSocket for real-time updates
    const wsManager = new WebSocketManager(assessmentId);
    wsManager.onProgressUpdate((data) => {
      if (status) {
        setStatus((prev) => prev ? { ...prev, progress: data.progress } : prev);
      }
    });
    wsManager.onFindingUpdate((data: any) => {
      if (data.action === 'created') {
        setFindings((prev) => [...prev, data.finding]);
      } else if (data.action === 'updated' || data.action === 'validated' || data.action === 'rejected') {
        setFindings((prev) =>
          prev.map((f) =>
            f.finding_id === data.finding.finding_id ? data.finding : f
          )
        );
      }
    });
    wsManager.connect();

    // Auto-refresh every 30 seconds for non-WebSocket data
    const interval = setInterval(fetchAssessment, 30000);

    // Cleanup on unmount
    return () => {
      wsManager.disconnect();
      clearInterval(interval);
    };
  }, [assessmentId, fetchAssessment]);

  const handleStartAssessment = async () => {
    try {
      await api.startAssessment(assessmentId);
      fetchAssessment();
    } catch (err) {
      console.error('Failed to start assessment:', err);
      setError('Failed to start assessment');
    }
  };

  const handleResumeAssessment = async () => {
    try {
      await api.resumeAssessment(assessmentId);
      fetchAssessment();
    } catch (err) {
      console.error('Failed to resume assessment:', err);
      setError('Failed to resume assessment');
    }
  };

  const handleBack = () => {
    if (onBack) onBack();
    else window.location.href = '/';
  };

  const handleCancelAssessment = async () => {
    try {
      await api.cancelAssessment(assessmentId);
      if (onBack) onBack();
      else window.location.href = '/';
    } catch (err) {
      console.error('Failed to cancel assessment:', err);
      setError('Failed to cancel assessment');
    }
  };

  const handleValidateFinding = async (findingId: string, notes?: string) => {
    try {
      await api.validateFinding(assessmentId, findingId, notes);
      fetchAssessment();
    } catch (err) {
      console.error('Failed to validate finding:', err);
      setError('Failed to validate finding');
    }
  };

  const handleRejectFinding = async (findingId: string, notes?: string) => {
    try {
      await api.rejectFinding(assessmentId, findingId, notes);
      fetchAssessment();
    } catch (err) {
      console.error('Failed to reject finding:', err);
      setError('Failed to reject finding');
    }
  };

  const handleExportAssessment = async () => {
    setExportState({ phase: 'starting' });
    setError(null);
    try {
      const exportData = await api.createExport(assessmentId);
      setExportState({ phase: 'building', exportId: exportData.export_id });

      // Poll the backend until the archive is really built. The export runs
      // server-side, so this reflects actual state rather than assuming success.
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
        setExportState({
          phase: 'error',
          message: status.error || 'Export failed on the server',
        });
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
    } catch (err) {
      console.error('Failed to create export:', err);
      setExportState({ phase: 'error', message: 'Failed to create export' });
    }
  };

  if (loading && !assessment) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-cyborg-muted">Loading assessment details...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-4 py-3 bg-red-600/20 border border-red-600/50 rounded-lg text-red-400 mb-6">
        {error}
        <button
          onClick={fetchAssessment}
          className="ml-4 underline"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap">
        <div>
          <h1 className="text-3xl font-bold text-white">
            {assessment?.name || 'Assessment Details'}
          </h1>
          <p className="text-cyborg-muted mt-1">
            ID: {assessment?.assessment_id}
          </p>
        </div>
        <div className="flex items-center space-x-3">
          {assessment && (
            <>
              <span
                className={`px-2 py-1 text-xs font-medium rounded-full ${
                  statusColors[assessment.status] || 'bg-gray-100 text-gray-800'
                }`}
              >
                {assessment.status}
              </span>
              <button
                onClick={handleBack}
                className="px-3 py-1 text-sm bg-cyborg-card border border-cyborg-border text-cyborg-muted 
                           rounded-lg hover:bg-cyborg-card/50 transition-colors"
              >
                Back
              </button>
            </>
          )}
        </div>
      </div>

      {/* Live Execution Status */}
      <LiveStatusPanel status={live} onRefresh={fetchAssessment} />

      {/* Assessment Info */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 bg-cyborg-card rounded-lg border border-cyborg-border p-6">
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">Assessment Info</h2>
          <div className="space-y-2 text-sm">
            <div className="flex">
              <span className="w-24 text-cyborg-muted">Created:</span>
              <span className="text-white">
                {assessment ? new Date(assessment.created_at).toLocaleString() : '-'}
              </span>
            </div>
            <div className="flex">
              <span className="w-24 text-cyborg-muted">Profile:</span>
              <span className="text-white">{assessment?.profile}</span>
            </div>
            <div className="flex">
              <span className="w-24 text-cyborg-muted">Target:</span>
              <span className="text-white">
                {assessment ? assessment.artifact_root.split('/').pop() || 'Unknown' : '-'}
              </span>
            </div>
            <div className="flex">
              <span className="w-24 text-cyborg-muted">Status Updated:</span>
              <span className="text-white">
                {status ? new Date(status.updated_at).toLocaleString() : '-'}
              </span>
            </div>
          </div>
        </div>

        <div>
          <h2 className="text-lg font-semibold text-white mb-3">Progress</h2>
          <div className="space-y-4">
            <div className="mb-2">
              <label className="block text-sm font-medium text-cyborg-muted mb-1">
                Overall Completion
              </label>
              <div className="w-full h-2 bg-cyborg-dark rounded-full overflow-hidden">
                <div
                  className="h-full bg-cyborg-accent rounded-full transition-all"
                  style={{
                    width: `${status?.progress?.completion_percentage || 0}%`,
                  }}
                />
              </div>
              <div className="flex items-center justify-between text-sm mt-1">
                <span className="text-cyborg-muted">
                  {status?.progress?.completion_percentage || 0}%
                </span>
                <span className="text-white">
                  {status?.progress?.completion_percentage || 0}%
                </span>
              </div>
            </div>

            {status?.progress?.targets?.length && (
              <div className="mt-4">
                <p className="text-sm font-medium text-cyborg-muted mb-2">
                  Target Progress
                </p>
                <div className="space-y-2">
                  {status.progress.targets.map((target: any) => (
                    <div key={target.target_id} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="text-cyborg-muted">{target.domain}</span>
                        <span className="text-white">{target.status}</span>
                      </div>
                      <div className="w-full h-1.5 bg-cyborg-dark rounded-full overflow-hidden">
                        <div
                          className="h-full bg-cyborg-accent rounded-full transition-all"
                          style={{
                            width: `${target.completion_percentage || 0}%`,
                          }}
                        />
                      </div>
                      <div className="text-xs text-cyborg-muted">
                        {target.completion_percentage?.toFixed(1)}%
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        <div>
          <h2 className="text-lg font-semibold text-white mb-3">Statistics</h2>
          <div className="space-y-2 text-sm">
            <div className="flex">
              <span className="w-24 text-cyborg-muted">Total Findings:</span>
              <span className="text-white">{findings.length}</span>
            </div>
            <div className="flex">
              <span className="w-24 text-cyborg-muted">Pending Validation:</span>
              <span className="text-white">
                {status?.pending_validation_count || 0}
              </span>
            </div>
            <div className="flex">
              <span className="w-24 text-cyborg-muted">Severity Breakdown:</span>
              <span className="text-white">
                {/* Calculate severity breakdown from findings */}
                {getSeverityBreakdown(findings)}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Actions */}
      {assessment && (
        <div className="flex items-center justify-between space-x-3">
          <div className="flex-1">
            <button
              onClick={handleStartAssessment}
              disabled={assessment.status !== 'CREATED'}
              className="w-full px-4 py-2 bg-blue-600 text-white font-medium rounded-lg 
                         hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed 
                         transition-colors"
            >
              Start Assessment
            </button>
          </div>
          <div className="flex-1">
            <button
              onClick={handleResumeAssessment}
              disabled={!['FAILED', 'AWAITING_VALIDATION'].includes(assessment.status)}
              className="w-full px-4 py-2 bg-purple-600 text-white font-medium rounded-lg 
                         hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed 
                         transition-colors"
            >
              Resume
            </button>
          </div>
          <div className="flex-1">
            <button
              onClick={handleCancelAssessment}
              disabled={!['RUNNING', 'RESUMING'].includes(assessment.status)}
              className="w-full px-4 py-2 bg-red-600 text-white font-medium rounded-lg 
                         hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed 
                         transition-colors"
            >
              Cancel Assessment
            </button>
          </div>
          <div className="flex-1">
            <button
              onClick={handleExportAssessment}
              disabled={exportState.phase === 'starting' || exportState.phase === 'building'}
              className="w-full px-4 py-2 bg-green-600 text-white font-medium rounded-lg 
                         hover:bg-green-700 transition-colors
                         disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {exportState.phase === 'starting' && 'Starting export...'}
              {exportState.phase === 'building' && 'Building archive...'}
              {exportState.phase === 'done' && 'Downloaded — export again'}
              {exportState.phase === 'error' && 'Retry export'}
              {(exportState.phase === 'idle') && 'Export Results'}
            </button>
            {exportState.phase === 'error' && exportState.message && (
              <p className="mt-2 text-xs text-red-400">{exportState.message}</p>
            )}
          </div>
        </div>
      )}

      {/* Findings Section */}
      <div>
        <h2 className="text-2xl font-bold text-white mb-4">
          Findings ({findings.length})
          {status?.pending_validation_count && status.pending_validation_count > 0 && (
            <span className="ml-2 px-2 py-0.5 bg-orange-600/20 text-orange-400 rounded text-xs">
              {status.pending_validation_count} pending validation
            </span>
          )}
        </h2>

        {findings.length === 0 ? (
          <div className="text-center py-12 bg-cyborg-card rounded-lg border border-cyborg-border">
            <div className="text-cyborg-muted">No findings discovered yet</div>
            {assessment?.status === 'RUNNING' || assessment?.status === 'RESUMING' ? (
              <p className="mt-2 text-cyborg-muted text-sm">
                Scan is still in progress...
              </p>
            ) : (
              <p className="mt-2 text-cyborg-muted text-sm">
                The assessment has completed but no findings were discovered.
              </p>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-between mb-3">
              <button
                onClick={async () => {
                  try {
                    const data = await api.getPendingValidation(assessmentId);
                    setPendingInfo(data.pending_count);
                  } catch (err) {
                    console.error('Failed to load pending validation:', err);
                    setPendingInfo(null);
                    setPendingError('Failed to load pending validation');
                  }
                }}
                className="px-3 py-1 text-sm bg-yellow-600 text-white rounded hover:bg-yellow-700 transition-colors"
              >
                View Pending Validation
              </button>
            </div>
            {pendingError && (
              <p className="mb-3 text-sm text-red-400">{pendingError}</p>
            )}
            {pendingInfo !== null && !pendingError && (
              <div className="mb-3 px-3 py-2 bg-yellow-600/10 border border-yellow-600/40 rounded text-sm text-yellow-200">
                {pendingInfo === 0
                  ? 'No findings are awaiting a validation decision.'
                  : `There are ${pendingInfo} finding${pendingInfo === 1 ? '' : 's'} pending validation. ` +
                    'Use the Confirm / Reject action on each finding below.'}
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-cyborg-dark">
                    <th className="p-3 text-left text-xs font-medium text-cyborg-muted">
                      Severity
                    </th>
                    <th className="p-3 text-left text-xs font-medium text-cyborg-muted">
                      Title
                    </th>
                    <th className="p-3 text-left text-xs font-medium text-cyborg-muted">
                      Target
                    </th>
                    <th className="p-3 text-left text-xs font-medium text-cyborg-muted">
                      Source
                    </th>
                    <th className="p-3 text-left text-xs font-medium text-cyborg-muted">
                      Status
                    </th>
                    <th className="p-3 text-left text-xs font-medium text-cyborg-muted">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyborg-border/50">
                  {findings.map((finding) => (
                    <tr key={finding.finding_id} className="hover:bg-cyborg-card/50 transition-colors">
                      <td className="p-3 text-sm font-medium">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs ${
                            finding.severity === 'critical'
                              ? 'bg-red-600/20 text-red-400'
                              : finding.severity === 'high'
                              ? 'bg-orange-600/20 text-orange-400'
                              : finding.severity === 'medium'
                              ? 'bg-yellow-600/20 text-yellow-400'
                              : finding.severity === 'low'
                              ? 'bg-green-600/20 text-green-400'
                              : 'bg-blue-600/20 text-blue-400'
                          }`}
                        >
                          {finding.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="p-3 text-sm max-w-[200px] truncate">{finding.title}</td>
                      <td className="p-3 text-sm">{finding.target_domain}</td>
                      <td className="p-3 text-sm">{finding.source_tool}</td>
                      <td className="p-3 text-sm">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 text-xs rounded-full ${
                            finding.validation_status === 'DISCOVERED'
                              ? 'bg-gray-600/20 text-gray-400'
                              : finding.validation_status === 'NEEDS_VALIDATION'
                              ? 'bg-yellow-600/20 text-yellow-400'
                              : finding.validation_status === 'VALIDATING'
                              ? 'bg-blue-600/20 text-blue-400'
                              : finding.validation_status === 'VALIDATED'
                              ? 'bg-green-600/20 text-green-400'
                              : finding.validation_status === 'FALSE_POSITIVE'
                              ? 'bg-red-600/20 text-red-400'
                              : 'bg-purple-600/20 text-purple-400'
                          }`}
                        >
                          {finding.validation_status.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="p-3 space-x-2">
                        {finding.validation_status === 'VALIDATING' && (
                          <>
                            <button
                              onClick={() => handleValidateFinding(finding.finding_id)}
                              className="text-xs bg-green-600 text-white px-2 py-0.5 rounded hover:bg-green-700 transition-colors"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => handleRejectFinding(finding.finding_id)}
                              className="text-xs ml-1 bg-red-600 text-white px-2 py-0.5 rounded hover:bg-red-700 transition-colors"
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
                            className="text-xs bg-blue-600 text-white px-2 py-0.5 rounded hover:bg-blue-700 transition-colors"
                          >
                            Validate
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// Helper function to get severity breakdown
function getSeverityBreakdown(findings: any[]): string {
  if (findings.length === 0) return 'None';

  const counts: Record<string, number> = {};
  findings.forEach((f) => {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  });

  return Object.entries(counts)
    .map(([severity, count]) => `${severity}: ${count}`)
    .join(', ');
}