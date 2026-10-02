/**
 * Assessment Dashboard Component
 *
 * Shows a list of assessments with their status, progress, and actions.
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import type { AssessmentResponse } from '../lib/models';

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
      setError('Failed to load assessments');
      setAssessments([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAssessments();
    // Refresh every 30 seconds
    const interval = setInterval(fetchAssessments, 30000);
    return () => clearInterval(interval);
  }, [fetchAssessments]);

  const handleStartAssessment = async (assessmentId: string) => {
    try {
      await api.startAssessment(assessmentId);
      fetchAssessments(); // Refresh the list
    } catch (err) {
      console.error('Failed to start assessment:', err);
      setError('Failed to start assessment');
    }
  };

  const handleCancelAssessment = async (assessmentId: string) => {
    try {
      await api.cancelAssessment(assessmentId);
      fetchAssessments(); // Refresh the list
    } catch (err) {
      console.error('Failed to cancel assessment:', err);
      setError('Failed to cancel assessment');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-cyborg-muted">Loading assessments...</div>
      </div>
    );
  }

  // Network/HTTP failure: never fall through to the empty state.
  if (error) {
    return (
      <div className="px-4 py-3 bg-red-600/20 border border-red-600/50 rounded-lg text-red-400">
        {error}
        <button
          onClick={() => fetchAssessments()}
          className="ml-4 underline"
        >
          Retry
        </button>
      </div>
    );
  }

  // Only a successful request with zero results reaches this state.
  if (assessments.length === 0) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">Assessments</h1>
          <button
            onClick={() => navigate('/assessments/new')}
            className="px-4 py-2 bg-cyborg-accent text-cyborg-dark font-medium rounded-lg hover:bg-cyborg-accent/90 transition-colors"
          >
            New Assessment
          </button>
        </div>
        <div className="text-center py-12 bg-cyborg-card rounded-lg border border-cyborg-border">
          <div className="text-cyborg-muted mb-4">No assessments yet</div>
          <button
            onClick={() => navigate('/assessments/new')}
            className="px-4 py-2 bg-cyborg-accent text-cyborg-dark font-medium rounded-lg hover:bg-cyborg-accent/90 transition-colors"
          >
            Create Your First Assessment
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Assessments</h1>
        <button
          onClick={() => navigate('/assessments/new')}
          className="px-4 py-2 bg-cyborg-accent text-cyborg-dark font-medium rounded-lg hover:bg-cyborg-accent/90 transition-colors"
        >
          New Assessment
        </button>
      </div>

      <div className="grid gap-4">
        {assessments.map((assessment) => (
          <div
            key={assessment.assessment_id}
            className="bg-cyborg-card rounded-lg border border-cyborg-border p-4 hover:border-cyborg-accent/50 transition-colors cursor-pointer"
            onClick={() => onSelectAssessment?.(assessment.assessment_id)}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-3">
                <h3 className="text-lg font-medium text-white">
                  {assessment.name || assessment.assessment_id}
                </h3>
                <span
                  className={`px-2 py-1 text-xs font-medium rounded-full ${
                    statusColors[assessment.status] || 'bg-gray-100 text-gray-800'
                  }`}
                >
                  {assessment.status}
                </span>
              </div>
              <div className="flex space-x-2">
                {assessment.status === 'CREATED' && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleStartAssessment(assessment.assessment_id);
                    }}
                    className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                  >
                    Start
                  </button>
                )}
                {(assessment.status === 'RUNNING' || assessment.status === 'RESUMING') && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleCancelAssessment(assessment.assessment_id);
                    }}
                    className="px-3 py-1 text-sm bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
                  >
                    Cancel
                  </button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-cyborg-muted">Created:</span>{' '}
                <span className="text-white">
                  {new Date(assessment.created_at).toLocaleDateString()}
                </span>
              </div>
              <div>
                <span className="text-cyborg-muted">Profile:</span>{' '}
                <span className="text-white">{assessment.profile}</span>
              </div>
              <div>
                <span className="text-cyborg-muted">Findings:</span>{' '}
                <span className="text-white">{assessment.findings_count}</span>
              </div>
              <div>
                <span className="text-cyborg-muted">Pending Validation:</span>{' '}
                <span className="text-white">{assessment.pending_validation_count}</span>
              </div>
            </div>

            {assessment.progress?.completion_percentage !== undefined && (
              <div className="mt-3">
                <div className="flex items-center justify-between text-sm mb-1">
                  <span className="text-cyborg-muted">Progress</span>
                  <span className="text-white">
                    {assessment.progress.completion_percentage.toFixed(1)}%
                  </span>
                </div>
                <div className="h-2 bg-cyborg-dark rounded-full overflow-hidden">
                  <div
                    className="h-full bg-cyborg-accent rounded-full transition-all"
                    style={{
                      width: `${assessment.progress.completion_percentage}%`,
                    }}
                  />
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}