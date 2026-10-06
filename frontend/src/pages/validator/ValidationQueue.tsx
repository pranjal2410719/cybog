import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api, AssessmentResponse } from '../../api';
import { getPendingValidation, validateFinding, rejectFinding } from '../../api/validation';
import type { FindingResponse } from '../../lib/models';

export function ValidationQueuePage() {
  const { id: paramAssessmentId } = useParams<{ id?: string }>();
  const navigate = useNavigate();

  const [assessments, setAssessments] = useState<AssessmentResponse[]>([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(
    paramAssessmentId || null
  );
  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [loadingAssessments, setLoadingAssessments] = useState(true);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Sync route param with state
  useEffect(() => {
    if (paramAssessmentId) {
      setSelectedAssessmentId(paramAssessmentId);
    }
  }, [paramAssessmentId]);

  // Load all assessments for the selector
  useEffect(() => {
    let mounted = true;
    setLoadingAssessments(true);
    api.listAssessments()
      .then((data) => {
        if (mounted) {
          setAssessments(data);
          // If no specific assessment selected but assessments exist, select the first one if on /validator/queue/:id
          if (!paramAssessmentId && data.length > 0) {
            // Keep on list overview or select first
          }
        }
      })
      .catch((err) => {
        if (mounted) {
          console.error('Failed to load assessments', err);
        }
      })
      .finally(() => {
        if (mounted) setLoadingAssessments(false);
      });
    return () => {
      mounted = false;
    };
  }, [paramAssessmentId]);

  // Load pending findings when selectedAssessmentId changes
  useEffect(() => {
    if (!selectedAssessmentId) {
      setFindings([]);
      return;
    }

    let mounted = true;
    setLoadingFindings(true);
    setError(null);

    getPendingValidation(selectedAssessmentId)
      .then((res) => {
        if (mounted) {
          setFindings(res.findings || []);
        }
      })
      .catch((err) => {
        if (mounted) {
          setError(String(err?.message || 'Failed to load pending findings'));
        }
      })
      .finally(() => {
        if (mounted) setLoadingFindings(false);
      });

    return () => {
      mounted = false;
    };
  }, [selectedAssessmentId]);

  const handleSelectAssessment = (assessmentId: string) => {
    setSelectedAssessmentId(assessmentId);
    navigate(`/validator/queue/${assessmentId}`);
  };

  const handleValidate = async (findingId: string, verdict: 'confirm' | 'reject') => {
    if (!selectedAssessmentId) return;
    try {
      if (verdict === 'confirm') {
        await validateFinding(selectedAssessmentId, findingId, 'Confirmed by validator');
      } else {
        await rejectFinding(selectedAssessmentId, findingId, 'Rejected by validator');
      }
      setFindings((prev) => prev.filter((f) => f.finding_id !== findingId));
    } catch (err: any) {
      alert(`Failed to ${verdict} finding: ${String(err?.message || 'unknown error')}`);
    }
  };

  return (
    <div className="space-y-6 max-w-[900px] mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-[22px] font-medium text-ink">Validation Queue</h1>
        <p className="text-[14px] text-graphite mt-1">
          Review, confirm, and reject security findings discovered during scans.
        </p>
      </div>

      {/* Assessment Selector */}
      {assessments.length > 0 && (
        <div className="bg-white p-4 rounded-card border border-warm-mist shadow-subtle flex flex-wrap items-center justify-between gap-3">
          <label className="text-[13px] font-medium text-ink">Select Assessment:</label>
          <select
            value={selectedAssessmentId || ''}
            onChange={(e) => {
              if (e.target.value) {
                handleSelectAssessment(e.target.value);
              } else {
                setSelectedAssessmentId(null);
                navigate('/validator/queue');
              }
            }}
            className="flex-1 max-w-md px-3 py-2 border border-warm-mist rounded-btn text-[14px] bg-[#faf8f5] text-ink focus:outline-none focus:border-deep-teal"
          >
            <option value="">— Choose an assessment —</option>
            {assessments.map((a) => (
              <option key={a.assessment_id} value={a.assessment_id}>
                {a.name} ({a.status}) — {a.assessment_id}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* If no assessment selected */}
      {!selectedAssessmentId && !loadingAssessments && (
        <div className="bg-white rounded-card border border-warm-mist shadow-subtle p-8 text-center">
          <p className="text-[15px] font-medium text-ink mb-1">
            {assessments.length === 0 ? 'No assessments found' : 'Select an assessment above to review findings'}
          </p>
          <p className="text-[13px] text-graphite">
            {assessments.length === 0
              ? 'When operators start assessments, findings awaiting validation will appear here.'
              : 'Choose any active or completed assessment from the dropdown to validate its findings.'}
          </p>
        </div>
      )}

      {/* Selected Assessment Findings */}
      {selectedAssessmentId && (
        <div className="bg-white rounded-card border border-warm-mist shadow-subtle p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-warm-mist pb-4">
            <div>
              <h2 className="text-[16px] font-semibold text-ink">
                Pending Findings ({findings.length})
              </h2>
              <p className="text-[12px] font-mono text-graphite mt-0.5">
                Assessment: {selectedAssessmentId}
              </p>
            </div>
            {selectedAssessmentId && (
              <button
                onClick={() => {
                  setSelectedAssessmentId(null);
                  navigate('/validator/queue');
                }}
                className="px-3 py-1.5 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink hover:border-ash transition-colors"
              >
                Clear Selection
              </button>
            )}
          </div>

          {loadingFindings && <p className="text-graphite text-[14px] py-4">Loading findings...</p>}

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 text-red-700 rounded-btn text-[13px]">
              {error}
            </div>
          )}

          {!loadingFindings && !error && findings.length === 0 && (
            <div className="text-center py-10 text-graphite text-[14px]">
              <svg className="w-10 h-10 mx-auto mb-2 text-ash" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              No findings awaiting validation for this assessment.
            </div>
          )}

          {!loadingFindings && !error && findings.length > 0 && (
            <div className="space-y-4 pt-2">
              {findings.map((f) => (
                <div
                  key={f.finding_id}
                  className="border border-warm-mist rounded-[10px] p-4 flex flex-col md:flex-row justify-between md:items-center gap-4 bg-[#faf8f5]"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded-[4px] text-[11px] font-medium border ${
                          f.severity === 'critical'
                            ? 'bg-red-50 border-red-200 text-red-700'
                            : f.severity === 'high'
                            ? 'bg-orange-50 border-orange-200 text-orange-700'
                            : f.severity === 'medium'
                            ? 'bg-yellow-50 border-yellow-200 text-yellow-700'
                            : 'bg-teal-50 border-teal-200 text-deep-teal'
                        }`}
                      >
                        {f.severity.toUpperCase()}
                      </span>
                      <h3 className="text-[15px] font-medium text-ink">{f.title}</h3>
                    </div>
                    <p className="text-[13px] text-graphite">{f.description}</p>
                    <div className="text-[12px] text-graphite flex gap-4 pt-1">
                      <span>Target: <strong className="text-ink font-normal">{f.target_domain}</strong></span>
                      <span>Tool: <code className="text-ink font-mono text-[11px]">{f.source_tool}</code></span>
                    </div>
                  </div>

                  <div className="flex gap-2 flex-shrink-0">
                    <button
                      onClick={() => handleValidate(f.finding_id, 'confirm')}
                      className="px-4 py-2 bg-[#016a71] hover:bg-ink text-white rounded-btn text-[13px] font-medium transition-colors"
                    >
                      Confirm
                    </button>
                    <button
                      onClick={() => handleValidate(f.finding_id, 'reject')}
                      className="px-4 py-2 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 rounded-btn text-[13px] font-medium transition-colors"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
