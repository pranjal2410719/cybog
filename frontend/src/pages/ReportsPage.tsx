/**
 * Dedicated Reports Page
 *
 * Displays generated HTML, JSONL, JSON, and PDF reports and scan artifacts across assessments:
 * - List of available reports per assessment
 * - Actions: View Inline (HTML preview with security headers), Download, Export ZIP
 */

import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type { AssessmentResponse } from '../lib/models';

interface ReportItem {
  filename: string;
  type: string;
  path: string;
  size_bytes: number;
  created_at: string;
  assessmentId: string;
  assessmentName: string;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function ReportsPage() {
  const [assessments, setAssessments] = useState<AssessmentResponse[]>([]);
  const [reportsList, setReportsList] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>('ALL');

  // Inline view modal state
  const [inlineHtmlUrl, setInlineHtmlUrl] = useState<string | null>(null);
  const [inlineReportTitle, setInlineReportTitle] = useState<string>('');

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const list = await api.listAssessments();
      setAssessments(list);

      const allReports: ReportItem[] = [];
      await Promise.all(
        list.map(async (a) => {
          try {
            const data = await api.getReports(a.assessment_id);
            if (data && Array.isArray(data.reports)) {
              data.reports.forEach((r) => {
                allReports.push({
                  ...r,
                  assessmentId: a.assessment_id,
                  assessmentName: a.name || a.assessment_id,
                });
              });
            }
          } catch {
            // Ignore single assessment error
          }
        })
      );

      setReportsList(allReports);
    } catch (err: any) {
      console.error('Failed to load reports:', err);
      setError(err?.message || 'Failed to load reports');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const filteredReports = reportsList.filter((r) => {
    if (selectedAssessmentId !== 'ALL' && r.assessmentId !== selectedAssessmentId) return false;
    return true;
  });

  const handleViewInline = (report: ReportItem) => {
    const inlineUrl = `/api/v1/assessments/${report.assessmentId}/reports/${report.filename}/inline`;
    setInlineHtmlUrl(inlineUrl);
    setInlineReportTitle(`${report.assessmentName} — ${report.filename}`);
  };

  return (
    <div className="space-y-6 max-w-[1000px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-[22px] font-medium text-ink">Assessment Reports</h1>
          <p className="text-[14px] text-graphite mt-0.5">
            View inline or download automatically generated HTML, JSONL, and aggregate reports.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle p-4 flex flex-wrap gap-4 items-center justify-between"
        style={{ background: '#fdfbfa' }}
      >
        <div className="flex items-center gap-3">
          <label className="text-[13px] font-medium text-graphite">Filter Assessment:</label>
          <select
            value={selectedAssessmentId}
            onChange={(e) => setSelectedAssessmentId(e.target.value)}
            className="px-3 py-1.5 text-[13px] text-ink border border-warm-mist rounded-input outline-none"
            style={{ background: '#faf8f5' }}
          >
            <option value="ALL">All Assessments ({assessments.length})</option>
            {assessments.map((a) => (
              <option key={a.assessment_id} value={a.assessment_id}>
                {a.name || a.assessment_id}
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={loadData}
          className="px-3 py-1.5 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink transition-colors"
        >
          Refresh Reports
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div
          className="rounded-card border p-3 text-[14px] flex items-center justify-between"
          style={{ background: '#fdf3f3', borderColor: '#f5c6c6', color: '#c0392b' }}
        >
          <span>{error}</span>
          <button onClick={loadData} className="underline text-[13px] font-medium">
            Retry
          </button>
        </div>
      )}

      {/* Reports Table */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle overflow-hidden"
        style={{ background: '#fdfbfa' }}
      >
        {loading ? (
          <div className="p-8 text-center text-graphite text-[14px]">Loading assessment reports…</div>
        ) : filteredReports.length === 0 ? (
          <div className="p-12 text-center text-graphite text-[14px]">
            No generated reports available yet. Reports appear automatically once an assessment completes.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr style={{ borderBottom: '1px solid #d1d1cd' }}>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Report File</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Assessment</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Type</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Size</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Created</th>
                  <th className="px-4 py-3 font-medium text-graphite uppercase tracking-wide">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredReports.map((report, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid #e8e5e0' }}>
                    <td className="px-4 py-3 font-mono font-medium text-ink">{report.filename}</td>
                    <td className="px-4 py-3 text-graphite max-w-[180px] truncate">{report.assessmentName}</td>
                    <td className="px-4 py-3 text-graphite capitalize">{report.type}</td>
                    <td className="px-4 py-3 text-graphite">{formatBytes(report.size_bytes)}</td>
                    <td className="px-4 py-3 text-graphite text-[12px]">
                      {new Date(report.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {report.filename.endsWith('.html') && (
                          <button
                            onClick={() => handleViewInline(report)}
                            className="px-2.5 py-1 text-[12px] font-medium text-white rounded-btn transition-opacity hover:opacity-90"
                            style={{ background: '#016a71' }}
                          >
                            View Inline
                          </button>
                        )}
                        <a
                          href={`/api/v1/assessments/${report.assessmentId}/reports/${report.filename}`}
                          download
                          className="px-2.5 py-1 text-[12px] font-medium text-graphite border border-warm-mist rounded-btn hover:text-ink transition-colors"
                          style={{ background: '#faf8f5' }}
                        >
                          Download
                        </a>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Inline HTML Report Modal */}
      {inlineHtmlUrl && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm">
          <div
            className="rounded-card border border-warm-mist shadow-lg w-full max-w-4xl h-[85vh] flex flex-col overflow-hidden"
            style={{ background: '#fdfbfa' }}
          >
            <div className="flex items-center justify-between p-4 border-b border-warm-mist">
              <h3 className="text-[16px] font-medium text-ink truncate">{inlineReportTitle}</h3>
              <button
                onClick={() => setInlineHtmlUrl(null)}
                className="text-[18px] text-graphite hover:text-ink font-bold px-2"
              >
                ✕
              </button>
            </div>
            <div className="flex-1 w-full bg-white">
              <iframe
                src={inlineHtmlUrl}
                title={inlineReportTitle}
                className="w-full h-full border-none"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
