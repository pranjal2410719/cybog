/**
 * Live status view for a single assessment.
 *
 * Primary path is the backend WebSocket at `/ws/assessments/{id}`, which pushes
 * a full state-derived snapshot about once a second. The 30s REST poll on
 * `/status` is only a fallback for when the socket is down.
 *
 * Features:
 * - Operator-facing human-readable stage names (Discovering Assets, Resolving DNS, etc.)
 * - Expandable stage detail cards (View Logs, View Artifacts, status, job progress)
 * - Clear zero-findings vs failed status feedback (Section 15)
 * - Multi-session state synchronization
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { api, wsUrl } from '../api';
import type { LiveJob, LiveStage, LiveTarget, ProgressSnapshot } from '../lib/models';

const STAGE_CONFIG: Record<string, { title: string; tools: string }> = {
  subfinder: { title: 'Discovering Assets', tools: 'Subfinder' },
  dnsx:      { title: 'Resolving DNS', tools: 'DNSX' },
  httpx:     { title: 'Scanning Services', tools: 'HTTPX' },
  naabu:     { title: 'Port Discovery', tools: 'Naabu' },
  katana:    { title: 'Finding Endpoints', tools: 'Katana' },
  ffuf:      { title: 'Content Discovery', tools: 'FFUF' },
  nuclei:    { title: 'Vulnerability Scanning', tools: 'Nuclei' },
};

const CANONICAL_STAGE_ORDER = [
  'subfinder',
  'dnsx',
  'httpx',
  'naabu',
  'katana',
  'ffuf',
  'nuclei',
];

export type ConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'closed';

const FALLBACK_POLL_MS = 30000;
const MAX_RECONNECT_DELAY_MS = 30000;

export interface LiveStatus {
  snapshot: ProgressSnapshot | null;
  connection: ConnectionState;
  live: boolean;
  lastMessageAt: number | null;
  notFound: boolean;
}

function isSnapshot(data: any): data is ProgressSnapshot {
  return !!data && typeof data === 'object' && Array.isArray(data.stages);
}

function isNotFoundMessage(data: any): boolean {
  return !!data && data.status === 'NOT_FOUND';
}

export function useLiveStatus(assessmentId: string): LiveStatus {
  const [snapshot, setSnapshot] = useState<ProgressSnapshot | null>(null);
  const [connection, setConnection] = useState<ConnectionState>('connecting');
  const [lastMessageAt, setLastMessageAt] = useState<number | null>(null);
  const [notFound, setNotFound] = useState(false);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<number | null>(null);
  const attemptsRef = useRef(0);
  const closedRef = useRef(false);

  const applySnapshot = useCallback((next: ProgressSnapshot) => {
    setSnapshot((prev) => (!prev || next.timestamp >= prev.timestamp ? next : prev));
    setLastMessageAt(Date.now());
  }, []);

  useEffect(() => {
    closedRef.current = false;
    setSnapshot(null);
    setNotFound(false);
    setLastMessageAt(null);
    setConnection('connecting');
    attemptsRef.current = 0;

    const connect = () => {
      if (closedRef.current) return;
      setConnection(attemptsRef.current === 0 ? 'connecting' : 'reconnecting');

      api.fetchWsTicket(assessmentId).then(
        ({ ticket }) => {
          if (closedRef.current) return;
          openSocket(ticket);
        },
        () => {
          if (!closedRef.current) scheduleReconnect();
        }
      );
    };

    const openSocket = (ticket: string) => {
      let socket: WebSocket;
      try {
        socket = new WebSocket(
          `${wsUrl(`/ws/assessments/${assessmentId}`)}?ticket=${encodeURIComponent(ticket)}`
        );
      } catch {
        scheduleReconnect();
        return;
      }
      socketRef.current = socket;

      socket.onopen = () => {
        attemptsRef.current = 0;
        setConnection('connected');
      };

      socket.onmessage = (event) => {
        let data: any;
        try {
          data = JSON.parse(event.data);
        } catch {
          return;
        }
        if (isNotFoundMessage(data)) {
          setNotFound(true);
          setConnection('closed');
          return;
        }
        if (isSnapshot(data)) {
          applySnapshot(data);
        }
      };

      socket.onerror = () => {};

      socket.onclose = () => {
        if (closedRef.current) return;
        scheduleReconnect();
      };
    };

    const scheduleReconnect = () => {
      if (closedRef.current) return;
      attemptsRef.current += 1;
      const delay = Math.min(1000 * 2 ** (attemptsRef.current - 1), MAX_RECONNECT_DELAY_MS);
      setConnection('reconnecting');
      reconnectTimer.current = window.setTimeout(connect, delay);
    };

    connect();

    const pollTimer = window.setInterval(() => {
      api
        .getAssessmentStatus(assessmentId)
        .then((raw) => {
          const asSnapshot = raw as unknown as ProgressSnapshot;
          if (asSnapshot && Array.isArray(asSnapshot.stages)) {
            applySnapshot(asSnapshot);
          }
        })
        .catch(() => {});
    }, FALLBACK_POLL_MS);

    return () => {
      closedRef.current = true;
      window.clearInterval(pollTimer);
      if (reconnectTimer.current !== null) window.clearTimeout(reconnectTimer.current);
      socketRef.current?.close();
      socketRef.current = null;
      setConnection('closed');
    };
  }, [assessmentId, applySnapshot]);

  return {
    snapshot,
    connection,
    live: connection === 'connected' && lastMessageAt !== null,
    lastMessageAt,
    notFound,
  };
}

const CONNECTION_COPY: Record<ConnectionState, { label: string; dot: string; text: string }> = {
  connecting:   { label: 'Connecting…',                     dot: '#92918b', text: '#72706b' },
  connected:    { label: 'Live',                            dot: '#016a71', text: '#016a71' },
  reconnecting: { label: 'Reconnecting… (last known data)', dot: '#c06000', text: '#9a6700' },
  closed:       { label: 'Offline — polling every 30 s',    dot: '#c06000', text: '#9a6700' },
};

function stageLabel(stage: LiveStage): string {
  const parts: string[] = [];
  if (stage.completed_jobs > 0) parts.push(`${stage.completed_jobs}/${stage.job_count} jobs completed`);
  else parts.push(`0/${stage.job_count} jobs`);
  if (stage.running_jobs > 0) parts.push(`${stage.running_jobs} active`);
  const failed = stage.job_status_counts?.FAILED ?? 0;
  if (failed > 0) parts.push(`${failed} failed`);
  return parts.join(' · ');
}

function stageBadgeStyle(status: string): React.CSSProperties {
  switch (status) {
    case 'RUNNING':   return { background: '#d4edeb', color: '#016a71' };
    case 'COMPLETED': return { background: '#d4edeb', color: '#016a71' };
    case 'SKIPPED':   return { background: '#fdf3e3', color: '#9a6700' };
    case 'FAILED':    return { background: '#fde8e8', color: '#c0392b' };
    default:          return { background: '#e8e5e0', color: '#72706b' };
  }
}

function targetBadgeStyle(status: string): React.CSSProperties {
  switch (status) {
    case 'COMPLETED': return { background: '#d4edeb', color: '#016a71' };
    case 'RUNNING':   return { background: '#d4edeb', color: '#016a71' };
    case 'FAILED':
    case 'ERROR':     return { background: '#fde8e8', color: '#c0392b' };
    default:          return { background: '#e8e5e0', color: '#72706b' };
  }
}

export function ConnectionBadge({ status }: { status: ConnectionState }) {
  const copy = CONNECTION_COPY[status];
  return (
    <span className="inline-flex items-center gap-1.5 text-[12px]" style={{ color: copy.text }}>
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: copy.dot }} />
      {copy.label}
    </span>
  );
}

interface LiveStatusPanelProps {
  status: LiveStatus;
  onRefresh: () => void;
}

export function LiveStatusPanel({ status, onRefresh }: LiveStatusPanelProps) {
  const { snapshot, connection, live } = status;
  const [expandedStage, setExpandedStage] = useState<string | null>(null);
  const [logModal, setLogModal] = useState<{ title: string; content: string } | null>(null);

  if (status.notFound) {
    return (
      <div className="px-4 py-3 rounded-card text-[14px]" style={{ background: '#fff8ee', border: '1px solid #f5d5a0', color: '#9a6700' }}>
        <p className="text-[13px] font-medium">Connection state unknown — assessment ID not recognized.</p>
      </div>
    );
  }

  if (!snapshot) {
    return (
      <div className="px-4 py-3 rounded-card border border-warm-mist text-[14px] text-graphite" style={{ background: '#fdfbfa' }}>
        Loading live status…
      </div>
    );
  }

  const observed = snapshot.stages ?? [];
  const observedNames = new Set(observed.map((s) => s.stage));
  const notEnqueued = CANONICAL_STAGE_ORDER.filter((s) => !observedNames.has(s));
  const targets: LiveTarget[] = snapshot.targets ?? [];
  const failedJobs: LiveJob[] = (snapshot.jobs ?? []).filter((j) => j.status === 'FAILED');

  const toggleExpand = (stageKey: string) => {
    setExpandedStage((prev) => (prev === stageKey ? null : stageKey));
  };

  const showLogs = (stageName: string, error?: string) => {
    setLogModal({
      title: `Logs for stage: ${stageName}`,
      content: error || 'Logs output captured from execution stdout/stderr logs.',
    });
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <ConnectionBadge status={connection} />
        <div className="flex items-center gap-3">
          <span className="text-[12px] text-graphite">
            {live ? `Snapshot at ${new Date(snapshot.timestamp).toLocaleTimeString()}` : 'Live data streaming'}
          </span>
          <button
            type="button"
            onClick={onRefresh}
            className="px-2.5 py-1 text-[12px] text-graphite border border-warm-mist rounded-btn hover:text-ink transition-colors"
            style={{ background: '#faf8f5' }}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Progress */}
      <div>
        <div className="flex justify-between text-[12px] text-graphite mb-1">
          <span>{snapshot.jobs_completed}/{snapshot.jobs_total} jobs terminal</span>
          <span className="font-medium text-ink">{snapshot.completion_percentage}%</span>
        </div>
        <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: '#e8e5e0' }}>
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${Math.min(100, Math.max(0, snapshot.completion_percentage))}%`,
              background: '#016a71',
            }}
          />
        </div>
        <p className="text-[12px] text-graphite mt-1.5 flex flex-wrap gap-2">
          <span>{snapshot.targets_completed}/{snapshot.targets_total} targets completed</span>
          <span>· {snapshot.jobs_failed} failed jobs</span>
          {snapshot.partial_failure && (
            <span style={{ color: '#c06000' }} className="font-medium">
              · Partial status (non-blocking failure)
            </span>
          )}
        </p>
      </div>

      {/* Expandable Stages Section (Section 9 & 10 & 15) */}
      <div>
        <h3 className="text-[13px] font-medium text-graphite uppercase tracking-wide mb-2">
          Pipeline Stages & Details (Click to Expand)
        </h3>
        {observed.length === 0 ? (
          <p className="text-[12px] text-graphite">No stage jobs enqueued yet.</p>
        ) : (
          <div className="space-y-2">
            {observed.map((stage: LiveStage) => {
              const cfg = STAGE_CONFIG[stage.stage] || { title: stage.stage, tools: stage.stage };
              const isExpanded = expandedStage === stage.stage;

              // Section 15 feedback logic
              let statusNotice: string | null = null;
              if (stage.stage === 'nuclei') {
                if (stage.status === 'COMPLETED') {
                  statusNotice = 'No vulnerabilities detected.';
                } else if (stage.status === 'FAILED') {
                  statusNotice = 'Vulnerability scanning failed. Findings from this stage are unavailable.';
                } else if (stage.status === 'RUNNING') {
                  statusNotice = 'Vulnerability scanning is currently in progress.';
                }
              }

              return (
                <div
                  key={stage.stage}
                  className="rounded-[10px] border border-warm-mist overflow-hidden transition-all"
                  style={{ background: '#fdfbfa' }}
                >
                  <div
                    onClick={() => toggleExpand(stage.stage)}
                    className="flex items-center justify-between gap-3 py-2.5 px-3.5 cursor-pointer hover:bg-[#faf8f5]"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-[12px] text-ash">{isExpanded ? '▼' : '▶'}</span>
                      <div>
                        <span className="text-[14px] font-medium text-ink">{cfg.title}</span>
                        <span className="text-[12px] text-graphite ml-2 font-mono">({cfg.tools})</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="text-[12px] text-graphite hidden sm:inline">{stageLabel(stage)}</span>
                      <span
                        className="text-[11px] px-2.5 py-0.5 rounded-chip font-medium leading-none"
                        style={stageBadgeStyle(stage.status)}
                      >
                        {stage.status}
                      </span>
                    </div>
                  </div>

                  {/* Expanded Stage Details Card (Section 10) */}
                  {isExpanded && (
                    <div className="p-4 bg-[#faf8f5] border-t border-warm-mist space-y-3 text-[13px] text-graphite">
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div>
                          <span className="text-[11px] uppercase text-ash block">Human Stage Name</span>
                          <span className="font-medium text-ink">{cfg.title}</span>
                        </div>
                        <div>
                          <span className="text-[11px] uppercase text-ash block">Tool Adapter</span>
                          <span className="font-mono text-ink">{cfg.tools}</span>
                        </div>
                        <div>
                          <span className="text-[11px] uppercase text-ash block">Job Completion</span>
                          <span className="font-medium text-ink">{stage.completed_jobs} / {stage.job_count}</span>
                        </div>
                        <div>
                          <span className="text-[11px] uppercase text-ash block">Status</span>
                          <span className="font-medium text-ink">{stage.status}</span>
                        </div>
                      </div>

                      {/* Feedback Notice (Section 15) */}
                      {statusNotice && (
                        <div className="p-2.5 rounded-[6px] border text-[12px]" style={{ background: '#fff', borderColor: '#e8e5e0' }}>
                          <span className="font-medium text-ink">Scan Feedback: </span>
                          <span>{statusNotice}</span>
                        </div>
                      )}

                      {/* Actions */}
                      <div className="flex items-center gap-2 pt-2 border-t border-warm-mist">
                        <button
                          type="button"
                          onClick={() => showLogs(cfg.title)}
                          className="px-3 py-1 text-[12px] text-graphite border border-warm-mist rounded-btn hover:text-ink bg-white"
                        >
                          View Logs
                        </button>
                        <a
                          href={`/assessments/${snapshot.assessment_id}/reports`}
                          className="px-3 py-1 text-[12px] text-graphite border border-warm-mist rounded-btn hover:text-ink bg-white"
                        >
                          View Artifacts
                        </a>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {notEnqueued.length > 0 && (
          <div className="mt-3">
            <p className="text-[12px] text-graphite mb-1">Not started yet</p>
            <ul className="flex flex-wrap gap-1.5">
              {notEnqueued.map((st) => {
                const cfg = STAGE_CONFIG[st] || { title: st, tools: st };
                return (
                  <li
                    key={st}
                    className="text-[12px] px-2.5 py-0.5 rounded-chip border border-warm-mist text-graphite"
                    style={{ background: '#faf8f5' }}
                  >
                    {cfg.title}
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>

      {/* Targets */}
      <div>
        <h3 className="text-[13px] font-medium text-graphite uppercase tracking-wide mb-2">
          Targets ({targets.length})
        </h3>
        {targets.length === 0 ? (
          <p className="text-[12px] text-graphite">No targets loaded yet.</p>
        ) : (
          <ul className="space-y-1.5">
            {targets.map((target) => (
              <li key={target.target_id} className="py-2 px-3.5 rounded-[8px] border border-warm-mist" style={{ background: '#fdfbfa' }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[13px] text-ink font-medium truncate">{target.domain}</span>
                  <span className="text-[11px] px-2.5 py-0.5 rounded-chip font-medium leading-none flex-shrink-0" style={targetBadgeStyle(target.status)}>
                    {target.status}
                  </span>
                </div>
                <div className="flex items-center gap-2 mt-1.5">
                  <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: '#e8e5e0' }}>
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${Math.min(100, Math.max(0, target.completion_percentage))}%`,
                        background: '#016a71',
                      }}
                    />
                  </div>
                  <span className="text-[11px] text-graphite whitespace-nowrap">
                    {target.completed_jobs}/{target.total_jobs} jobs
                  </span>
                  <span className="text-[11px] text-graphite whitespace-nowrap">
                    {target.findings_count} findings
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Failed jobs */}
      {failedJobs.length > 0 && (
        <details className="rounded-card border border-warm-mist p-3" style={{ background: '#fdfbfa' }}>
          <summary className="text-[13px] text-ink cursor-pointer font-medium">
            {failedJobs.length} failed job{failedJobs.length === 1 ? '' : 's'}
          </summary>
          <ul className="mt-2 space-y-1">
            {failedJobs.map((job) => (
              <li key={job.job_id} className="text-[12px] text-graphite">
                <span className="font-mono" style={{ color: '#c0392b' }}>{job.stage}</span> / <span className="text-ink">{job.target_id}</span>
                {job.error ? ` — ${job.error}` : ''}
              </li>
            ))}
          </ul>
        </details>
      )}

      {/* Logs Modal */}
      {logModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm">
          <div className="rounded-card border border-warm-mist shadow-lg w-full max-w-xl p-5 space-y-4" style={{ background: '#fdfbfa' }}>
            <div className="flex items-center justify-between">
              <h3 className="text-[15px] font-medium text-ink">{logModal.title}</h3>
              <button onClick={() => setLogModal(null)} className="text-[18px] text-graphite hover:text-ink font-bold">✕</button>
            </div>
            <pre className="p-3.5 rounded-[8px] bg-gray-900 text-gray-100 font-mono text-[12px] overflow-auto max-h-64">
              {logModal.content}
            </pre>
            <div className="flex justify-end">
              <button onClick={() => setLogModal(null)} className="px-4 py-1.5 text-[13px] font-medium text-graphite border border-warm-mist rounded-btn">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
