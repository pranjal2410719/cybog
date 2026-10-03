/**
 * Live status view for a single assessment.
 *
 * Primary path is the backend WebSocket at `/ws/assessments/{id}`, which pushes
 * a full state-derived snapshot about once a second. The 30s REST poll on
 * `/status` is only a fallback for when the socket is down, and the connection
 * state is shown so the user can tell whether what they see is live.
 *
 * HONESTY: the snapshot's `stages` array is a rollup of `StageJob` rows, not an
 * emitted "current stage" event. The scheduler runs one worker pool per stage
 * concurrently, so several stages can be in flight at once (`running_stages`
 * is a list). A canonical stage that is absent from `stages` has simply not been
 * enqueued yet — it is labelled "Not started", never "failed" or "skipped".
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { api, wsUrl } from '../api';
import type { LiveJob, LiveStage, LiveTarget, ProgressSnapshot } from '../lib/models';

/**
 * Display order only, mirroring the backend's `STAGE_ORDER` in
 * `backend/app/services/progress_snapshot.py`. Used to decide which canonical
 * stages to list as "not yet enqueued"; it is never used to compute progress.
 */
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
  /** True when the displayed snapshot came from the socket (not the poll). */
  live: boolean;
  lastMessageAt: number | null;
  /** Set when the backend reported the assessment id is unknown. */
  notFound: boolean;
}

function isSnapshot(data: any): data is ProgressSnapshot {
  return !!data && typeof data === 'object' && Array.isArray(data.stages);
}

function isNotFoundMessage(data: any): boolean {
  return !!data && data.status === 'NOT_FOUND';
}

/**
 * Subscribes to the assessment progress WebSocket and keeps a REST fallback
 * poll running. The socket URL is built with `wsUrl()`; no host or path
 * prefix is hardcoded here.
 */
export function useLiveStatus(assessmentId: string): LiveStatus {
  const [snapshot, setSnapshot] = useState<ProgressSnapshot | null>(null);
  const [connection, setConnection] = useState<ConnectionState>('connecting');
  const [lastMessageAt, setLastMessageAt] = useState<number | null>(null);
  const [notFound, setNotFound] = useState(false);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<number | null>(null);
  const attemptsRef = useRef(0);
  const closedRef = useRef(false);

  // Latest snapshot wins; a poll must never overwrite newer socket data.
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

      let socket: WebSocket;
      try {
        socket = new WebSocket(wsUrl(`/ws/assessments/${assessmentId}`));
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
        // The backend labels this push "progress" (see build_progress_snapshot).
        if (isSnapshot(data)) {
          applySnapshot(data);
        }
      };

      socket.onerror = () => {
        // onclose always follows; reconnection is handled there.
      };

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

    // REST fallback. Runs regardless of socket health so the page is never
    // empty when the socket is blocked, but the socket keeps winning while up.
    const pollTimer = window.setInterval(() => {
      api
        .getAssessmentStatus(assessmentId)
        .then((raw) => {
          // /status serves the full progress snapshot; the api module types it
          // as AssessmentStatusResponse, which is narrower than what arrives.
          const asSnapshot = raw as unknown as ProgressSnapshot;
          if (asSnapshot && Array.isArray(asSnapshot.stages)) {
            applySnapshot(asSnapshot);
          }
        })
        .catch(() => {
          // Poll failure is not fatal: the socket may still be streaming.
        });
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

/** Honest label for a per-stage job rollup. */
function stageLabel(stage: LiveStage): string {
  const parts: string[] = [];
  if (stage.completed_jobs > 0) parts.push(`${stage.completed_jobs}/${stage.job_count} done`);
  else parts.push(`0/${stage.job_count} done`);
  if (stage.running_jobs > 0) parts.push(`${stage.running_jobs} running`);
  const failed = stage.job_status_counts?.FAILED ?? 0;
  if (failed > 0) parts.push(`${failed} failed`);
  return parts.join(' · ');
}

function stageBadgeStyle(status: string): React.CSSProperties {
  switch (status) {
    case 'RUNNING':   return { background: '#d4edeb', color: '#016a71' };
    case 'COMPLETED': return { background: '#d4edeb', color: '#016a71' };
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

  if (status.notFound) {
    return (
      <div className="px-4 py-3 rounded-card text-[14px]"
           style={{ background: '#fdf3f3', border: '1px solid #f5c6c6', color: '#c0392b' }}>
        The backend does not know this assessment id.
      </div>
    );
  }

  if (!snapshot) {
    return (
      <div className="px-4 py-3 rounded-card border border-warm-mist text-[14px] text-graphite"
           style={{ background: '#fdfbfa' }}>
        Loading live status…
      </div>
    );
  }

  const observed = snapshot.stages ?? [];
  const observedNames = new Set(observed.map((s) => s.stage));
  const notEnqueued = CANONICAL_STAGE_ORDER.filter((s) => !observedNames.has(s));
  const targets: LiveTarget[] = snapshot.targets ?? [];
  const failedJobs: LiveJob[] = (snapshot.jobs ?? []).filter((j) => j.status === 'FAILED');

  return (
    <div className="space-y-5">
      {/* Connection + timestamp row */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <ConnectionBadge status={connection} />
        <div className="flex items-center gap-3">
          <span className="text-[12px] text-graphite">
            {live
              ? `Snapshot at ${new Date(snapshot.timestamp).toLocaleTimeString()}`
              : 'Live data may be stale'}
          </span>
          <button
            type="button"
            onClick={onRefresh}
            className="px-2 py-1 text-[12px] text-graphite border border-warm-mist rounded-btn
                       hover:text-ink hover:border-ash transition-colors"
            style={{ background: '#faf8f5' }}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Reconnect warning */}
      {connection !== 'connected' && (
        <p className="text-[12px] px-3 py-2 rounded-card"
           style={{ background: '#fff8ee', border: '1px solid #f5d5a0', color: '#9a6700' }}>
          The live socket is {connection}. Values below are the last snapshot; the 30s REST fallback
          keeps them roughly current until the socket recovers.
        </p>
      )}

      {/* Overall progress */}
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
        <p className="text-[12px] text-graphite mt-1">
          {snapshot.targets_completed}/{snapshot.targets_total} targets completed ·{' '}
          {snapshot.jobs_failed} failed job{snapshot.jobs_failed === 1 ? '' : 's'}
        </p>
      </div>

      {/* Stages */}
      <div>
        <h3 className="text-[13px] font-medium text-graphite uppercase tracking-wide mb-2">Stages</h3>
        {observed.length === 0 ? (
          <p className="text-[12px] text-graphite">No stage jobs have been enqueued yet.</p>
        ) : (
          <ul className="space-y-1">
            {observed.map((stage: LiveStage) => (
              <li
                key={stage.stage}
                className="flex items-center justify-between gap-2 py-1.5 px-3 rounded-[8px] border border-warm-mist"
                style={{ background: '#fdfbfa' }}
              >
                <span className="font-mono text-[13px] text-ink">{stage.stage}</span>
                <span className="text-[12px] text-graphite flex-1 text-center">{stageLabel(stage)}</span>
                <span
                  className="text-[11px] px-2 py-0.5 rounded-chip font-medium leading-none"
                  style={stageBadgeStyle(stage.status)}
                  title="Rollup of this stage's job rows, not an emitted event"
                >
                  {stage.status}
                </span>
              </li>
            ))}
          </ul>
        )}

        {notEnqueued.length > 0 && (
          <div className="mt-3">
            <p className="text-[12px] text-graphite mb-1">Not started yet</p>
            <ul className="flex flex-wrap gap-1.5">
              {notEnqueued.map((stage) => (
                <li
                  key={stage}
                  className="text-[12px] px-2 py-0.5 rounded-chip border border-warm-mist text-graphite"
                  style={{ background: '#faf8f5' }}
                  title="No jobs enqueued for this stage yet — not a failure or skip"
                >
                  {stage}
                </li>
              ))}
            </ul>
            <p className="text-[12px] text-graphite mt-1.5">
              A stage appears above only once the scheduler enqueues jobs for it. Absence means "not
              started", not "failed" or "skipped". Stages run concurrently
              {snapshot.running_stages?.length
                ? ` (running: ${snapshot.running_stages.join(', ')})`
                : ''}.
            </p>
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
              <li
                key={target.target_id}
                className="py-2 px-3 rounded-[8px] border border-warm-mist"
                style={{ background: '#fdfbfa' }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[13px] text-ink truncate">{target.domain}</span>
                  <span
                    className="text-[11px] px-2 py-0.5 rounded-chip font-medium leading-none flex-shrink-0"
                    style={targetBadgeStyle(target.status)}
                  >
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
        <details
          className="rounded-card border border-warm-mist p-3"
          style={{ background: '#fdfbfa' }}
        >
          <summary className="text-[13px] text-ink cursor-pointer">
            {failedJobs.length} failed job{failedJobs.length === 1 ? '' : 's'}
          </summary>
          <ul className="mt-2 space-y-1">
            {failedJobs.map((job) => (
              <li key={job.job_id} className="text-[12px] text-graphite">
                <span className="font-mono" style={{ color: '#c0392b' }}>{job.stage}</span>{' '}
                / <span className="text-ink">{job.target_id}</span>
                {job.error ? ` — ${job.error}` : ''}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
