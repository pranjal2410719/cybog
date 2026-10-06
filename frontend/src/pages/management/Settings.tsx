/**
 * Management Settings Page
 *
 * Read-only system configuration and health overview.
 * Requires MANAGEMENT role (enforced server-side).
 */

import { useState, useEffect, useCallback } from 'react';
import { api } from '../../api';
import type { HealthResponse } from '../../lib/models';

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
    <div className="flex items-start gap-2 text-[14px] mb-2">
      <span className="text-graphite w-36 flex-shrink-0">{label}</span>
      <span className="text-ink">{value}</span>
    </div>
  );
}

interface SystemHealth extends HealthResponse {
  assessments_active: number;
  assessments_pending: number;
  assessments_completed: number;
  findings_validated: number;
  findings_pending: number;
  uptime_seconds: number;
}

export function SettingsPage() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadHealth = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.checkHealth();
      setHealth(data as SystemHealth);
    } catch (err: any) {
      setError(err?.message || 'Failed to load system health');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHealth();
    const interval = setInterval(loadHealth, 30000);
    return () => clearInterval(interval);
  }, [loadHealth]);

  if (loading && !health) {
    return (
      <div className="space-y-4">
        <div className="h-12 rounded-card border border-warm-mist animate-pulse" style={{ background: '#fdfbfa' }} />
        <div className="h-40 rounded-card border border-warm-mist animate-pulse" style={{ background: '#fdfbfa' }} />
        <div className="h-40 rounded-card border border-warm-mist animate-pulse" style={{ background: '#fdfbfa' }} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-[22px] font-medium text-ink">System Settings</h1>
        <p className="text-[14px] text-graphite mt-1">
          Read-only overview of system health and configuration.
        </p>
      </div>

      {/* Error banner */}
      {error && (
        <div
          className="rounded-card border p-3 text-[13px]"
          style={{ background: '#fdf3f3', borderColor: '#f5c6c6', color: '#c0392b' }}
        >
          {error}
          <button
            onClick={loadHealth}
            className="ml-3 underline text-[13px]"
          >
            Retry
          </button>
        </div>
      )}

      {/* System Health */}
      <InfoCard title="System Health">
        {health ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <InfoRow label="Status" value={health.status} />
            <InfoRow
              label="Version"
              value={
                <span className="font-mono text-[12px]">
                  {health.version} / {health.cybog_version}
                </span>
              }
            />
            {health.uptime_seconds != null && (
              <InfoRow
                label="Uptime"
                value={`${Math.floor(health.uptime_seconds / 3600)}h ${Math.floor((health.uptime_seconds % 3600) / 60)}m`}
              />
            )}
            {health.assessments_active != null && (
              <InfoRow label="Active Assessments" value={health.assessments_active} />
            )}
            {health.assessments_pending != null && (
              <InfoRow label="Pending Assessments" value={health.assessments_pending} />
            )}
            {health.assessments_completed != null && (
              <InfoRow label="Completed Assessments" value={health.assessments_completed} />
            )}
            {health.findings_validated != null && (
              <InfoRow label="Validated Findings" value={health.findings_validated} />
            )}
            {health.findings_pending != null && (
              <InfoRow label="Pending Findings" value={health.findings_pending} />
            )}
          </div>
        ) : (
          <p className="text-[13px] text-graphite">System health data unavailable.</p>
        )}
      </InfoCard>

      {/* Configuration */}
      <InfoCard title="Configuration">
        <div className="space-y-2 text-[13px] text-graphite">
          <p>• Scan profiles: Standard, Quick, Full (configured server-side)</p>
          <p>• Authentication: Token-based with role-based access control</p>
          <p>• WebSocket: Real-time updates via single-use tickets (60s expiry)</p>
          <p>• Scope admission: Per-host validation at stage-input time</p>
          <p>• Audit logging: All actions recorded with user and timestamp</p>
          <p>• Report formats: JSON, JSONL, HTML</p>
        </div>
      </InfoCard>

      {/* Security Notice */}
      <div
        className="rounded-card border border-warm-mist shadow-subtle p-4"
        style={{ background: '#fdfbfa' }}
      >
        <h3 className="text-[13px] font-medium text-graphite uppercase tracking-wide mb-2">
          Authorization Notice
        </h3>
        <p className="text-[12px] text-graphite">
          Backend authorization is the authoritative security boundary. The
          role-based guards and capability-based navigation in this UI are
          convenience layers; all write operations require backend RBAC
          enforcement regardless of UI state.
        </p>
      </div>
    </div>
  );
}
