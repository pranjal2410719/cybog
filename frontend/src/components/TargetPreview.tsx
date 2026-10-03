/**
 * Resolved-target preview table: raw entry, normalized form and per-target
 * status, for the multiple-targets flow.
 */

import { submittableTargets, type TargetEntry } from './TargetUtils';

function Row({ entry }: { entry: TargetEntry }) {
  const valid = entry.status === 'VALID';
  return (
    <tr className="border-t border-warm-mist align-top text-[13px]">
      <td className="py-2.5 pr-3 font-mono text-ink break-all">{entry.raw}</td>
      <td className="py-2.5 pr-3 font-mono text-graphite break-all">
        {entry.normalized || '—'}
      </td>
      <td className="py-2.5 pr-3">
        <div className="flex flex-wrap gap-1.5 items-start">
          {valid ? (
            <span className="text-[11px] font-medium px-2 py-0.5 rounded-chip leading-none"
                  style={{ background: '#d4edeb', color: '#016a71' }}>
              VALID
            </span>
          ) : (
            <span className="text-[11px] font-medium px-2 py-0.5 rounded-chip leading-none"
                  style={{ background: '#fde8e8', color: '#c0392b' }}>
              INVALID
            </span>
          )}
          {entry.duplicate && (
            <span className="text-[11px] font-medium px-2 py-0.5 rounded-chip leading-none"
                  style={{ background: '#fef5e7', color: '#9a6700' }}>
              DUPLICATE
            </span>
          )}
        </div>
      </td>
      <td className="py-2.5 text-[12px] text-graphite">{entry.reason || '—'}</td>
    </tr>
  );
}

export function TargetPreview({ entries }: { entries: TargetEntry[] }) {
  if (entries.length === 0) {
    return (
      <div className="bg-soft-paper border border-warm-mist rounded-card p-4">
        <p className="text-[13px] font-medium uppercase tracking-wide text-graphite mb-2">
          Target preview
        </p>
        <p className="text-[13px] text-graphite">
          No targets loaded. Choose a .txt file to populate this list.
        </p>
      </div>
    );
  }

  const sent = submittableTargets(entries).length;

  return (
    <div className="bg-soft-paper border border-warm-mist rounded-card p-4">
      <div className="flex items-center justify-between mb-3">
        <p className="text-[13px] font-medium uppercase tracking-wide text-graphite">
          Target preview
        </p>
        <p className="text-[12px] text-graphite font-medium">
          {sent} of {entries.length} will be sent
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="text-[11px] uppercase tracking-wide text-ash border-b border-warm-mist">
              <th className="pb-2 pr-3 font-medium">Target</th>
              <th className="pb-2 pr-3 font-medium">Normalized</th>
              <th className="pb-2 pr-3 font-medium">Status</th>
              <th className="pb-2 font-medium">Notes</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <Row key={entry.id} entry={entry} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
