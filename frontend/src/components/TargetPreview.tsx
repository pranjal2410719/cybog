/**
 * Resolved-target preview table: raw entry, normalized form and per-target
 * status, for the multiple-targets flow.
 */

import { submittableTargets, type TargetEntry } from './TargetUtils';

function Row({ entry }: { entry: TargetEntry }) {
  const valid = entry.status === 'VALID';
  return (
    <tr className="border-t border-cyborg-border/60 align-top">
      <td className="py-2 pr-3 font-mono text-white break-all">{entry.raw}</td>
      <td className="py-2 pr-3 font-mono text-cyborg-muted break-all">
        {entry.normalized || '—'}
      </td>
      <td className="py-2 pr-3">
        {valid ? (
          <span className="px-2 py-0.5 rounded border border-cyborg-accent/50 bg-cyborg-accent/10 text-cyborg-accent text-xs font-semibold">
            VALID
          </span>
        ) : (
          <span className="px-2 py-0.5 rounded border border-red-500/50 bg-red-500/10 text-red-400 text-xs font-semibold">
            INVALID
          </span>
        )}
        {entry.duplicate && (
          <span className="ml-2 px-2 py-0.5 rounded border border-amber-500/50 bg-amber-500/10 text-amber-400 text-xs font-semibold">
            DUPLICATE
          </span>
        )}
      </td>
      <td className="py-2 text-xs text-cyborg-muted/80">{entry.reason || '—'}</td>
    </tr>
  );
}

export function TargetPreview({ entries }: { entries: TargetEntry[] }) {
  if (entries.length === 0) {
    return (
      <div className="bg-cyborg-darker border border-cyborg-border rounded-lg p-4">
        <p className="text-xs font-semibold uppercase tracking-wider text-cyborg-muted mb-2">
          Target preview
        </p>
        <p className="text-sm text-cyborg-muted/70">
          No targets loaded. Choose a .txt file to populate this list.
        </p>
      </div>
    );
  }

  const sent = submittableTargets(entries).length;

  return (
    <div className="bg-cyborg-darker border border-cyborg-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <p className="text-xs font-semibold uppercase tracking-wider text-cyborg-muted">
          Target preview
        </p>
        <p className="text-xs text-cyborg-muted/80">
          {sent} of {entries.length} will be sent
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs uppercase tracking-wider text-cyborg-muted">
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
