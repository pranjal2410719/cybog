/**
 * Single-target input: accepts a bare domain or a full URL, shows exactly what
 * normalization was applied, and renders a compact preview card.
 */

import { createTargetEntry, describeChanges, type TargetEntry } from './TargetUtils';

function StatusBadge({ entry }: { entry: TargetEntry }) {
  if (entry.status === 'INVALID') {
    return (
      <span className="text-[11px] font-medium px-2 py-0.5 rounded-chip leading-none"
            style={{ background: '#fde8e8', color: '#c0392b' }}>
        INVALID
      </span>
    );
  }
  return (
    <span className="text-[11px] font-medium px-2 py-0.5 rounded-chip leading-none"
          style={{ background: '#d4edeb', color: '#016a71' }}>
        VALID
    </span>
  );
}

export function TargetInput({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const entry = createTargetEntry(value);
  const dirty = value.trim() !== '';

  return (
    <div className="space-y-4">
      <div>
        <label
          htmlFor="single-target"
          className="block text-[13px] font-medium text-graphite uppercase tracking-wide mb-1.5"
        >
          Target
        </label>
        <input
          id="single-target"
          type="text"
          name="single_target"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          placeholder="example.com  or  https://example.com"
          className="w-full px-4 py-3 bg-parchment border border-warm-mist rounded-input
                     text-ink placeholder-ash input-glow transition-all"
        />
        <p className="mt-2 text-[12px] text-graphite">
          A bare domain or a full URL. Normalization strips the scheme, any
          userinfo, path, query/fragment, port, trailing dot and uppercase —
          the preview below shows the result.
        </p>
      </div>

      <div className="bg-soft-paper border border-warm-mist rounded-card p-4">
        <p className="text-[13px] font-medium uppercase tracking-wide text-graphite mb-2.5">
          Target preview
        </p>
        {!dirty ? (
          <p className="text-[13px] text-graphite">Enter a target to preview it.</p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-4 text-[13px]">
              <div className="min-w-0">
                <p className="text-[11px] uppercase tracking-wide text-ash mb-0.5">Entered</p>
                <p className="font-mono text-ink break-all">{entry.raw || '(empty)'}</p>
              </div>
              <span className="text-ash">&rarr;</span>
              <div className="min-w-0">
                <p className="text-[11px] uppercase tracking-wide text-ash mb-0.5">Normalized</p>
                <p className="font-mono text-ink break-all">
                  {entry.normalized || '(nothing usable)'}
                </p>
              </div>
              <div className="ml-auto flex items-center">
                <StatusBadge entry={entry} />
              </div>
            </div>
            <p className="mt-3 text-[12px] text-graphite">
              Normalization applied: {describeChanges(entry.changes)}.
            </p>
            {entry.status === 'INVALID' && (
              <p className="mt-1 text-[12px]" style={{ color: '#c0392b' }}>{entry.reason}.</p>
            )}
            <p className="mt-2 text-[12px] text-ash">
              Client-side check only — the backend validates again and is authoritative.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
