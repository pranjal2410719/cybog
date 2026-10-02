/**
 * Single-target input: accepts a bare domain or a full URL, shows exactly what
 * normalization was applied, and renders a compact preview card.
 */

import { createTargetEntry, describeChanges, type TargetEntry } from './TargetUtils';

const VALID_CLASS = 'text-cyborg-accent border-cyborg-accent/50 bg-cyborg-accent/10';
const INVALID_CLASS = 'text-red-400 border-red-500/50 bg-red-500/10';

function StatusBadge({ entry }: { entry: TargetEntry }) {
  if (entry.status === 'INVALID') {
    return (
      <span
        className={`px-2 py-0.5 rounded border text-xs font-semibold tracking-wide ${INVALID_CLASS}`}
      >
        INVALID
      </span>
    );
  }
  return (
    <span
      className={`px-2 py-0.5 rounded border text-xs font-semibold tracking-wide ${VALID_CLASS}`}
    >
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
    <div className="space-y-3">
      <div>
        <label
          htmlFor="single-target"
          className="block text-sm font-medium text-cyborg-muted mb-1"
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
          className="w-full px-4 py-2 bg-cyborg-card border border-cyborg-border rounded-lg
                     text-white placeholder-cyborg-muted focus:ring-2 focus:ring-cyborg-accent
                     focus:border-transparent transition-colors"
        />
        <p className="mt-1 text-xs text-cyborg-muted/80">
          A bare domain or a full URL. Normalization strips the scheme, any
          userinfo, path, query/fragment, port, trailing dot and uppercase —
          the preview below shows the result.
        </p>
      </div>

      <div className="bg-cyborg-darker border border-cyborg-border rounded-lg p-4">
        <p className="text-xs font-semibold uppercase tracking-wider text-cyborg-muted mb-2">
          Target preview
        </p>
        {!dirty ? (
          <p className="text-sm text-cyborg-muted/70">Enter a target to preview it.</p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <div className="min-w-0">
                <p className="text-xs text-cyborg-muted/70">Entered</p>
                <p className="font-mono text-white break-all">{entry.raw || '(empty)'}</p>
              </div>
              <span className="text-cyborg-muted">&rarr;</span>
              <div className="min-w-0">
                <p className="text-xs text-cyborg-muted/70">Normalized</p>
                <p className="font-mono text-white break-all">
                  {entry.normalized || '(nothing usable)'}
                </p>
              </div>
              <StatusBadge entry={entry} />
            </div>
            <p className="mt-2 text-xs text-cyborg-muted/80">
              Normalization applied: {describeChanges(entry.changes)}.
            </p>
            {entry.status === 'INVALID' && (
              <p className="mt-1 text-xs text-red-400">{entry.reason}.</p>
            )}
            <p className="mt-2 text-xs text-cyborg-muted/70">
              Client-side check only — the backend validates again and is
              authoritative.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
