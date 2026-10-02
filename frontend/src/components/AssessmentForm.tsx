/**
 * Assessment Creation Form Component
 *
 * Supports two entry modes that both feed the SAME backend/Cybog pipeline:
 *   - Single Target:  type a domain or URL
 *   - Multiple Targets: upload a .txt manifest
 *
 * Targets are normalized and previewed before anything is submitted. The form
 * contains no scanner logic and never builds a command — it only posts to the
 * REST API.
 */

import { useMemo, useState } from 'react';
import { api } from '../api';
import { TargetInput } from './TargetInput';
import { TargetPreview } from './TargetPreview';
import {
  buildScopeContent,
  buildTargetsContent,
  createTargetEntry,
  parseScopeText,
  parseTargetsText,
  submittableTargets,
  type TargetEntry,
} from './TargetUtils';

type Mode = 'single' | 'multiple';

/**
 * Drag-and-drop + file-picker control. The picker is the mandatory path;
 * drag/drop is a convenience layered on top and must never be the only way in.
 */
function FileInput({
  label,
  fieldLabel,
  acceptedTypes,
  onFileChange,
  onDrop,
  fileName,
}: {
  label: string;
  /** Distinct accessible name — two fields must not share one. */
  fieldLabel: string;
  acceptedTypes: string[];
  onFileChange: (file: File) => void;
  onDrop?: (file: File) => void;
  fileName?: string;
}) {
  const [isDragging, setIsDragging] = useState(false);
  const inputId = `file-${fieldLabel.replace(/\s+/g, '-').toLowerCase()}`;

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0];
    if (selected) onFileChange(selected);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const dropped = e.dataTransfer?.files?.[0];
    if (dropped && acceptedTypes.some((t) => dropped.name.toLowerCase().endsWith(t))) {
      onDrop?.(dropped);
    }
  };

  return (
    <div>
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-lg py-8 px-4 text-center transition-colors ${
          isDragging
            ? 'bg-cyborg-accent/10 border-cyborg-accent'
            : 'border-cyborg-border'
        }`}
      >
        {fileName ? (
          <p className="text-cyborg-accent text-sm font-medium">{fileName}</p>
        ) : (
          <p className="text-cyborg-muted text-sm">{label}</p>
        )}
        <label
          htmlFor={inputId}
          className="inline-block mt-2 px-3 py-1 bg-cyborg-card border border-cyborg-border
                     text-cyborg-muted text-sm rounded cursor-pointer hover:border-cyborg-accent
                     hover:text-cyborg-accent transition-colors"
        >
          {fieldLabel}
        </label>
        <input
          id={inputId}
          type="file"
          accept={acceptedTypes.join(',')}
          onChange={handleChange}
          className="hidden"
        />
      </div>
    </div>
  );
}

export function AssessmentCreationForm({
  onAssessmentCreated,
}: {
  onAssessmentCreated?: (assessmentId: string) => void;
}) {
  const [mode, setMode] = useState<Mode>('single');
  const [name, setName] = useState('');
  const [profile, setProfile] = useState<'standard' | 'quick'>('standard');

  // Single-target raw text, exactly as typed.
  const [singleTarget, setSingleTarget] = useState('');

  // Multiple-target manifest entries.
  const [entries, setEntries] = useState<TargetEntry[]>([]);
  const [targetsFileName, setTargetsFileName] = useState('');

  // Optional scope override. When empty, scope is derived from the targets.
  const [scopePatterns, setScopePatterns] = useState<string[]>([]);
  const [scopeFileName, setScopeFileName] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const readText = (file: File, apply: (text: string) => void) => {
    const reader = new FileReader();
    reader.onload = (e) => apply(e.target?.result as string);
    reader.onerror = () => setError(`Could not read ${file.name}`);
    reader.readAsText(file);
  };

  const handleTargetsFile = (file: File) => {
    setTargetsFileName(file.name);
    readText(file, (text) => setEntries(parseTargetsText(text)));
  };

  const handleScopeFile = (file: File) => {
    setScopeFileName(file.name);
    readText(file, (text) => setScopePatterns(parseScopeText(text)));
  };

  // In single mode the typed value becomes a one-entry list so both modes
  // share one code path downstream.
  const effectiveEntries: TargetEntry[] = useMemo(() => {
    if (mode === 'single') {
      return singleTarget.trim() === '' ? [] : [createTargetEntry(singleTarget)];
    }
    return entries;
  }, [mode, singleTarget, entries]);

  const submittable = submittableTargets(effectiveEntries);
  const hasInvalid = effectiveEntries.some((e) => e.status === 'INVALID');
  const canSubmit = name.trim() !== '' && submittable.length > 0 && !loading;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submittable.length === 0) return;

    setLoading(true);
    setError(null);

    // Both payloads are newline-terminated. The backend decides whether
    // `targets_file` is a path or inline content via `_is_file_content()`, so a
    // bare `example.com` with no trailing newline would be read as a
    // filesystem path and fail. Terminating guarantees "content".
    const targetsContent = buildTargetsContent(effectiveEntries);
    const scopePatternsToSend =
      scopePatterns.length > 0 ? scopePatterns : submittable.map((t) => t.normalized);
    const scopeContent = buildScopeContent(scopePatternsToSend);

    try {
      const created = await api.createAssessment({
        name: name.trim(),
        targets_file: targetsContent,
        scope_file: scopeContent,
        profile,
      });

      // Create only registers the assessment; execution is a separate call.
      // Both go through the same AssessmentService the CLI uses.
      try {
        await api.startAssessment(created.assessment_id);
      } catch (startErr: any) {
        // Surface the partial outcome rather than pretending all is well.
        setLoading(false);
        // Distinguish a server-reported failure from a transport-level one.
        // A network/timeout abort has no `response`, and collapsing that case
        // into "unknown error" hid the fact that the run may well have
        // continued server-side.
        const detail = startErr?.response?.data?.detail;
        const reason = detail
          ? String(detail)
          : startErr?.code === 'ECONNABORTED'
            ? 'the request timed out before the server responded (the run may still be in progress)'
            : startErr?.message
              ? `no response from server (${startErr.message})`
              : 'unknown error';
        setError(
          `Assessment ${created.assessment_id} was created but could not be started: ` +
            `${reason}. ` +
            'Open it from the dashboard and retry execution.'
        );
        return;
      }

      if (onAssessmentCreated) {
        onAssessmentCreated(created.assessment_id);
      } else {
        window.location.href = `/assessments/${created.assessment_id}`;
      }
    } catch (err: any) {
      console.error('Failed to create assessment:', err);
      setError(err?.response?.data?.detail || 'Failed to create assessment');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <h2 className="text-2xl font-bold text-white">New Assessment</h2>

      {error && (
        <div className="px-4 py-3 bg-red-600/20 border border-red-600/50 rounded-lg text-red-400">
          {error}
        </div>
      )}

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-cyborg-muted mb-1">
            Assessment Name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            placeholder="My Security Assessment"
            className="w-full px-4 py-2 bg-cyborg-card border border-cyborg-border rounded-lg
                       text-white placeholder-cyborg-muted focus:ring-2 focus:ring-cyborg-accent
                       focus:border-transparent transition-colors"
          />
        </div>

        {/* Mode toggle */}
        <div>
          <span className="block text-sm font-medium text-cyborg-muted mb-1">Targets</span>
          <div className="inline-flex rounded-lg overflow-hidden border border-cyborg-border">
            {(
              [
                ['single', 'Single Target'],
                ['multiple', 'Multiple Targets'],
              ] as [Mode, string][]
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                onClick={() => setMode(value)}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  mode === value
                    ? 'bg-cyborg-accent text-cyborg-dark'
                    : 'bg-cyborg-card text-cyborg-muted hover:text-white'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {mode === 'single' ? (
          <TargetInput value={singleTarget} onChange={setSingleTarget} />
        ) : (
          <div className="space-y-2">
            <FileInput
              label="Drop a targets .txt file here"
              fieldLabel="Choose targets file"
              acceptedTypes={['.txt']}
              fileName={targetsFileName}
              onFileChange={handleTargetsFile}
              onDrop={handleTargetsFile}
            />
            {entries.length > 0 && (
              <p className="text-sm text-cyborg-muted">
                Targets detected: <span className="text-white font-medium">{entries.length}</span>
              </p>
            )}
          </div>
        )}

        {/* Target preview. TargetInput renders its own compact preview card in
            single mode (entered -> normalized -> status -> changes), so the
            table is only needed for the multi-target review step. */}
        {mode === 'multiple' && effectiveEntries.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-cyborg-muted mb-1">
              Review targets
            </label>
            <TargetPreview entries={effectiveEntries} />
            {entries.some((e) => e.status === 'VALID') && (
              <div className="mt-2 flex flex-wrap gap-2">
                {entries
                  .map((e, i) => ({ e, i }))
                  .filter(({ e }) => e.status === 'VALID' || e.status === 'INVALID')
                  .map(({ e, i }) => (
                    <button
                      key={e.id}
                      type="button"
                      onClick={() => setEntries((prev) => prev.filter((_, idx) => idx !== i))}
                      className="px-2 py-0.5 bg-cyborg-card border border-cyborg-border
                                 text-cyborg-muted text-xs rounded hover:border-red-500
                                 hover:text-red-400 transition-colors"
                    >
                      remove {e.normalized || e.raw}
                    </button>
                  ))}
              </div>
            )}
          </div>
        )}

        {/* Scope */}
        <div>
          <label className="block text-sm font-medium text-cyborg-muted mb-1">
            Authorized Scope
          </label>
          <p className="text-xs text-cyborg-muted/70 mb-2">
            {scopePatterns.length > 0
              ? `Using ${scopePatterns.length} pattern(s) from ${scopeFileName}.`
              : `Defaults to the ${submittable.length} target domain(s) above. ` +
                'Upload a scope file to restrict or extend it. ' +
                'Only hosts covered by scope are scanned.'}
          </p>
          <FileInput
            label="Optional scope .txt file"
            fieldLabel="Choose scope file"
            acceptedTypes={['.txt']}
            fileName={scopeFileName}
            onFileChange={handleScopeFile}
            onDrop={handleScopeFile}
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-cyborg-muted mb-1">Profile</label>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value as 'standard' | 'quick')}
            className="w-full px-4 py-2 bg-cyborg-card border border-cyborg-border rounded-lg
                       text-white focus:ring-2 focus:ring-cyborg-accent focus:border-transparent
                       transition-colors"
          >
            <option value="standard">Standard (Full Assessment)</option>
            <option value="quick">Quick (Speed Optimized)</option>
          </select>
        </div>
      </div>

      <div className="flex space-x-3">
        <button
          type="submit"
          disabled={!canSubmit}
          className="flex-1 px-4 py-2 bg-cyborg-accent text-cyborg-dark font-medium rounded-lg
                     hover:bg-cyborg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed
                     transition-colors"
        >
          {loading
            ? 'Starting...'
            : `Start Assessment (${submittable.length} target${submittable.length === 1 ? '' : 's'})`}
        </button>
      </div>

      {hasInvalid && (
        <p className="text-xs text-amber-400">
          Invalid targets will be skipped. Remove them if that is not intended.
        </p>
      )}
    </form>
  );
}
