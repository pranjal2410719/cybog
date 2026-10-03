/**
 * Assessment Creation Form — Perplexity parchment redesign
 *
 * - Hero-style section heading
 * - Pill chip mode selector (deep-teal active)
 * - Input-glow search-style fields
 * - Drag-drop file zones as ghost-card areas
 * - Ink-fill submit button
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

// ─── File drop zone ───────────────────────────────────────────────────────────

function FileInput({
  label,
  fieldLabel,
  acceptedTypes,
  onFileChange,
  onDrop,
  fileName,
}: {
  label: string;
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
    <div
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={`
        rounded-card border-2 border-dashed py-8 px-4 text-center
        transition-all duration-150
        ${isDragging
          ? 'border-deep-teal bg-[color-mix(in_oklch,#016a71_8%,#faf8f5)]'
          : 'border-warm-mist hover:border-ash'
        }
      `}
      style={{ background: isDragging ? undefined : '#fdfbfa' }}
    >
      {/* Upload icon */}
      <div className="mx-auto mb-3 w-10 h-10 rounded-card flex items-center justify-center"
           style={{ background: '#e8e5e0' }}>
        <svg className="w-5 h-5 text-graphite" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round"
            d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
        </svg>
      </div>

      {fileName ? (
        <p className="text-[14px] font-medium" style={{ color: '#016a71' }}>{fileName}</p>
      ) : (
        <p className="text-[14px] text-graphite">{label}</p>
      )}

      <label
        htmlFor={inputId}
        className="inline-block mt-3 px-3 py-1.5 text-[13px] text-graphite
                   border border-warm-mist rounded-btn cursor-pointer
                   hover:text-ink hover:border-ash transition-colors"
        style={{ background: '#faf8f5' }}
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
  );
}

// ─── Section label ────────────────────────────────────────────────────────────

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-[13px] text-graphite mb-1.5 font-medium">
      {children}
    </label>
  );
}

// ─── Main form ────────────────────────────────────────────────────────────────

export function AssessmentCreationForm({
  onAssessmentCreated,
}: {
  onAssessmentCreated?: (assessmentId: string) => void;
}) {
  const [mode, setMode] = useState<Mode>('single');
  const [name, setName] = useState('');
  const [profile, setProfile] = useState<'standard' | 'quick'>('standard');
  const [singleTarget, setSingleTarget] = useState('');
  const [entries, setEntries] = useState<TargetEntry[]>([]);
  const [targetsFileName, setTargetsFileName] = useState('');
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

      try {
        await api.startAssessment(created.assessment_id);
      } catch (startErr: any) {
        setLoading(false);
        const detail = startErr?.response?.data?.detail;
        const reason = detail
          ? String(detail)
          : startErr?.code === 'ECONNABORTED'
            ? 'the request timed out (the run may still be in progress)'
            : startErr?.message
              ? `no response from server (${startErr.message})`
              : 'unknown error';
        setError(
          `Assessment ${created.assessment_id} was created but could not be started: ` +
            `${reason}. Open it from the dashboard and retry.`
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
    <form onSubmit={handleSubmit} className="space-y-8">
      {/* Heading */}
      <div>
        <h2 className="text-[22px] font-medium text-ink">New Assessment</h2>
        <p className="text-[14px] text-graphite mt-1">
          Configure your scan target and start a security assessment pipeline.
        </p>
      </div>

      {/* Error banner */}
      {error && (
        <div
          className="px-4 py-3 rounded-card text-[14px]"
          style={{ background: '#fdf3f3', border: '1px solid #f5c6c6', color: '#c0392b' }}
        >
          {error}
        </div>
      )}

      <div className="space-y-6">
        {/* Name */}
        <div>
          <FieldLabel>Assessment Name</FieldLabel>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            placeholder="My Security Assessment"
            className="input-glow w-full px-4 py-2.5 rounded-input text-[16px] text-ink
                       placeholder-graphite outline-none"
            style={{ background: '#faf8f5' }}
          />
        </div>

        {/* Mode chips */}
        <div>
          <FieldLabel>Target Mode</FieldLabel>
          <div className="flex gap-2 flex-wrap">
            {(['single', 'multiple'] as Mode[]).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setMode(m)}
                className="px-4 py-1.5 rounded-chip text-[14px] font-normal transition-colors border"
                style={{
                  background: mode === m ? '#016a71' : 'transparent',
                  color: mode === m ? '#fff' : '#27251e',
                  borderColor: mode === m ? '#016a71' : '#d1d1cd',
                }}
              >
                {m === 'single' ? 'Single Target' : 'Multiple Targets'}
              </button>
            ))}
          </div>
        </div>

        {/* Target input */}
        {mode === 'single' ? (
          <TargetInput value={singleTarget} onChange={setSingleTarget} />
        ) : (
          <div className="space-y-2">
            <FileInput
              label="Drop a targets .txt file here, or click to browse"
              fieldLabel="Choose targets file"
              acceptedTypes={['.txt']}
              fileName={targetsFileName}
              onFileChange={handleTargetsFile}
              onDrop={handleTargetsFile}
            />
            {entries.length > 0 && (
              <p className="text-[13px] text-graphite">
                Targets detected:{' '}
                <span className="font-medium text-ink">{entries.length}</span>
              </p>
            )}
          </div>
        )}

        {/* Target preview table (multiple mode) */}
        {mode === 'multiple' && effectiveEntries.length > 0 && (
          <div>
            <FieldLabel>Review Targets</FieldLabel>
            <TargetPreview entries={effectiveEntries} />
            {entries.some((e) => e.status === 'VALID' || e.status === 'INVALID') && (
              <div className="mt-2 flex flex-wrap gap-2">
                {entries
                  .map((e, i) => ({ e, i }))
                  .filter(({ e }) => e.status === 'VALID' || e.status === 'INVALID')
                  .map(({ e, i }) => (
                    <button
                      key={e.id}
                      type="button"
                      onClick={() => setEntries((prev) => prev.filter((_, idx) => idx !== i))}
                      className="px-2 py-0.5 text-[12px] text-graphite border border-warm-mist
                                 rounded-btn hover:border-red-400 hover:text-red-500 transition-colors"
                      style={{ background: '#faf8f5' }}
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
          <FieldLabel>Authorized Scope</FieldLabel>
          <p className="text-[13px] text-graphite mb-2">
            {scopePatterns.length > 0
              ? `Using ${scopePatterns.length} pattern(s) from ${scopeFileName}.`
              : `Defaults to the ${submittable.length} target domain(s) above. Upload a scope file to restrict or extend.`}
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

        {/* Profile */}
        <div>
          <FieldLabel>Scan Profile</FieldLabel>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value as 'standard' | 'quick')}
            className="input-glow w-full px-4 py-2.5 rounded-input text-[14px] text-ink outline-none"
            style={{ background: '#faf8f5' }}
          >
            <option value="standard">Standard — Full Assessment</option>
            <option value="quick">Quick — Speed Optimized</option>
          </select>
        </div>
      </div>

      {/* Invalid warning */}
      {hasInvalid && (
        <p className="text-[12px]" style={{ color: '#c06000' }}>
          Invalid targets will be skipped. Remove them if that is not intended.
        </p>
      )}

      {/* Submit */}
      <button
        type="submit"
        disabled={!canSubmit}
        className="w-full px-5 py-3 text-[15px] font-medium text-parchment
                   rounded-input transition-opacity disabled:opacity-40 disabled:cursor-not-allowed"
        style={{ background: '#27251e' }}
      >
        {loading
          ? 'Starting scan…'
          : `Start Assessment (${submittable.length} target${submittable.length === 1 ? '' : 's'})`}
      </button>
    </form>
  );
}
