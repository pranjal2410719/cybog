/**
 * Target normalization, validation and TXT parsing helpers.
 *
 * These helpers are shared by the single-target input, the bulk upload list and
 * the preview table. They contain no scanner logic, no file-system access and
 * no network access — they only turn user text into the newline-delimited
 * domain list the backend's manifest loader expects.
 */

export type TargetStatus = 'VALID' | 'INVALID';

export interface TargetEntry {
  /** Stable React key. */
  id: string;
  /** Exactly what the user supplied (trimmed). */
  raw: string;
  /** Host after normalization; empty when nothing usable remained. */
  normalized: string;
  status: TargetStatus;
  /** Human-readable explanation shown next to an INVALID entry. */
  reason: string;
  /** True when this entry repeats an earlier entry and will not be submitted. */
  duplicate: boolean;
  /** Ordered list of normalizations that were applied, for UI disclosure. */
  changes: string[];
}

/**
 * Mirrors the backend manifest domain format: one or more dot-separated
 * alphanumeric/hyphen labels followed by an alphabetic TLD of 2-63 chars.
 * Matching it here means our VALID/INVALID badge predicts what the backend
 * will actually accept. The backend is still authoritative.
 */
const BACKEND_DOMAIN_RE =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

const MAX_HOST_LENGTH = 253;

let idCounter = 0;
function nextId(): string {
  idCounter += 1;
  return `target-${idCounter}`;
}

/** Reset the id sequence. Only used to keep preview keys stable in tests. */
export function resetTargetIds(): void {
  idCounter = 0;
}

export interface NormalizationResult {
  normalized: string;
  changes: string[];
}

/**
 * Reduce user input to a bare host suitable for the targets file.
 *
 * Steps, in order: trim, strip scheme, strip userinfo, strip path, strip
 * query/fragment, strip port, strip trailing dot, lowercase. Every step that
 * actually changed something is reported in `changes` so the UI can state
 * exactly what was rewritten.
 */
export function normalizeTarget(raw: string): NormalizationResult {
  const changes: string[] = [];
  let value = raw.trim();
  if (value !== raw) changes.push('trimmed surrounding whitespace');
  if (value === '') return { normalized: '', changes };

  const scheme = value.match(/^([a-zA-Z][a-zA-Z0-9+.\-]*):\/\//);
  if (scheme) {
    value = value.slice(scheme[0].length);
    changes.push(`removed scheme "${scheme[0]}"`);
  }

  const at = value.indexOf('@');
  const slash = value.indexOf('/');
  if (at > -1 && (slash === -1 || at < slash)) {
    value = value.slice(at + 1);
    changes.push('removed userinfo');
  }

  const pathAt = value.indexOf('/');
  if (pathAt > -1) {
    value = value.slice(0, pathAt);
    changes.push('removed path');
  }

  const queryAt = value.search(/[?#]/);
  if (queryAt > -1) {
    value = value.slice(0, queryAt);
    changes.push('removed query/fragment');
  }

  const port = value.match(/:(\d+)$/);
  if (port) {
    value = value.slice(0, value.length - port[0].length);
    changes.push(`removed port "${port[0]}"`);
  }

  if (value.endsWith('.')) {
    value = value.slice(0, -1);
    changes.push('removed trailing dot');
  }

  const lowered = value.toLowerCase();
  if (lowered !== value) {
    value = lowered;
    changes.push('lowercased');
  }

  return { normalized: value, changes };
}

export interface ValidationResult {
  valid: boolean;
  reason: string;
}

/** Client-side format check. UX only — the backend remains authoritative. */
export function validateTarget(normalized: string): ValidationResult {
  if (normalized === '') return { valid: false, reason: 'No target entered' };
  if (/\s/.test(normalized)) {
    return { valid: false, reason: 'Contains whitespace' };
  }
  if (normalized.length > MAX_HOST_LENGTH) {
    return { valid: false, reason: `Longer than ${MAX_HOST_LENGTH} characters` };
  }
  if (!normalized.includes('.')) {
    return { valid: false, reason: 'No dot — expected a domain with a TLD' };
  }
  if (BACKEND_DOMAIN_RE.test(normalized)) return { valid: true, reason: '' };

  const labels = normalized.split('.');
  const tld = labels[labels.length - 1];
  if (!/^[a-zA-Z]{2,63}$/.test(tld)) {
    return {
      valid: false,
      reason: 'Top-level domain must be 2-63 letters (a bare IP is not accepted)',
    };
  }
  const badLabel = labels.find(
    (label) => label.length === 0 || label.length > 63 || !/^[a-zA-Z0-9-]+$/.test(label)
  );
  if (badLabel !== undefined) {
    return { valid: false, reason: `Invalid domain label "${badLabel}"` };
  }
  return { valid: false, reason: 'Not a valid domain' };
}

/** Build a single entry from one raw string (no comment/blank handling). */
export function createTargetEntry(raw: string): TargetEntry {
  const { normalized, changes } = normalizeTarget(raw);
  const { valid, reason } = validateTarget(normalized);
  return {
    id: nextId(),
    raw: raw.trim(),
    normalized,
    status: valid ? 'VALID' : 'INVALID',
    reason: valid ? '' : reason,
    duplicate: false,
    changes,
  };
}

/**
 * Parse a newline-delimited target list.
 *
 * Rules: split on CRLF/CR/LF, trim each line, skip blank lines, skip lines
 * whose first non-space character is `#`. Inline `#` comments are NOT
 * stripped — a `#` inside a line makes that line invalid rather than silently
 * truncated. Duplicates are detected on the normalized (lowercased) form;
 * the later copy is flagged and excluded from the submitted file, the earlier
 * copy is kept in the order the user supplied.
 */
export function parseTargetsText(text: string): TargetEntry[] {
  const entries: TargetEntry[] = [];
  const seen = new Set<string>();

  for (const line of text.split(/\r\n|\r|\n/)) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    if (trimmed.startsWith('#')) continue;

    const entry = createTargetEntry(trimmed);
    if (entry.status === 'VALID' && seen.has(entry.normalized)) {
      entry.duplicate = true;
      entry.reason = 'Duplicate of an earlier target — will not be sent';
    } else if (entry.status === 'VALID') {
      seen.add(entry.normalized);
    }
    entries.push(entry);
  }

  return entries;
}

/** Entries that will actually be written to the targets file. */
export function submittableTargets(entries: TargetEntry[]): TargetEntry[] {
  return entries.filter((e) => e.status === 'VALID' && !e.duplicate);
}

/**
 * Render the targets file body.
 *
 * The trailing newline is REQUIRED, not cosmetic. The backend decides whether
 * `targets_file` is a path or inline content with `_is_file_content()`, which
 * only reports "content" for a value containing a newline, a backslash-free
 * path that is over 256 chars, or... never for a short bare string. A value
 * like `example.com` would be treated as a filesystem path and fail. Every
 * payload this form sends is therefore newline-terminated so it is
 * unambiguously content.
 */
export function buildTargetsContent(entries: TargetEntry[]): string {
  const domains = submittableTargets(entries).map((e) => e.normalized);
  return domains.length > 0 ? `${domains.join('\n')}\n` : '';
}

/**
 * Parse a scope list the same way as targets, but WITHOUT deduplication and
 * WITHOUT format validation. `!pattern` exclude lines are preserved verbatim;
 * the backend treats them as explicit excludes. Scope is a hard authorization
 * gate, so an empty scope file is rejected server-side.
 */
export function parseScopeText(text: string): string[] {
  return text
    .split(/\r\n|\r|\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'));
}

/** Render the scope file body. Newline-terminated for the same reason as targets. */
export function buildScopeContent(patterns: string[]): string {
  return patterns.length > 0 ? `${patterns.join('\n')}\n` : '';
}

/** One-line summary of what normalization changed, for UI disclosure. */
export function describeChanges(changes: string[]): string {
  return changes.length > 0 ? changes.join(', ') : 'none — already a bare domain';
}
