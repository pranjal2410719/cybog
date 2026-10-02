/**
 * Target normalization, validation and TXT parsing.
 *
 * These are the functions that decide what actually gets scanned, so they are
 * tested directly rather than only through the UI.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  normalizeTarget,
  validateTarget,
  parseTargetsText,
  createTargetEntry,
  submittableTargets,
  buildTargetsContent,
  buildScopeContent,
  resetTargetIds,
} from '../components/TargetUtils';

beforeEach(() => resetTargetIds());

describe('normalizeTarget', () => {
  it('strips a URL scheme down to a bare host', () => {
    expect(normalizeTarget('https://example.com').normalized).toBe('example.com');
    expect(normalizeTarget('http://example.com').normalized).toBe('example.com');
  });

  it('strips path, query, fragment and port', () => {
    expect(normalizeTarget('https://example.com/admin?x=1#top').normalized).toBe('example.com');
    expect(normalizeTarget('example.com:8443').normalized).toBe('example.com');
    expect(normalizeTarget('https://example.com:8443/admin').normalized).toBe('example.com');
  });

  it('strips userinfo', () => {
    expect(normalizeTarget('https://user:pass@example.com/x').normalized).toBe('example.com');
  });

  it('lowercases and trims', () => {
    expect(normalizeTarget('  EXAMPLE.COM  ').normalized).toBe('example.com');
  });

  it('strips a trailing dot', () => {
    expect(normalizeTarget('example.com.').normalized).toBe('example.com');
  });

  it('records what it changed', () => {
    const { changes } = normalizeTarget('https://EXAMPLE.com/path');
    expect(changes.join(' ')).toMatch(/scheme/i);
    expect(changes.join(' ')).toMatch(/path/i);
  });

  it('reports no changes for an already-bare domain', () => {
    expect(normalizeTarget('example.com').changes).toEqual([]);
  });
});

describe('validateTarget', () => {
  it('accepts ordinary domains', () => {
    expect(validateTarget('example.com').valid).toBe(true);
    expect(validateTarget('sub.example.co.uk').valid).toBe(true);
    expect(validateTarget('my-site.example.com').valid).toBe(true);
  });

  it('rejects empty, whitespace and dotless input', () => {
    expect(validateTarget('').valid).toBe(false);
    expect(validateTarget('   ').valid).toBe(false);
    expect(validateTarget('localhost').valid).toBe(false);
  });

  it('rejects whitespace inside a value', () => {
    expect(validateTarget('exa mple.com').valid).toBe(false);
  });

  it('rejects an over-long name', () => {
    // 5 x 60-char labels + dots + ".com" = 308 chars, past the 253 limit.
    const long = `${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.${'d'.repeat(60)}.${'e'.repeat(60)}.com`;
    expect(validateTarget(long).valid).toBe(false);
  });

  it('accepts a name just under the length limit', () => {
    const ok = `${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.${'d'.repeat(57)}.com`;
    expect(ok.length).toBeLessThanOrEqual(253);
    expect(validateTarget(ok).valid).toBe(true);
  });

  it('rejects a numeric TLD and a bare IP', () => {
    expect(validateTarget('example.123').valid).toBe(false);
    expect(validateTarget('192.168.1.1').valid).toBe(false);
  });
});

describe('parseTargetsText', () => {
  it('parses a realistic manifest, dropping comments, blanks and duplicates', () => {
    const text = 'example.com\n# a comment\nexample.org\n\n  spaced.com  \nexample.com\n';
    const entries = parseTargetsText(text);

    // 3 unique + 1 duplicate, all shown to the user for review
    expect(entries).toHaveLength(4);
    expect(submittableTargets(entries).map((e) => e.normalized)).toEqual([
      'example.com',
      'example.org',
      'spaced.com',
    ]);
  });

  it('flags the later duplicate, not the first', () => {
    const entries = parseTargetsText('example.com\nEXAMPLE.com\n');
    expect(entries[0].duplicate).toBe(false);
    expect(entries[1].duplicate).toBe(true);
    expect(entries[1].status).toBe('VALID');
  });

  it('normalizes URLs so they are not dropped', () => {
    const entries = parseTargetsText('https://example.com/path\nhttps://example.com/\n');
    expect(submittableTargets(entries)).toHaveLength(1);
  });

  it('handles CRLF and CR line endings', () => {
    const entries = parseTargetsText('example.com\r\nexample.org\rexample.net');
    expect(submittableTargets(entries)).toHaveLength(3);
  });

  it('returns an empty list for empty input', () => {
    expect(parseTargetsText('')).toEqual([]);
  });

  it('marks garbage INVALID rather than dropping it silently', () => {
    const entries = parseTargetsText('not a domain\n');
    expect(entries).toHaveLength(1);
    expect(entries[0].status).toBe('INVALID');
    expect(entries[0].reason).toBeTruthy();
  });
});

describe('buildTargetsContent', () => {
  /**
   * The backend decides whether `targets_file` is a path or inline content via
   * _is_file_content(), which only reports "content" for a value containing a
   * newline. A bare `example.com` would be read as a filesystem path and fail,
   * so every payload must be newline-terminated.
   */
  it('always ends with a newline so the backend treats it as content', () => {
    const entries = [createTargetEntry('example.com')];
    const content = buildTargetsContent(entries);
    expect(content).toBe('example.com\n');
    expect(content).toMatch(/\n$/);
    expect(content.split('\n').length).toBeGreaterThan(1);
  });

  it('emits one newline-delimited domain per valid unique target', () => {
    const entries = parseTargetsText('example.com\nexample.org\nexample.com\nbad line\n');
    expect(buildTargetsContent(entries)).toBe('example.com\nexample.org\n');
  });

  it('returns an empty string when nothing is submittable', () => {
    expect(buildTargetsContent(parseTargetsText('# only a comment\n'))).toBe('');
    expect(buildTargetsContent([])).toBe('');
  });
});

describe('buildScopeContent', () => {
  it('newline-terminates patterns for the same path-vs-content reason', () => {
    expect(buildScopeContent(['example.com', '*.example.org'])).toBe(
      'example.com\n*.example.org\n'
    );
  });
});
