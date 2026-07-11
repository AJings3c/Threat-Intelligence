import { describe, it, expect } from 'vitest';
import { cvssToSeverity, errorMessage, extractToken, fetchWithRetry } from '../src/util.js';

describe('cvssToSeverity', () => {
  it('maps CVSS bands to severities', () => {
    expect(cvssToSeverity(9.8)).toBe('critical');
    expect(cvssToSeverity(9.0)).toBe('critical');
    expect(cvssToSeverity(7.0)).toBe('high');
    expect(cvssToSeverity(8.9)).toBe('high');
    expect(cvssToSeverity(4.0)).toBe('medium');
    expect(cvssToSeverity(6.9)).toBe('medium');
    expect(cvssToSeverity(3.9)).toBe('low');
    expect(cvssToSeverity(0)).toBe('low');
  });

  it('defaults to low for missing / invalid scores', () => {
    expect(cvssToSeverity(undefined)).toBe('low');
    expect(cvssToSeverity(Number.NaN)).toBe('low');
  });
});

describe('errorMessage', () => {
  it('extracts message from Error and stringifies the rest', () => {
    expect(errorMessage(new Error('boom'))).toBe('boom');
    expect(errorMessage('plain')).toBe('plain');
    expect(errorMessage(42)).toBe('42');
  });
});

describe('extractToken', () => {
  it('reads a Bearer token, falling back to the API token header', () => {
    expect(extractToken('Bearer abc', undefined)).toBe('abc');
    expect(extractToken(undefined, 'hdr')).toBe('hdr');
  });

  it('prefers Authorization over the API token header', () => {
    expect(extractToken('Bearer a', 'b')).toBe('a');
    expect(extractToken(undefined, 'b')).toBe('b');
  });

  it('returns empty string when nothing is provided or scheme is wrong', () => {
    expect(extractToken(undefined, undefined)).toBe('');
    expect(extractToken('Basic xyz', undefined)).toBe('');
  });
});

describe('fetchWithRetry', () => {
  it('retries transient responses and honors Retry-After', async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async () => {
      calls += 1;
      return calls === 1
        ? new Response('busy', { status: 503, headers: { 'Retry-After': '0' } })
        : new Response('{}', { status: 200 });
    }) as typeof fetch;
    try {
      const response = await fetchWithRetry('https://example.test/feed', {}, 1000, 2);
      expect(response.status).toBe(200);
      expect(calls).toBe(2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
