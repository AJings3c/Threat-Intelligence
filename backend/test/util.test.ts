import { describe, it, expect } from 'vitest';
import { cvssToSeverity, errorMessage, extractToken } from '../src/util.js';

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
  it('reads a Bearer token, falling back to header then query', () => {
    expect(extractToken('Bearer abc', undefined, undefined)).toBe('abc');
    expect(extractToken(undefined, 'hdr', undefined)).toBe('hdr');
    expect(extractToken(undefined, undefined, 'qry')).toBe('qry');
  });

  it('prefers Authorization over header over query', () => {
    expect(extractToken('Bearer a', 'b', 'c')).toBe('a');
    expect(extractToken(undefined, 'b', 'c')).toBe('b');
  });

  it('returns empty string when nothing is provided or scheme is wrong', () => {
    expect(extractToken(undefined, undefined, undefined)).toBe('');
    expect(extractToken('Basic xyz', undefined, undefined)).toBe('');
  });
});
