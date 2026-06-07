import { describe, it, expect } from 'vitest';
import { clampLimit, MAX_QUERY_LIMIT } from '../src/store.js';

describe('clampLimit', () => {
  it('returns the fallback for undefined / non-finite / non-positive input', () => {
    expect(clampLimit(undefined, 500)).toBe(500);
    expect(clampLimit(Number.NaN, 500)).toBe(500);
    expect(clampLimit(0, 60)).toBe(60);
    expect(clampLimit(-10, 60)).toBe(60);
  });

  it('passes through valid limits and floors fractional values', () => {
    expect(clampLimit(120, 500)).toBe(120);
    expect(clampLimit(120.9, 500)).toBe(120);
  });

  it('caps at the hard maximum', () => {
    expect(clampLimit(1_000_000, 500)).toBe(MAX_QUERY_LIMIT);
    expect(clampLimit(MAX_QUERY_LIMIT + 1, 500)).toBe(MAX_QUERY_LIMIT);
  });
});
