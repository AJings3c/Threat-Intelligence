import { describe, expect, it } from 'vitest';
import { extractIocs } from '../src/iocExtract.js';

describe('IOC extraction', () => {
  it('refangs and extracts common deterministic IOC types', () => {
    const hash = 'a'.repeat(64);
    const results = extractIocs(
      `See hxxps[:]//evil[.]example/path, IP 203[.]0[.]113[.]9, ${hash}, and CVE-2026-12345.`,
    );

    expect(results).toEqual(
      expect.arrayContaining([
        { value: 'https://evil.example/path', indicatorType: 'url' },
        { value: 'evil.example', indicatorType: 'domain' },
        { value: '203.0.113.9', indicatorType: 'ip' },
        { value: hash, indicatorType: 'hash' },
        { value: 'CVE-2026-12345', indicatorType: 'cve' },
      ]),
    );
  });

  it('rejects invalid IPs, deduplicates values, and enforces a result cap', () => {
    const results = extractIocs('999.1.1.1 good.example good.example second.example', 1);
    expect(results).toEqual([{ value: 'good.example', indicatorType: 'domain' }]);
  });
});
