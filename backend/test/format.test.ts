import { describe, it, expect } from 'vitest';
import { buildDigest, type AlertItem } from '../src/notify/format.js';

const at = new Date('2026-06-07T05:30:00.000Z');

const items: AlertItem[] = [
  {
    id: 'a',
    sourceLabel: 'CISA KEV',
    severity: 'critical',
    title: 'Example RCE',
    indicator: 'CVE-2026-0001',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
    country: 'US',
  },
  {
    id: 'b',
    sourceLabel: 'abuse.ch Feodo Tracker',
    severity: 'high',
    title: 'Botnet C2',
    indicator: '1.2.3.4',
  },
];

describe('buildDigest', () => {
  it('renders a titled markdown + text digest with one entry per item', () => {
    const d = buildDigest(items, at);
    expect(d.title).toBe('Threat Intel Alert · 2 new indicator(s)');
    expect(d.markdown).toContain('2026-06-07 05:30:00 UTC');
    expect(d.markdown).toContain('Example RCE');
    expect(d.markdown).toContain('[details](https://nvd.nist.gov/vuln/detail/CVE-2026-0001)');
    expect(d.text).toContain('1. [CRITICAL] Example RCE');
    expect(d.text).toContain('2. [HIGH] Botnet C2');
  });

  it('escapes markdown-significant characters in titles/indicators', () => {
    const d = buildDigest(
      [{ id: 'x', sourceLabel: 's', severity: 'low', title: 'a_b*c', indicator: 'x[y]' }],
      at,
    );
    expect(d.markdown).toContain('a\\_b\\*c');
    expect(d.markdown).toContain('x\\[y\\]');
  });
});
