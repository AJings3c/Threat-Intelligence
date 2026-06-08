import { describe, it, expect } from 'vitest';
import { dedupeIndicators, scoreConfidence } from '../src/correlate.js';
import type { ThreatIndicator } from '../src/types.js';

function ind(over: Partial<ThreatIndicator>): ThreatIndicator {
  return {
    id: over.id ?? 'x',
    source: over.source ?? 'feodo',
    type: over.type ?? 'c2_server',
    indicator: over.indicator ?? '1.2.3.4',
    indicatorType: over.indicatorType ?? 'ip',
    severity: over.severity ?? 'medium',
    tags: over.tags ?? [],
    ...over,
  };
}

describe('scoreConfidence', () => {
  it('rises with independent corroborating sources', () => {
    expect(scoreConfidence(['feodo'], 'medium')).toBeLessThan(scoreConfidence(['feodo', 'urlhaus'], 'medium'));
    expect(scoreConfidence(['feodo', 'urlhaus'], 'medium')).toBeLessThan(
      scoreConfidence(['feodo', 'urlhaus', 'cisa_kev'], 'medium'),
    );
  });

  it('treats CISA KEV as authoritative and caps at 100', () => {
    expect(scoreConfidence(['cisa_kev'], 'low')).toBeGreaterThan(scoreConfidence(['feodo'], 'low'));
    expect(scoreConfidence(['feodo', 'urlhaus', 'cisa_kev'], 'critical')).toBe(100);
  });
});

describe('dedupeIndicators', () => {
  it('collapses the same indicator across sources, merging sources/tags and raising severity', () => {
    const out = dedupeIndicators([
      ind({ id: 'a', source: 'feodo', indicator: '1.2.3.4', severity: 'medium', tags: ['c2'] }),
      ind({ id: 'b', source: 'urlhaus', indicator: '1.2.3.4', severity: 'high', tags: ['malware'] }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].sources?.sort()).toEqual(['feodo', 'urlhaus']);
    expect(out[0].severity).toBe('high');
    expect(out[0].tags.sort()).toEqual(['c2', 'malware']);
    expect(out[0].confidence).toBe(scoreConfidence(['feodo', 'urlhaus'], 'high'));
    expect(out[0].sourceReliability).toBe('A');
    expect(out[0].tlp).toBe('clear');
  });

  it('keeps distinct indicators separate and normalizes case', () => {
    const out = dedupeIndicators([
      ind({ id: 'a', indicator: 'evil.com', indicatorType: 'domain' }),
      ind({ id: 'b', indicator: 'EVIL.COM', indicatorType: 'domain', source: 'urlhaus' }),
      ind({ id: 'c', indicator: '9.9.9.9' }),
    ]);
    expect(out).toHaveLength(2);
    const domain = out.find((o) => o.indicatorType === 'domain');
    expect(domain?.sources?.sort()).toEqual(['feodo', 'urlhaus']);
  });
});
