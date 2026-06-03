import { describe, it, expect } from 'vitest';
import { collectNewAlerts } from '../notify/collect.js';
import type { ThreatIndicator, CveItem } from '../types.js';

function indicator(over: Partial<ThreatIndicator> & Pick<ThreatIndicator, 'id'>): ThreatIndicator {
  return {
    id: over.id,
    source: over.source ?? 'feodo',
    type: over.type ?? 'c2_server',
    indicator: over.indicator ?? '1.1.1.1',
    indicatorType: over.indicatorType ?? 'ip',
    severity: over.severity ?? 'high',
    tags: over.tags ?? [],
    ...over,
  };
}

const cve: CveItem = {
  id: 'CVE-2024-9999',
  source: 'nvd',
  title: 'CVE-2024-9999',
  description: 'Critical bug',
  severity: 'critical',
  reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-9999',
  knownExploited: false,
};

describe('collectNewAlerts', () => {
  it('filters out items below the minimum severity', () => {
    const items = collectNewAlerts({
      indicators: [
        indicator({ id: 'a', severity: 'low' }),
        indicator({ id: 'b', severity: 'critical' }),
      ],
      cves: [],
      seen: new Set(),
      minSeverity: 'high',
      sources: null,
    });
    expect(items.map((i) => i.id)).toEqual(['b']);
  });

  it('skips items already in the seen set (dedup / baseline priming)', () => {
    const items = collectNewAlerts({
      indicators: [indicator({ id: 'a' }), indicator({ id: 'b' })],
      cves: [],
      seen: new Set(['a']),
      minSeverity: 'low',
      sources: null,
    });
    expect(items.map((i) => i.id)).toEqual(['b']);
  });

  it('applies the source allow-list to both indicators and CVEs', () => {
    const items = collectNewAlerts({
      indicators: [
        indicator({ id: 'feodo-1', source: 'feodo' }),
        indicator({ id: 'kev-1', source: 'cisa_kev', type: 'exploited_vuln' }),
      ],
      cves: [cve],
      seen: new Set(),
      minSeverity: 'low',
      sources: ['feodo'],
    });
    // Only the feodo indicator passes; cisa_kev indicator and nvd CVE are excluded.
    expect(items.map((i) => i.id)).toEqual(['feodo-1']);
  });

  it('includes CVEs and orders results highest severity first', () => {
    const items = collectNewAlerts({
      indicators: [indicator({ id: 'med', severity: 'medium' })],
      cves: [cve],
      seen: new Set(),
      minSeverity: 'low',
      sources: null,
    });
    expect(items[0].id).toBe('CVE-2024-9999');
    expect(items[0].severity).toBe('critical');
    expect(items.map((i) => i.id)).toContain('med');
  });
});
