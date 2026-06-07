import { describe, it, expect } from 'vitest';
import { buildStixBundle, type StixObject } from '../src/stix.js';
import type { ThreatIndicator, CveItem } from '../src/types.js';

function ind(over: Partial<ThreatIndicator>): ThreatIndicator {
  return {
    id: over.id ?? 'x',
    source: over.source ?? 'feodo',
    type: over.type ?? 'c2_server',
    indicator: over.indicator ?? '1.2.3.4',
    indicatorType: over.indicatorType ?? 'ip',
    severity: over.severity ?? 'high',
    tags: over.tags ?? [],
    ...over,
  };
}

const cve: CveItem = {
  id: 'CVE-2025-0001',
  source: 'nvd',
  title: 'Example',
  description: 'desc',
  severity: 'high',
  reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0001',
  knownExploited: true,
};

describe('buildStixBundle', () => {
  it('emits a 2.1 bundle with indicator + vulnerability SDOs', () => {
    const bundle = buildStixBundle(
      [
        ind({ indicator: '1.2.3.4', indicatorType: 'ip', tags: ['c2'] }),
        ind({ indicator: 'evil.com', indicatorType: 'domain' }),
        ind({ indicator: 'http://bad/x', indicatorType: 'url' }),
      ],
      [cve],
    );
    expect(bundle.type).toBe('bundle');
    expect(bundle.id).toMatch(/^bundle--/);
    expect(bundle.objects.every((o: StixObject) => o.spec_version === '2.1')).toBe(true);

    const patterns = bundle.objects.filter((o) => o.type === 'indicator').map((o) => o.pattern);
    expect(patterns).toContain("[ipv4-addr:value = '1.2.3.4']");
    expect(patterns).toContain("[domain-name:value = 'evil.com']");
    expect(patterns).toContain("[url:value = 'http://bad/x']");

    const vuln = bundle.objects.find((o) => o.type === 'vulnerability');
    expect(vuln?.external_references).toEqual([{ source_name: 'cve', external_id: 'CVE-2025-0001' }]);
  });

  it('represents cve-type indicators as vulnerabilities and dedups against the CVE list', () => {
    const bundle = buildStixBundle(
      [ind({ indicator: 'CVE-2025-0001', indicatorType: 'cve', type: 'exploited_vuln', source: 'cisa_kev' })],
      [cve],
    );
    const vulns = bundle.objects.filter((o) => o.type === 'vulnerability');
    expect(vulns).toHaveLength(1);
    expect(bundle.objects.some((o) => o.type === 'indicator')).toBe(false);
  });
});
