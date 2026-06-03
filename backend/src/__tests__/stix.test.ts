import { describe, it, expect } from 'vitest';
import { toStixBundle } from '../stix.js';
import type { ThreatIndicator, CveItem } from '../types.js';

const ip: ThreatIndicator = {
  id: 'feodo:1.2.3.4:443',
  source: 'feodo',
  type: 'c2_server',
  indicator: '1.2.3.4',
  indicatorType: 'ip',
  severity: 'high',
  title: 'Emotet C2 server',
  tags: ['Emotet'],
};

const kev: ThreatIndicator = {
  id: 'kev:CVE-2024-0001',
  source: 'cisa_kev',
  type: 'exploited_vuln',
  indicator: 'CVE-2024-0001',
  indicatorType: 'cve',
  severity: 'critical',
  tags: [],
};

const cve: CveItem = {
  id: 'CVE-2024-9999',
  source: 'nvd',
  title: 'CVE-2024-9999',
  description: 'Critical',
  severity: 'critical',
  cvssScore: 9.8,
  reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-9999',
  knownExploited: false,
};

describe('toStixBundle', () => {
  it('produces a STIX 2.1 bundle with indicator and vulnerability objects', () => {
    const bundle = toStixBundle([ip, kev], [cve]);
    expect(bundle.type).toBe('bundle');
    expect(bundle.id.startsWith('bundle--')).toBe(true);

    const indicatorObj = bundle.objects.find((o) => o.type === 'indicator');
    expect(indicatorObj?.pattern).toBe("[ipv4-addr:value = '1.2.3.4']");
    expect(indicatorObj?.spec_version).toBe('2.1');

    // cve-typed indicator and the standalone CVE both become vulnerability SDOs.
    const vulns = bundle.objects.filter((o) => o.type === 'vulnerability');
    expect(vulns).toHaveLength(2);
    expect(vulns.every((v) => Array.isArray(v.external_references))).toBe(true);
  });

  it('escapes single quotes in URL patterns', () => {
    const url: ThreatIndicator = {
      id: 'urlhaus:1',
      source: 'urlhaus',
      type: 'malicious_url',
      indicator: "http://bad.example/it's",
      indicatorType: 'url',
      severity: 'high',
      tags: [],
    };
    const bundle = toStixBundle([url], []);
    const obj = bundle.objects[0];
    expect(obj.pattern).toBe("[url:value = 'http://bad.example/it\\'s']");
  });

  it('generates deterministic ids for the same indicator', () => {
    const a = toStixBundle([ip], []).objects[0].id;
    const b = toStixBundle([ip], []).objects[0].id;
    expect(a).toBe(b);
  });
});
