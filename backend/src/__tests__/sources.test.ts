import { describe, it, expect } from 'vitest';
import { normalizeCisaKev } from '../sources/cisaKev.js';
import { normalizeFeodo } from '../sources/feodo.js';
import { normalizeUrlhaus } from '../sources/urlhaus.js';
import { normalizeNvd } from '../sources/nvd.js';

describe('normalizeCisaKev', () => {
  it('maps fields and flags ransomware as critical', () => {
    const [a, b] = normalizeCisaKev({
      vulnerabilities: [
        {
          cveID: 'CVE-2024-0001',
          vendorProject: 'Acme',
          product: 'Widget',
          vulnerabilityName: 'Acme Widget RCE',
          dateAdded: '2024-01-10',
          shortDescription: 'Remote code execution.',
          knownRansomwareCampaignUse: 'Known',
        },
        {
          cveID: 'CVE-2024-0002',
          vendorProject: 'Globex',
          product: 'Gadget',
          vulnerabilityName: 'Globex Gadget XSS',
          dateAdded: '2024-02-20',
          shortDescription: 'Stored XSS.',
          knownRansomwareCampaignUse: 'Unknown',
        },
      ],
    });

    // Sorted most-recent first, so CVE-2024-0002 comes first.
    expect(a.id).toBe('kev:CVE-2024-0002');
    expect(a.severity).toBe('high');
    expect(a.indicatorType).toBe('cve');

    expect(b.id).toBe('kev:CVE-2024-0001');
    expect(b.severity).toBe('critical');
    expect(b.tags).toContain('ransomware');
    expect(b.reference).toBe('https://nvd.nist.gov/vuln/detail/CVE-2024-0001');
  });

  it('respects the limit and tolerates missing vulnerabilities', () => {
    expect(normalizeCisaKev({ vulnerabilities: [] })).toEqual([]);
    const many = Array.from({ length: 5 }, (_, i) => ({
      cveID: `CVE-2024-00${i}`,
      vendorProject: 'V',
      product: 'P',
      vulnerabilityName: 'N',
      dateAdded: `2024-01-0${i}`,
      shortDescription: 'D',
    }));
    expect(normalizeCisaKev({ vulnerabilities: many }, 2)).toHaveLength(2);
  });
});

describe('normalizeFeodo', () => {
  it('builds c2_server indicators with composite id', () => {
    const [item] = normalizeFeodo([
      {
        ip_address: '1.2.3.4',
        port: 443,
        status: 'online',
        country: 'US',
        as_name: 'EXAMPLE-AS',
        first_seen: '2024-01-01 00:00:00',
        last_online: '2024-01-02 00:00:00',
        malware: 'Emotet',
      },
    ]);
    expect(item.id).toBe('feodo:1.2.3.4:443');
    expect(item.type).toBe('c2_server');
    expect(item.indicatorType).toBe('ip');
    expect(item.malwareFamily).toBe('Emotet');
    expect(item.tags).toEqual(['Emotet', 'online', 'EXAMPLE-AS']);
  });

  it('defaults port to 0 and tolerates empty input', () => {
    expect(normalizeFeodo([])).toEqual([]);
    const [item] = normalizeFeodo([{ ip_address: '9.9.9.9' }]);
    expect(item.id).toBe('feodo:9.9.9.9:0');
    expect(item.title).toBe('Botnet C2 server');
  });
});

describe('normalizeUrlhaus', () => {
  it('maps online/offline severity and takes the first entry per id', () => {
    const items = normalizeUrlhaus({
      '100': [
        {
          url: 'http://bad.example/payload',
          url_status: 'online',
          threat: 'malware_download',
          urlhaus_link: 'https://urlhaus.abuse.ch/url/100/',
          reporter: 'tester',
          tags: ['exe'],
        },
      ],
      '101': [
        {
          url: 'http://old.example/x',
          url_status: 'offline',
          threat: 'malware_download',
        },
      ],
    });
    const online = items.find((i) => i.id === 'urlhaus:100');
    const offline = items.find((i) => i.id === 'urlhaus:101');
    expect(online?.severity).toBe('high');
    expect(online?.tags).toContain('exe');
    expect(offline?.severity).toBe('medium');
  });

  it('honors the limit', () => {
    const data: Record<string, { url: string }[]> = {};
    for (let i = 0; i < 5; i++) data[String(i)] = [{ url: `http://e/${i}` }];
    expect(normalizeUrlhaus(data, 3)).toHaveLength(3);
  });
});

describe('normalizeNvd', () => {
  it('derives severity from CVSS and sorts newest first', () => {
    const items = normalizeNvd({
      vulnerabilities: [
        {
          cve: {
            id: 'CVE-2024-1000',
            published: '2024-01-01T00:00:00.000',
            descriptions: [{ lang: 'en', value: 'Low impact bug.' }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: 3.1 } }] },
          },
        },
        {
          cve: {
            id: 'CVE-2024-2000',
            published: '2024-05-01T00:00:00.000',
            descriptions: [{ lang: 'en', value: 'Critical RCE.' }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }] },
          },
        },
      ],
    });
    expect(items[0].id).toBe('CVE-2024-2000');
    expect(items[0].severity).toBe('critical');
    expect(items[1].severity).toBe('low');
    expect(items[0].knownExploited).toBe(false);
  });

  it('falls back to low severity and a default description', () => {
    const [item] = normalizeNvd({
      vulnerabilities: [{ cve: { id: 'CVE-2024-3000' } }],
    });
    expect(item.severity).toBe('low');
    expect(item.description).toBe('No description available.');
  });
});
