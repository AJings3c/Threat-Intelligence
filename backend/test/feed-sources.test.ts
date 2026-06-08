import { describe, expect, it, vi, afterEach } from 'vitest';
import { parseOpenPhishFeed } from '../src/sources/openphish.js';
import { parseMalwareBazaarSha256Feed } from '../src/sources/malwarebazaar.js';
import { parseThreatFoxResponse } from '../src/sources/threatfox.js';
import { parseSpamhausDropFeed } from '../src/sources/spamhausDrop.js';
import { parseDShieldBlockFeed } from '../src/sources/dshield.js';
import { fetchPhishTank, parsePhishTankFeed } from '../src/sources/phishtank.js';
import { fetchAbuseIpDb, parseAbuseIpDbBlacklist } from '../src/sources/abuseipdb.js';
import { fetchOtx, parseOtxPulses } from '../src/sources/otx.js';
import { fetchTaxiiImport, parseTaxiiObjects } from '../src/sources/taxiiImport.js';
import { fetchNvd } from '../src/sources/nvd.js';

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.PHISHTANK_APP_KEY;
  delete process.env.PHISHTANK_FEED_URL;
  delete process.env.ABUSEIPDB_API_KEY;
  delete process.env.ABUSEIPDB_API_BASE;
  delete process.env.OTX_API_KEY;
  delete process.env.OTX_API_BASE;
  delete process.env.TAXII_IMPORT_OBJECTS_URL;
  delete process.env.TAXII_IMPORT_BEARER_TOKEN;
});

describe('parseOpenPhishFeed', () => {
  it('maps valid phishing URLs and skips comments, duplicates, and invalid lines', () => {
    const items = parseOpenPhishFeed(
      ['# comment', 'https://phish.example/login', 'not a url', 'https://phish.example/login'].join('\n'),
      Date.UTC(2026, 5, 8),
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      source: 'openphish',
      type: 'phishing_url',
      indicator: 'https://phish.example/login',
      indicatorType: 'url',
      severity: 'high',
    });
  });
});

describe('parseMalwareBazaarSha256Feed', () => {
  it('maps valid SHA256 hashes and ignores malformed rows', () => {
    const hash = 'a'.repeat(64);
    const items = parseMalwareBazaarSha256Feed(`# sha256_hash\n${hash}\nnot-a-hash\n${hash}`);

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      id: `malwarebazaar:${hash}`,
      source: 'malwarebazaar',
      type: 'malicious_hash',
      indicatorType: 'hash',
      severity: 'high',
    });
  });
});

describe('parseThreatFoxResponse', () => {
  it('normalizes ip:port and hash indicators', () => {
    const items = parseThreatFoxResponse({
      '1': [
        {
          ioc_value: '1.2.3.4:443',
          ioc_type: 'ip:port',
          threat_type: 'botnet_cc',
          malware_printable: 'Mirai',
          confidence_level: 75,
          tags: 'c2,mirai',
          first_seen_utc: '2026-06-08 01:02:03',
        },
      ],
      '2': [
        {
          ioc_value: 'b'.repeat(64),
          ioc_type: 'sha256_hash',
          threat_type: 'payload',
          malware_printable: 'Loader',
          confidence_level: 95,
        },
      ],
    });

    expect(items).toHaveLength(2);
    expect(items.find((item) => item.id === 'threatfox:1')).toMatchObject({
      source: 'threatfox',
      type: 'c2_server',
      indicator: '1.2.3.4',
      indicatorType: 'ip',
      severity: 'high',
      tags: expect.arrayContaining(['port:443', 'Mirai']),
    });
    expect(items.find((item) => item.id === 'threatfox:2')).toMatchObject({
      type: 'malicious_hash',
      indicatorType: 'hash',
      severity: 'critical',
    });
  });
});

describe('parseSpamhausDropFeed', () => {
  it('maps newline-delimited DROP JSON into CIDR indicators', () => {
    const items = parseSpamhausDropFeed(
      [
        '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}',
        'not json',
        '{"cidr":"1.10.16.0/20","sblid":"duplicate"}',
      ].join('\n'),
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      id: 'spamhaus_drop:1.10.16.0/20',
      source: 'spamhaus_drop',
      type: 'malicious_network',
      indicator: '1.10.16.0/20',
      indicatorType: 'cidr',
      severity: 'high',
    });
  });
});

describe('parseDShieldBlockFeed', () => {
  it('maps tab-delimited block rows into scanner subnet indicators', () => {
    const items = parseDShieldBlockFeed(
      [
        '# comment',
        '45.205.1.0\t45.205.1.255\t24\t343\tMULTA-ASN1\tUS\tabuse@example.com',
      ].join('\n'),
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      id: 'dshield:45.205.1.0/24',
      source: 'dshield',
      type: 'scanner_network',
      indicator: '45.205.1.0/24',
      indicatorType: 'cidr',
      severity: 'high',
      country: 'US',
    });
  });
});

describe('parsePhishTankFeed', () => {
  it('maps verified online phishing rows and skips offline rows', () => {
    const items = parsePhishTankFeed([
      {
        phish_id: 123,
        url: 'https://phish.example/login',
        phish_detail_url: 'https://phishtank.org/phish_detail.php?phish_id=123',
        submission_time: '2026-06-08 01:02:03',
        verified: 'yes',
        verification_time: '2026-06-08 02:03:04',
        online: 'yes',
        target: 'Example Bank',
      },
      {
        phish_id: 456,
        url: 'https://offline.example/login',
        verified: 'yes',
        online: 'no',
      },
    ]);

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      id: 'phishtank:123',
      source: 'phishtank',
      type: 'phishing_url',
      indicator: 'https://phish.example/login',
      indicatorType: 'url',
      severity: 'high',
      tags: expect.arrayContaining(['phishing', 'phishtank', 'Example Bank']),
    });
  });
});

describe('fetchPhishTank', () => {
  it('returns empty results when no app key is configured', async () => {
    const result = await fetchPhishTank();
    expect(result.error).toBeNull();
    expect(result.items).toEqual([]);
  });
});

describe('parseAbuseIpDbBlacklist', () => {
  it('maps blacklist entries into IP indicators', () => {
    const items = parseAbuseIpDbBlacklist({
      data: [
        {
          ipAddress: '203.0.113.10',
          abuseConfidenceScore: 95,
          countryCode: 'US',
          usageType: 'Data Center/Web Hosting/Transit',
          isp: 'Example ISP',
          domain: 'example.net',
          lastReportedAt: '2026-06-08T01:02:03+00:00',
        },
      ],
    });

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      id: 'abuseipdb:203.0.113.10',
      source: 'abuseipdb',
      type: 'malware_host',
      indicator: '203.0.113.10',
      indicatorType: 'ip',
      severity: 'critical',
      country: 'US',
    });
  });
});

describe('fetchAbuseIpDb', () => {
  it('returns empty results when no API key is configured', async () => {
    const result = await fetchAbuseIpDb();
    expect(result.error).toBeNull();
    expect(result.items).toEqual([]);
  });
});

describe('parseOtxPulses', () => {
  it('maps pulse indicators into normalized indicators', () => {
    const items = parseOtxPulses({
      results: [
        {
          id: 'pulse-1',
          name: 'Example pulse',
          modified: '2026-06-08T00:00:00Z',
          tags: ['ransomware'],
          indicators: [
            { indicator: '203.0.113.20', type: 'IPv4', created: '2026-06-07T00:00:00Z' },
            { indicator: 'Example.COM', type: 'domain' },
            { indicator: 'a'.repeat(64), type: 'FileHash-SHA256' },
          ],
        },
      ],
    });

    expect(items).toHaveLength(3);
    expect(items[0]).toMatchObject({
      source: 'otx',
      indicator: '203.0.113.20',
      indicatorType: 'ip',
      severity: 'critical',
    });
    expect(items[1]).toMatchObject({ indicator: 'example.com', indicatorType: 'domain' });
    expect(items[2]).toMatchObject({ indicatorType: 'hash', type: 'malicious_hash' });
  });
});

describe('parseTaxiiObjects', () => {
  it('maps common STIX indicator patterns and vulnerabilities', () => {
    const items = parseTaxiiObjects({
      objects: [
        {
          type: 'indicator',
          id: 'indicator--1',
          pattern: "[ipv4-addr:value = '198.51.100.2']",
          name: 'Imported IP',
          confidence: 90,
        },
        {
          type: 'indicator',
          id: 'indicator--2',
          pattern: `[file:hashes.'SHA-256' = '${'b'.repeat(64)}']`,
          labels: ['malware'],
        },
        {
          type: 'vulnerability',
          id: 'vulnerability--1',
          name: 'CVE-2026-0002',
        },
      ],
    });

    expect(items).toHaveLength(3);
    expect(items[0]).toMatchObject({
      source: 'taxii_import',
      indicator: '198.51.100.2',
      indicatorType: 'ip',
      severity: 'high',
    });
    expect(items[1]).toMatchObject({ indicatorType: 'hash', type: 'malicious_hash' });
    expect(items[2]).toMatchObject({ indicator: 'CVE-2026-0002', indicatorType: 'cve' });
  });
});

describe('optional OTX/TAXII sources', () => {
  it('return empty results when credentials or endpoints are not configured', async () => {
    await expect(fetchOtx()).resolves.toMatchObject({ items: [], error: null });
    await expect(fetchTaxiiImport()).resolves.toMatchObject({ items: [], error: null });
  });
});

describe('fetchNvd EPSS enrichment', () => {
  it('adds EPSS fields when FIRST returns a score', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({
            vulnerabilities: [
              {
                cve: {
                  id: 'CVE-2026-0001',
                  published: '2026-06-08T00:00:00.000',
                  lastModified: '2026-06-08T00:00:00.000',
                  descriptions: [{ lang: 'en', value: 'Example CVE' }],
                  metrics: {
                    cvssMetricV31: [{ cvssData: { baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N' } }],
                  },
                },
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            data: [
              {
                cve: 'CVE-2026-0001',
                epss: '0.420000000',
                percentile: '0.930000000',
                date: '2026-06-07',
              },
            ],
          }),
        ),
    );

    const result = await fetchNvd();
    expect(result.error).toBeNull();
    expect(result.items[0]).toMatchObject({
      id: 'CVE-2026-0001',
      epssScore: 0.42,
      epssPercentile: 0.93,
      epssDate: '2026-06-07',
    });
  });
});
