import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock all source modules and geo to prevent any network I/O.
vi.mock('../src/sources/cisaKev.js', () => ({
  fetchCisaKev: vi.fn(),
}));
vi.mock('../src/sources/feodo.js', () => ({
  fetchFeodo: vi.fn(),
}));
vi.mock('../src/sources/urlhaus.js', () => ({
  fetchUrlhaus: vi.fn(),
}));
vi.mock('../src/sources/nvd.js', () => ({
  fetchNvd: vi.fn(),
}));
vi.mock('../src/sources/x.js', () => ({
  fetchXRecentSearch: vi.fn(),
}));
vi.mock('../src/sources/facebook.js', () => ({
  fetchFacebookPages: vi.fn(),
}));
vi.mock('../src/sources/openphish.js', () => ({
  fetchOpenPhish: vi.fn(),
}));
vi.mock('../src/sources/threatfox.js', () => ({
  fetchThreatFox: vi.fn(),
}));
vi.mock('../src/sources/malwarebazaar.js', () => ({
  fetchMalwareBazaar: vi.fn(),
}));
vi.mock('../src/sources/spamhausDrop.js', () => ({
  fetchSpamhausDrop: vi.fn(),
}));
vi.mock('../src/sources/dshield.js', () => ({
  fetchDShield: vi.fn(),
}));
vi.mock('../src/sources/phishtank.js', () => ({
  fetchPhishTank: vi.fn(),
}));
vi.mock('../src/sources/abuseipdb.js', () => ({
  fetchAbuseIpDb: vi.fn(),
}));
vi.mock('../src/sources/otx.js', () => ({
  fetchOtx: vi.fn(),
}));
vi.mock('../src/sources/taxiiImport.js', () => ({
  fetchTaxiiImport: vi.fn(),
}));
vi.mock('../src/geo.js', () => ({
  geolocate: vi.fn(async () => new Map()),
  isIpv4: vi.fn((v: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(v)),
}));

import { store } from '../src/store.js';
import { fetchCisaKev } from '../src/sources/cisaKev.js';
import { fetchFeodo } from '../src/sources/feodo.js';
import { fetchUrlhaus } from '../src/sources/urlhaus.js';
import { fetchNvd } from '../src/sources/nvd.js';
import { fetchXRecentSearch } from '../src/sources/x.js';
import { fetchFacebookPages } from '../src/sources/facebook.js';
import { fetchOpenPhish } from '../src/sources/openphish.js';
import { fetchThreatFox } from '../src/sources/threatfox.js';
import { fetchMalwareBazaar } from '../src/sources/malwarebazaar.js';
import { fetchSpamhausDrop } from '../src/sources/spamhausDrop.js';
import { fetchDShield } from '../src/sources/dshield.js';
import { fetchPhishTank } from '../src/sources/phishtank.js';
import { fetchAbuseIpDb } from '../src/sources/abuseipdb.js';
import { fetchOtx } from '../src/sources/otx.js';
import { fetchTaxiiImport } from '../src/sources/taxiiImport.js';
import type { ThreatIndicator, CveItem, FetchResult } from '../src/types.js';

const mockKev = fetchCisaKev as ReturnType<typeof vi.fn>;
const mockFeodo = fetchFeodo as ReturnType<typeof vi.fn>;
const mockUrlhaus = fetchUrlhaus as ReturnType<typeof vi.fn>;
const mockNvd = fetchNvd as ReturnType<typeof vi.fn>;
const mockX = fetchXRecentSearch as ReturnType<typeof vi.fn>;
const mockFacebook = fetchFacebookPages as ReturnType<typeof vi.fn>;
const mockOpenPhish = fetchOpenPhish as ReturnType<typeof vi.fn>;
const mockThreatFox = fetchThreatFox as ReturnType<typeof vi.fn>;
const mockMalwareBazaar = fetchMalwareBazaar as ReturnType<typeof vi.fn>;
const mockSpamhausDrop = fetchSpamhausDrop as ReturnType<typeof vi.fn>;
const mockDShield = fetchDShield as ReturnType<typeof vi.fn>;
const mockPhishTank = fetchPhishTank as ReturnType<typeof vi.fn>;
const mockAbuseIpDb = fetchAbuseIpDb as ReturnType<typeof vi.fn>;
const mockOtx = fetchOtx as ReturnType<typeof vi.fn>;
const mockTaxiiImport = fetchTaxiiImport as ReturnType<typeof vi.fn>;

// Distinct indicator value per id so cross-source dedup keeps them separate.
function indicator(id: string, source: ThreatIndicator['source']): ThreatIndicator {
  return {
    id,
    source,
    type: 'c2_server',
    indicator: `ip-${id}`,
    indicatorType: 'ip',
    severity: 'high',
    tags: [],
  };
}

function cve(id: string, score?: number): CveItem {
  return {
    id,
    source: 'nvd',
    title: id,
    description: 'desc',
    severity: score && score >= 9 ? 'critical' : score && score >= 7 ? 'high' : 'medium',
    cvssScore: score,
    reference: `https://nvd.nist.gov/vuln/detail/${id}`,
    knownExploited: false,
  };
}

function ok<T>(items: T[]): FetchResult<T> {
  return { items, fetchedAt: Date.now(), error: null };
}

function okAt<T>(items: T[], fetchedAt: number): FetchResult<T> {
  return { items, fetchedAt, error: null };
}

function fail<T>(): FetchResult<T> {
  return { items: [], fetchedAt: Date.now(), error: 'HTTP 503' };
}

beforeEach(() => {
  store.resetForTest();
  vi.clearAllMocks();
  delete process.env.REFRESH_FEODO_INTERVAL_MS;
  delete process.env.X_BEARER_TOKEN;
  delete process.env.FACEBOOK_ACCESS_TOKEN;
  delete process.env.FACEBOOK_PAGE_IDS;
  delete process.env.PHISHTANK_APP_KEY;
  delete process.env.ABUSEIPDB_API_KEY;
  delete process.env.OTX_API_KEY;
  delete process.env.TAXII_IMPORT_OBJECTS_URL;
  mockX.mockResolvedValue(ok([]));
  mockFacebook.mockResolvedValue(ok([]));
  mockOpenPhish.mockResolvedValue(ok([]));
  mockThreatFox.mockResolvedValue(ok([]));
  mockMalwareBazaar.mockResolvedValue(ok([]));
  mockSpamhausDrop.mockResolvedValue(ok([]));
  mockDShield.mockResolvedValue(ok([]));
  mockPhishTank.mockResolvedValue(ok([]));
  mockAbuseIpDb.mockResolvedValue(ok([]));
  mockOtx.mockResolvedValue(ok([]));
  mockTaxiiImport.mockResolvedValue(ok([]));
});

describe('ThreatStore resilience', () => {
  it('retains last-good data when a source fails on subsequent refresh', async () => {
    // First refresh: all succeed.
    mockKev.mockResolvedValue(ok([indicator('k1', 'cisa_kev')]));
    mockFeodo.mockResolvedValue(ok([indicator('f1', 'feodo')]));
    mockUrlhaus.mockResolvedValue(ok([indicator('u1', 'urlhaus')]));
    mockNvd.mockResolvedValue(ok([cve('CVE-1')]));

    await store.refresh();
    const after1 = store.queryThreats({});
    expect(after1.total).toBe(3);
    expect(store.getCves().total).toBe(1);

    // Second refresh: feodo and nvd fail.
    mockKev.mockResolvedValue(ok([indicator('k2', 'cisa_kev')]));
    mockFeodo.mockResolvedValue(fail<ThreatIndicator>());
    mockUrlhaus.mockResolvedValue(ok([indicator('u2', 'urlhaus')]));
    mockNvd.mockResolvedValue(fail<CveItem>());
    mockX.mockResolvedValue(ok([]));
    mockFacebook.mockResolvedValue(ok([]));

    await store.refresh();
    const after2 = store.queryThreats({});
    // feodo retains f1 from the previous good fetch.
    expect(after2.threats.some((t) => t.id === 'f1')).toBe(true);
    // kev and urlhaus updated to new data.
    expect(after2.threats.some((t) => t.id === 'k2')).toBe(true);
    expect(after2.threats.some((t) => t.id === 'u2')).toBe(true);
    // NVD retains the previous CVE.
    expect(store.getCves().total).toBe(1);

    // Health shows the failure.
    const health = store.getHealth();
    const feodoHealth = health.find((h) => h.source === 'feodo')!;
    expect(feodoHealth.ok).toBe(false);
    expect(feodoHealth.lastError).toBe('HTTP 503');
    expect(feodoHealth.count).toBe(1); // retained
  });

  it('skips a last-good source until its source-specific interval elapses', async () => {
    process.env.REFRESH_FEODO_INTERVAL_MS = String(60 * 60 * 1000);
    mockKev.mockResolvedValue(ok([]));
    mockFeodo.mockResolvedValue(ok([indicator('f-interval', 'feodo')]));
    mockUrlhaus.mockResolvedValue(ok([]));
    mockNvd.mockResolvedValue(ok([]));

    await store.refresh();
    expect(mockFeodo).toHaveBeenCalledTimes(1);
    expect(store.queryThreats({}).threats.some((t) => t.id === 'f-interval')).toBe(true);

    mockFeodo.mockResolvedValue(ok([indicator('f-new', 'feodo')]));
    await store.refresh();

    expect(mockFeodo).toHaveBeenCalledTimes(1);
    const threats = store.queryThreats({}).threats;
    expect(threats.some((t) => t.id === 'f-interval')).toBe(true);
    expect(threats.some((t) => t.id === 'f-new')).toBe(false);
  });

  it('marks a source stale when last-good data exceeds twice its refresh interval', async () => {
    process.env.REFRESH_FEODO_INTERVAL_MS = '1';
    mockKev.mockResolvedValue(ok([]));
    mockFeodo.mockResolvedValue(okAt([indicator('f-stale', 'feodo')], Date.now() - 10_000));
    mockUrlhaus.mockResolvedValue(ok([]));
    mockNvd.mockResolvedValue(ok([]));

    await store.refresh();

    const feodoHealth = store.getHealth().find((h) => h.source === 'feodo')!;
    expect(feodoHealth.ok).toBe(true);
    expect(feodoHealth.stale).toBe(true);
    expect(feodoHealth.refreshIntervalMs).toBe(1);
  });

  it('marks credentialed sources as disabled when required env vars are missing', async () => {
    mockKev.mockResolvedValue(ok([]));
    mockFeodo.mockResolvedValue(ok([]));
    mockUrlhaus.mockResolvedValue(ok([]));
    mockNvd.mockResolvedValue(ok([]));

    await store.refresh();

    const health = store.getHealth();
    const otx = health.find((h) => h.source === 'otx')!;
    expect(otx.status).toBe('disabled');
    expect(otx.ok).toBe(false);
    expect(otx.configured).toBe(false);
    expect(otx.requiredEnv).toContain('OTX_API_KEY');
  });
});

describe('ThreatStore hash intelligence', () => {
  it('returns hash indicators and malware-family aggregations', async () => {
    mockKev.mockResolvedValue(ok([]));
    mockFeodo.mockResolvedValue(ok([]));
    mockUrlhaus.mockResolvedValue(ok([]));
    mockNvd.mockResolvedValue(ok([]));
    mockMalwareBazaar.mockResolvedValue(
      ok([
        {
          ...indicator('hash-1', 'malwarebazaar'),
          type: 'malicious_hash',
          indicator: 'a'.repeat(64),
          indicatorType: 'hash',
          malwareFamily: 'ExampleLoader',
          severity: 'high',
        },
      ]),
    );
    mockThreatFox.mockResolvedValue(
      ok([
        {
          ...indicator('hash-2', 'threatfox'),
          type: 'malicious_hash',
          indicator: 'b'.repeat(64),
          indicatorType: 'hash',
          malwareFamily: 'ExampleLoader',
          severity: 'critical',
        },
      ]),
    );

    await store.refresh();
    const intel = store.getHashIntel();

    expect(intel.total).toBe(2);
    expect(intel.hashes.map((hash) => hash.indicatorType)).toEqual(['hash', 'hash']);
    expect(intel.families[0]).toMatchObject({
      family: 'ExampleLoader',
      count: 2,
      critical: 1,
      high: 1,
    });
  });
});

describe('ThreatStore KEV↔NVD correlation', () => {
  it('marks CVEs that appear in CISA KEV as known-exploited', async () => {
    const kevIndicator: ThreatIndicator = {
      id: 'kev:CVE-2025-1234',
      source: 'cisa_kev',
      type: 'exploited_vuln',
      indicator: 'CVE-2025-1234',
      indicatorType: 'cve',
      severity: 'high',
      tags: [],
    };
    mockKev.mockResolvedValue(ok([kevIndicator]));
    mockFeodo.mockResolvedValue(ok([]));
    mockUrlhaus.mockResolvedValue(ok([]));
    mockNvd.mockResolvedValue(ok([cve('CVE-2025-1234', 6.5), cve('CVE-2025-9999', 5.0)]));
    mockX.mockResolvedValue(ok([]));
    mockFacebook.mockResolvedValue(ok([]));

    await store.refresh();
    const { cves } = store.getCves();
    const matched = cves.find((c) => c.id === 'CVE-2025-1234')!;
    const unmatched = cves.find((c) => c.id === 'CVE-2025-9999')!;
    expect(matched.knownExploited).toBe(true);
    expect(matched.severity).toBe('high');
    expect(unmatched.knownExploited).toBe(false);
  });
});

describe('ThreatStore IOC investigation', () => {
  it('returns local matches, related indicators, and STRIDE scenarios', async () => {
    const family = 'ExampleLoader';
    mockKev.mockResolvedValue(ok([]));
    mockFeodo.mockResolvedValue(ok([]));
    mockUrlhaus.mockResolvedValue(ok([]));
    mockNvd.mockResolvedValue(ok([]));
    mockMalwareBazaar.mockResolvedValue(
      ok([
        {
          ...indicator('hash-exact', 'malwarebazaar'),
          type: 'malicious_hash',
          indicator: 'c'.repeat(64),
          indicatorType: 'hash',
          malwareFamily: family,
          severity: 'critical',
        },
        {
          ...indicator('hash-related', 'malwarebazaar'),
          type: 'malicious_hash',
          indicator: 'd'.repeat(64),
          indicatorType: 'hash',
          malwareFamily: family,
          severity: 'high',
        },
      ]),
    );

    await store.refresh();
    const result = store.investigateIndicator('c'.repeat(64));

    expect(result.indicatorType).toBe('hash');
    expect(result.exactMatches).toHaveLength(1);
    expect(result.relatedIndicators.some((item) => item.id === 'hash-related')).toBe(true);
    expect(result.model.posture).toBe('matched');
    expect(result.model.scenarios.some((scenario) => scenario.stride === 'Tampering')).toBe(true);

    const history = store.getInvestigationHistory();
    expect(history[0]).toMatchObject({
      indicator: 'c'.repeat(64),
      indicatorType: 'hash',
      posture: 'matched',
      exactCount: 1,
    });
  });

  it('relates domains to URL hosts when no exact indicator exists', async () => {
    mockKev.mockResolvedValue(ok([]));
    mockFeodo.mockResolvedValue(ok([]));
    mockUrlhaus.mockResolvedValue(
      ok([
        {
          ...indicator('url-related', 'urlhaus'),
          type: 'malicious_url',
          indicator: 'https://login.example.test/payload',
          indicatorType: 'url',
          severity: 'high',
          tags: ['phishing'],
        },
      ]),
    );
    mockNvd.mockResolvedValue(ok([]));

    await store.refresh();
    const result = store.investigateIndicator('example.test');

    expect(result.exactMatches).toHaveLength(0);
    expect(result.relatedIndicators.some((item) => item.id === 'url-related')).toBe(true);
    expect(result.model.posture).toBe('related_only');
    expect(result.model.scenarios.some((scenario) => scenario.stride === 'Spoofing')).toBe(true);
  });

  it('relates IP searches to matching CIDR indicators', async () => {
    mockKev.mockResolvedValue(ok([]));
    mockFeodo.mockResolvedValue(ok([]));
    mockUrlhaus.mockResolvedValue(ok([]));
    mockNvd.mockResolvedValue(ok([]));
    mockSpamhausDrop.mockResolvedValue(
      ok([
        {
          ...indicator('cidr-related', 'spamhaus_drop'),
          type: 'malicious_network',
          indicator: '203.0.113.0/24',
          indicatorType: 'cidr',
          severity: 'medium',
          tags: ['drop'],
        },
      ]),
    );

    await store.refresh();
    const result = store.investigateIndicator('203.0.113.42', 'ip');

    expect(result.exactMatches).toHaveLength(0);
    expect(result.relatedIndicators.some((item) => item.id === 'cidr-related')).toBe(true);
    expect(result.model.posture).toBe('related_only');
    expect(result.model.scenarios.some((scenario) => scenario.stride === 'Denial of Service')).toBe(true);
  });
});
