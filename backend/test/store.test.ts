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
vi.mock('../src/geo.js', () => ({
  geolocate: vi.fn(async () => new Map()),
  isIpv4: vi.fn((v: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(v)),
}));

import { store } from '../src/store.js';
import { fetchCisaKev } from '../src/sources/cisaKev.js';
import { fetchFeodo } from '../src/sources/feodo.js';
import { fetchUrlhaus } from '../src/sources/urlhaus.js';
import { fetchNvd } from '../src/sources/nvd.js';
import type { ThreatIndicator, CveItem, FetchResult } from '../src/types.js';

const mockKev = fetchCisaKev as ReturnType<typeof vi.fn>;
const mockFeodo = fetchFeodo as ReturnType<typeof vi.fn>;
const mockUrlhaus = fetchUrlhaus as ReturnType<typeof vi.fn>;
const mockNvd = fetchNvd as ReturnType<typeof vi.fn>;

function indicator(id: string, source: 'cisa_kev' | 'feodo' | 'urlhaus'): ThreatIndicator {
  return {
    id,
    source,
    type: 'c2_server',
    indicator: '1.2.3.4',
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

function fail<T>(): FetchResult<T> {
  return { items: [], fetchedAt: Date.now(), error: 'HTTP 503' };
}

beforeEach(() => {
  vi.clearAllMocks();
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

    await store.refresh();
    const { cves } = store.getCves();
    const matched = cves.find((c) => c.id === 'CVE-2025-1234')!;
    const unmatched = cves.find((c) => c.id === 'CVE-2025-9999')!;
    expect(matched.knownExploited).toBe(true);
    expect(matched.severity).toBe('high');
    expect(unmatched.knownExploited).toBe(false);
  });
});
