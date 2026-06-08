import type {
  ThreatIndicator,
  CveItem,
  SourceHealth,
  ThreatSource,
  Severity,
  ThreatType,
  FetchResult,
  MalwareFamilySummary,
} from './types.js';
import { fetchCisaKev } from './sources/cisaKev.js';
import { fetchFeodo } from './sources/feodo.js';
import { fetchUrlhaus } from './sources/urlhaus.js';
import { fetchNvd } from './sources/nvd.js';
import { fetchXRecentSearch } from './sources/x.js';
import { fetchFacebookPages } from './sources/facebook.js';
import { fetchOpenPhish } from './sources/openphish.js';
import { fetchThreatFox } from './sources/threatfox.js';
import { fetchMalwareBazaar } from './sources/malwarebazaar.js';
import { fetchSpamhausDrop } from './sources/spamhausDrop.js';
import { fetchDShield } from './sources/dshield.js';
import { fetchPhishTank } from './sources/phishtank.js';
import { fetchAbuseIpDb } from './sources/abuseipdb.js';
import { fetchOtx } from './sources/otx.js';
import { fetchTaxiiImport } from './sources/taxiiImport.js';
import { geolocate, isIpv4 } from './geo.js';
import { dedupeIndicators } from './correlate.js';
import { recordSeen, recordSnapshot, recordSourceHealthHistory } from './persist.js';
import { sourceProfile } from './sourceProfiles.js';

// Hard server-side cap so a client can't request an unbounded result set.
export const MAX_QUERY_LIMIT = 2000;

// Clamp a requested limit into [1, MAX_QUERY_LIMIT], falling back to a default.
export function clampLimit(limit: number | undefined, fallback: number): number {
  if (limit === undefined || !Number.isFinite(limit) || limit <= 0) return fallback;
  return Math.min(Math.floor(limit), MAX_QUERY_LIMIT);
}

export const SOURCE_LABELS: Record<ThreatSource, string> = {
  cisa_kev: 'CISA KEV',
  feodo: 'abuse.ch Feodo Tracker',
  urlhaus: 'abuse.ch URLhaus',
  nvd: 'NVD CVE',
  x: 'X Security Intel',
  facebook: 'Facebook Security Intel',
  openphish: 'OpenPhish',
  threatfox: 'abuse.ch ThreatFox',
  malwarebazaar: 'abuse.ch MalwareBazaar',
  spamhaus_drop: 'Spamhaus DROP',
  dshield: 'SANS ISC DShield',
  phishtank: 'PhishTank',
  abuseipdb: 'AbuseIPDB',
  otx: 'AlienVault OTX',
  taxii_import: 'External TAXII',
};

// IOC feeds (everything except NVD, which produces standalone CVEs).
type IocSource = Exclude<ThreatSource, 'nvd'>;

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

export const DEFAULT_SOURCE_REFRESH_INTERVAL_MS: Record<ThreatSource, number> = {
  cisa_kev: 2 * HOUR,
  feodo: 15 * MINUTE,
  urlhaus: 15 * MINUTE,
  nvd: HOUR,
  x: 15 * MINUTE,
  facebook: 15 * MINUTE,
  openphish: 5 * MINUTE,
  threatfox: 15 * MINUTE,
  malwarebazaar: 15 * MINUTE,
  spamhaus_drop: 6 * HOUR,
  dshield: HOUR,
  phishtank: HOUR,
  abuseipdb: 2 * HOUR,
  otx: HOUR,
  taxii_import: HOUR,
};

function emptyIocItems(): Record<IocSource, ThreatIndicator[]> {
  return {
    cisa_kev: [],
    feodo: [],
    urlhaus: [],
    x: [],
    facebook: [],
    openphish: [],
    threatfox: [],
    malwarebazaar: [],
    spamhaus_drop: [],
    dshield: [],
    phishtank: [],
    abuseipdb: [],
    otx: [],
    taxii_import: [],
  };
}

function emptySourceState(): Record<ThreatSource, SourceState> {
  return {
    cisa_kev: { fetchedAt: null, error: null, count: 0 },
    feodo: { fetchedAt: null, error: null, count: 0 },
    urlhaus: { fetchedAt: null, error: null, count: 0 },
    nvd: { fetchedAt: null, error: null, count: 0 },
    x: { fetchedAt: null, error: null, count: 0 },
    facebook: { fetchedAt: null, error: null, count: 0 },
    openphish: { fetchedAt: null, error: null, count: 0 },
    threatfox: { fetchedAt: null, error: null, count: 0 },
    malwarebazaar: { fetchedAt: null, error: null, count: 0 },
    spamhaus_drop: { fetchedAt: null, error: null, count: 0 },
    dshield: { fetchedAt: null, error: null, count: 0 },
    phishtank: { fetchedAt: null, error: null, count: 0 },
    abuseipdb: { fetchedAt: null, error: null, count: 0 },
    otx: { fetchedAt: null, error: null, count: 0 },
    taxii_import: { fetchedAt: null, error: null, count: 0 },
  };
}

export function sourceRefreshIntervalMs(source: ThreatSource): number {
  const envName = `REFRESH_${source.toUpperCase()}_INTERVAL_MS`;
  const raw = process.env[envName];
  if (raw !== undefined && raw.trim() !== '') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
  }
  if (process.env.NODE_ENV === 'test' || process.env.VITEST === 'true') return 0;
  return DEFAULT_SOURCE_REFRESH_INTERVAL_MS[source];
}

interface IocDescriptor {
  source: IocSource;
  fetch: () => Promise<FetchResult<ThreatIndicator>>;
}

const IOC_DESCRIPTORS: IocDescriptor[] = [
  { source: 'cisa_kev', fetch: fetchCisaKev },
  { source: 'feodo', fetch: fetchFeodo },
  { source: 'urlhaus', fetch: fetchUrlhaus },
  { source: 'x', fetch: fetchXRecentSearch },
  { source: 'facebook', fetch: fetchFacebookPages },
  { source: 'openphish', fetch: fetchOpenPhish },
  { source: 'threatfox', fetch: fetchThreatFox },
  { source: 'malwarebazaar', fetch: fetchMalwareBazaar },
  { source: 'spamhaus_drop', fetch: fetchSpamhausDrop },
  { source: 'dshield', fetch: fetchDShield },
  { source: 'phishtank', fetch: fetchPhishTank },
  { source: 'abuseipdb', fetch: fetchAbuseIpDb },
  { source: 'otx', fetch: fetchOtx },
  { source: 'taxii_import', fetch: fetchTaxiiImport },
];

interface SourceState {
  // Timestamp of the last SUCCESSFUL fetch (drives staleness/age).
  fetchedAt: number | null;
  // Error from the most recent attempt (null when the last attempt succeeded).
  error: string | null;
  count: number;
}

class ThreatStore {
  private indicators: ThreatIndicator[] = [];
  private cves: CveItem[] = [];
  // Last-good items retained per source so a transient feed failure doesn't wipe data.
  private iocItems: Record<IocSource, ThreatIndicator[]> = emptyIocItems();
  private state: Record<ThreatSource, SourceState> = emptySourceState();
  private refreshing = false;
  private lastRefresh = 0;
  // Listeners notified after each successful refresh (used for SSE streaming).
  private refreshListeners = new Set<() => void>();

  get lastRefreshAt(): number {
    return this.lastRefresh;
  }

  // Subscribe to refresh events. Returns an unsubscribe function.
  onRefresh(listener: () => void): () => void {
    this.refreshListeners.add(listener);
    return () => this.refreshListeners.delete(listener);
  }

  get isReady(): boolean {
    return this.lastRefresh > 0;
  }

  async refresh(): Promise<void> {
    if (this.refreshing) return;
    this.refreshing = true;
    try {
      const [iocResults, nvd] = await Promise.all([
        Promise.all(
          IOC_DESCRIPTORS.map(async (descriptor) => ({
            source: descriptor.source,
            result: await this.fetchIfDue(descriptor.source, descriptor.fetch),
          })),
        ),
        this.fetchIfDue('nvd', fetchNvd),
      ]);

      for (const { source, result } of iocResults) {
        if (result) this.applyIocResult(source, result);
      }
      if (nvd) this.applyCveResult(nvd);

      // Merge across sources so a repeated indicator becomes one record with a
      // corroboration-based confidence score instead of duplicate map points.
      const indicators = dedupeIndicators([
        ...this.iocItems.cisa_kev,
        ...this.iocItems.feodo,
        ...this.iocItems.urlhaus,
        ...this.iocItems.x,
        ...this.iocItems.facebook,
        ...this.iocItems.openphish,
        ...this.iocItems.threatfox,
        ...this.iocItems.malwarebazaar,
        ...this.iocItems.spamhaus_drop,
        ...this.iocItems.dshield,
        ...this.iocItems.phishtank,
        ...this.iocItems.abuseipdb,
        ...this.iocItems.otx,
        ...this.iocItems.taxii_import,
      ]);
      await this.enrichGeo(indicators);
      this.indicators = indicators;

      // Cross-mark CVEs already in CISA KEV as known-exploited.
      this.correlateKev();

      // Persist first/last-seen + a trend snapshot (no-op unless DATA_DIR is set).
      this.persistObservations();
      this.persistSourceHealth();

      this.lastRefresh = Date.now();
    } finally {
      this.refreshing = false;
    }
    for (const listener of this.refreshListeners) {
      try {
        listener();
      } catch {
        // a misbehaving listener must not break the refresh cycle
      }
    }
  }

  resetForTest(): void {
    this.indicators = [];
    this.cves = [];
    this.iocItems = emptyIocItems();
    this.state = emptySourceState();
    this.lastRefresh = 0;
    this.refreshing = false;
    this.refreshListeners.clear();
  }

  private shouldFetch(source: ThreatSource, now = Date.now()): boolean {
    const lastGood = this.state[source].fetchedAt;
    const minInterval = sourceRefreshIntervalMs(source);
    return lastGood === null || minInterval <= 0 || now - lastGood >= minInterval;
  }

  private async fetchIfDue<T>(
    source: ThreatSource,
    fetcher: () => Promise<FetchResult<T>>,
  ): Promise<FetchResult<T> | null> {
    if (!this.shouldFetch(source)) return null;
    return fetcher();
  }

  // Replace a source's retained items only when the fetch succeeded; otherwise keep
  // the last-good data and record the error so the source shows as stale, not empty.
  private applyIocResult(source: IocSource, result: FetchResult<ThreatIndicator>): void {
    if (result.error === null) {
      this.iocItems[source] = result.items;
      this.state[source] = { fetchedAt: result.fetchedAt, error: null, count: result.items.length };
    } else {
      this.state[source] = {
        fetchedAt: this.state[source].fetchedAt,
        error: result.error,
        count: this.iocItems[source].length,
      };
    }
  }

  private applyCveResult(result: FetchResult<CveItem>): void {
    if (result.error === null) {
      this.cves = result.items;
      this.state.nvd = { fetchedAt: result.fetchedAt, error: null, count: result.items.length };
    } else {
      this.state.nvd = {
        fetchedAt: this.state.nvd.fetchedAt,
        error: result.error,
        count: this.cves.length,
      };
    }
  }

  // Mark NVD CVEs that appear in the CISA KEV catalog as known-exploited and raise severity.
  private correlateKev(): void {
    const kevCves = new Set(this.iocItems.cisa_kev.map((t) => t.indicator));
    for (const c of this.cves) {
      if (kevCves.has(c.id)) {
        c.knownExploited = true;
        if (c.severity !== 'critical') c.severity = 'high';
      }
    }
  }

  private keyOf(t: ThreatIndicator): string {
    return `${t.indicatorType}:${t.indicator.toLowerCase()}`;
  }

  // Record observations and a severity snapshot. recordSeen returns the persisted
  // first-seen per key so firstSeen stays stable across restarts.
  private persistObservations(): void {
    const nowIso = new Date().toISOString();
    const firstSeen = recordSeen(
      this.indicators.map((t) => this.keyOf(t)),
      nowIso,
    );
    if (firstSeen.size > 0) {
      for (const t of this.indicators) {
        const seen = firstSeen.get(this.keyOf(t));
        if (!seen) continue;
        t.firstSeen = t.firstSeen && t.firstSeen < seen ? t.firstSeen : seen;
        t.lastSeen = nowIso;
      }
    }
    const sev = this.getStats().bySeverity;
    recordSnapshot({
      ts: Date.now(),
      total: this.indicators.length,
      critical: sev.critical ?? 0,
      high: sev.high ?? 0,
      medium: sev.medium ?? 0,
      low: sev.low ?? 0,
    });
  }

  private persistSourceHealth(): void {
    const ts = Date.now();
    recordSourceHealthHistory(
      this.getHealth().map((source) => ({
        ts,
        source: source.source,
        ok: source.ok,
        stale: source.stale,
        count: source.count,
        error: source.lastError,
      })),
    );
  }

  // Extract an IPv4 from an indicator for map plotting, then geolocate in bulk.
  private async enrichGeo(indicators: ThreatIndicator[]): Promise<void> {
    const ipFor = (t: ThreatIndicator): string | null => {
      if (t.indicatorType === 'ip' && isIpv4(t.indicator)) return t.indicator;
      if (t.indicatorType === 'url') {
        try {
          const host = new URL(t.indicator).hostname;
          return isIpv4(host) ? host : null;
        } catch {
          return null;
        }
      }
      return null;
    };

    const ips: string[] = [];
    for (const t of indicators) {
      const ip = ipFor(t);
      if (ip) ips.push(ip);
    }

    const geo = await geolocate(ips);
    for (const t of indicators) {
      const ip = ipFor(t);
      if (!ip) continue;
      const info = geo.get(ip);
      if (!info) continue;
      if (info.lat !== undefined && info.lon !== undefined) {
        t.lat = info.lat;
        t.lon = info.lon;
      }
      // Prefer the geolocation country name for consistency across feeds.
      if (info.country) t.country = info.country;
    }
  }

  queryThreats(opts: {
    source?: string;
    type?: string;
    severity?: string;
    q?: string;
    limit?: number;
  }): { threats: ThreatIndicator[]; total: number } {
    let list = this.indicators;
    if (opts.source) list = list.filter((t) => t.source === opts.source);
    if (opts.type) list = list.filter((t) => t.type === opts.type);
    if (opts.severity) list = list.filter((t) => t.severity === opts.severity);
    if (opts.q) {
      const q = opts.q.toLowerCase();
      list = list.filter(
        (t) =>
          t.indicator.toLowerCase().includes(q) ||
          (t.title ?? '').toLowerCase().includes(q) ||
          (t.malwareFamily ?? '').toLowerCase().includes(q) ||
          (t.country ?? '').toLowerCase().includes(q) ||
          t.tags.some((tag) => tag.toLowerCase().includes(q)),
      );
    }
    const total = list.length;
    const limit = clampLimit(opts.limit, 500);
    return { threats: list.slice(0, limit), total };
  }

  getCves(limit = 60): { cves: CveItem[]; total: number } {
    return { cves: this.cves.slice(0, clampLimit(limit, 60)), total: this.cves.length };
  }

  // Full snapshots used by the alert notifier (no limit applied).
  getIndicators(): ThreatIndicator[] {
    return this.indicators;
  }

  getAllCves(): CveItem[] {
    return this.cves;
  }

  getHashIntel(limit = 50): {
    hashes: ThreatIndicator[];
    total: number;
    families: MalwareFamilySummary[];
  } {
    const hashes = this.indicators
      .filter((t) => t.indicatorType === 'hash')
      .sort((a, b) => (b.lastSeen ?? b.firstSeen ?? '').localeCompare(a.lastSeen ?? a.firstSeen ?? ''));
    return {
      hashes: hashes.slice(0, clampLimit(limit, 50)),
      total: hashes.length,
      families: this.getMalwareFamilies(20),
    };
  }

  private getMalwareFamilies(limit = 20): MalwareFamilySummary[] {
    const byFamily = new Map<string, MalwareFamilySummary>();
    for (const t of this.indicators) {
      const family = t.malwareFamily?.trim();
      if (!family) continue;
      const existing =
        byFamily.get(family) ??
        ({
          family,
          count: 0,
          sources: [],
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          lastSeen: null,
        } satisfies MalwareFamilySummary);
      existing.count += 1;
      if (!existing.sources.includes(t.source)) existing.sources.push(t.source);
      existing[t.severity] += 1;
      const seen = t.lastSeen ?? t.firstSeen ?? null;
      if (seen && (!existing.lastSeen || seen > existing.lastSeen)) existing.lastSeen = seen;
      byFamily.set(family, existing);
    }
    return Array.from(byFamily.values())
      .sort((a, b) => b.count - a.count || (b.lastSeen ?? '').localeCompare(a.lastSeen ?? ''))
      .slice(0, clampLimit(limit, 20));
  }

  getMapPoints(): ThreatIndicator[] {
    return this.indicators.filter((t) => t.lat !== undefined && t.lon !== undefined);
  }

  getStats() {
    const bySource: Record<string, number> = {};
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const byCountry: Record<string, number> = {};

    for (const t of this.indicators) {
      bySource[t.source] = (bySource[t.source] ?? 0) + 1;
      byType[t.type] = (byType[t.type] ?? 0) + 1;
      bySeverity[t.severity] = (bySeverity[t.severity] ?? 0) + 1;
      if (t.country) byCountry[t.country] = (byCountry[t.country] ?? 0) + 1;
    }

    const topCountries = Object.entries(byCountry)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([country, count]) => ({ country, count }));

    return {
      totalIndicators: this.indicators.length,
      totalCves: this.cves.length,
      bySource: bySource as Record<ThreatSource, number>,
      byType: byType as Record<ThreatType, number>,
      bySeverity: bySeverity as Record<Severity, number>,
      topCountries,
      lastRefresh: this.lastRefresh,
    };
  }

  getHealth(): SourceHealth[] {
    const now = Date.now();
    return (Object.keys(this.state) as ThreatSource[]).map((source) => {
      const s = this.state[source];
      const ageMs = s.fetchedAt ? now - s.fetchedAt : null;
      const refreshIntervalMs = sourceRefreshIntervalMs(source);
      const stale = ageMs !== null && refreshIntervalMs > 0 && ageMs > refreshIntervalMs * 2;
      const deprecated = sourceProfile(source).deprecated;
      return {
        source,
        label: SOURCE_LABELS[source],
        ok: s.error === null && s.fetchedAt !== null,
        stale,
        deprecated: Boolean(deprecated),
        deprecationMessage: deprecated
          ? `${deprecated.message}${deprecated.replacement ? ` Replacement: ${deprecated.replacement}` : ''}`
          : undefined,
        count: s.count,
        lastFetched: s.fetchedAt ? new Date(s.fetchedAt).toISOString() : null,
        lastError: s.error,
        ageMs,
        refreshIntervalMs,
      };
    });
  }
}

export const store = new ThreatStore();
