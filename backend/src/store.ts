import type {
  ThreatIndicator,
  CveItem,
  SourceHealth,
  ThreatSource,
  Severity,
  ThreatType,
  FetchResult,
} from './types.js';
import { fetchCisaKev } from './sources/cisaKev.js';
import { fetchFeodo } from './sources/feodo.js';
import { fetchUrlhaus } from './sources/urlhaus.js';
import { fetchNvd } from './sources/nvd.js';
import { geolocate, isIpv4 } from './geo.js';

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
};

interface SourceState {
  // Timestamp of the last SUCCESSFUL fetch (drives staleness/age).
  fetchedAt: number | null;
  // Error from the most recent attempt (null when the last attempt succeeded).
  error: string | null;
  count: number;
}

// IOC feeds (everything except NVD, which produces standalone CVEs).
type IocSource = Exclude<ThreatSource, 'nvd'>;

class ThreatStore {
  private indicators: ThreatIndicator[] = [];
  private cves: CveItem[] = [];
  // Last-good items retained per source so a transient feed failure doesn't wipe data.
  private iocItems: Record<IocSource, ThreatIndicator[]> = {
    cisa_kev: [],
    feodo: [],
    urlhaus: [],
  };
  private state: Record<ThreatSource, SourceState> = {
    cisa_kev: { fetchedAt: null, error: null, count: 0 },
    feodo: { fetchedAt: null, error: null, count: 0 },
    urlhaus: { fetchedAt: null, error: null, count: 0 },
    nvd: { fetchedAt: null, error: null, count: 0 },
  };
  private refreshing = false;
  private lastRefresh = 0;

  get lastRefreshAt(): number {
    return this.lastRefresh;
  }

  get isReady(): boolean {
    return this.lastRefresh > 0;
  }

  async refresh(): Promise<void> {
    if (this.refreshing) return;
    this.refreshing = true;
    try {
      const [kev, feodo, urlhaus, nvd] = await Promise.all([
        fetchCisaKev(),
        fetchFeodo(),
        fetchUrlhaus(),
        fetchNvd(),
      ]);

      this.applyIocResult('cisa_kev', kev);
      this.applyIocResult('feodo', feodo);
      this.applyIocResult('urlhaus', urlhaus);
      this.applyCveResult(nvd);

      const indicators = [
        ...this.iocItems.cisa_kev,
        ...this.iocItems.feodo,
        ...this.iocItems.urlhaus,
      ];
      await this.enrichGeo(indicators);
      this.indicators = indicators;

      // Cross-mark CVEs already in CISA KEV as known-exploited.
      this.correlateKev();

      this.lastRefresh = Date.now();
    } finally {
      this.refreshing = false;
    }
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
      return {
        source,
        label: SOURCE_LABELS[source],
        ok: s.error === null && s.fetchedAt !== null,
        count: s.count,
        lastFetched: s.fetchedAt ? new Date(s.fetchedAt).toISOString() : null,
        lastError: s.error,
        ageMs: s.fetchedAt ? now - s.fetchedAt : null,
      };
    });
  }
}

export const store = new ThreatStore();
