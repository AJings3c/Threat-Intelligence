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

export const SOURCE_LABELS: Record<ThreatSource, string> = {
  cisa_kev: 'CISA KEV',
  feodo: 'abuse.ch Feodo Tracker',
  urlhaus: 'abuse.ch URLhaus',
  nvd: 'NVD CVE',
};

interface SourceState {
  fetchedAt: number | null;
  error: string | null;
  count: number;
}

// Indicator-producing sources (NVD feeds the separate CVE list).
type IndicatorSource = 'cisa_kev' | 'feodo' | 'urlhaus';

class ThreatStore {
  private indicators: ThreatIndicator[] = [];
  private cves: CveItem[] = [];
  // Per-source snapshots so a failing feed can fall back to its last good data.
  private sourceItems: Record<IndicatorSource, ThreatIndicator[]> = {
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

      // On a per-source failure, keep that source's previous data (stale fallback)
      // instead of dropping it, so one flaky feed can't blank the dashboard.
      this.applySource('cisa_kev', kev);
      this.applySource('feodo', feodo);
      this.applySource('urlhaus', urlhaus);
      if (nvd.error === null) this.cves = nvd.items;
      this.state.nvd = {
        fetchedAt: nvd.error === null ? nvd.fetchedAt : this.state.nvd.fetchedAt,
        error: nvd.error,
        count: nvd.error === null ? nvd.items.length : this.state.nvd.count,
      };

      const indicators = [
        ...this.sourceItems.cisa_kev,
        ...this.sourceItems.feodo,
        ...this.sourceItems.urlhaus,
      ];
      await this.enrichGeo(indicators);
      this.indicators = indicators;

      this.lastRefresh = Date.now();
    } finally {
      this.refreshing = false;
    }
  }

  // Replace a source's snapshot on success; on error retain the last good snapshot
  // and only surface the error in health (fetchedAt/count stay at last success).
  private applySource(source: IndicatorSource, result: FetchResult<ThreatIndicator>): void {
    if (result.error === null) {
      this.sourceItems[source] = result.items;
      this.state[source] = {
        fetchedAt: result.fetchedAt,
        error: null,
        count: result.items.length,
      };
    } else {
      this.state[source] = {
        fetchedAt: this.state[source].fetchedAt,
        error: result.error,
        count: this.state[source].count,
      };
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
    const limit = opts.limit ?? 500;
    return { threats: list.slice(0, limit), total };
  }

  getCves(limit = 60): { cves: CveItem[]; total: number } {
    return { cves: this.cves.slice(0, limit), total: this.cves.length };
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
