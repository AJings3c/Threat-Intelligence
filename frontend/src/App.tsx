import { useCallback, useEffect, useRef, useState } from 'react';
import type { CveItem, SourceHealth, Stats, ThreatIndicator, TrendPoint } from './types';
import { fetchCves, fetchHealth, fetchMap, fetchStats, fetchThreats, fetchTrend } from './api';
import { StatsCards } from './components/StatsCards';
import { ThreatMap } from './components/ThreatMap';
import { Filters, type FilterState } from './components/Filters';
import { ThreatTable } from './components/ThreatTable';
import { CvePanel } from './components/CvePanel';
import { SourceHealthBar } from './components/SourceHealthBar';
import { TrendChart } from './components/TrendChart';

const REFRESH_MS = 60_000;

export default function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [points, setPoints] = useState<ThreatIndicator[]>([]);
  const [cves, setCves] = useState<CveItem[]>([]);
  const [health, setHealth] = useState<SourceHealth[]>([]);
  const [trend, setTrend] = useState<{ enabled: boolean; points: TrendPoint[] }>({
    enabled: false,
    points: [],
  });
  const [threats, setThreats] = useState<ThreatIndicator[]>([]);
  const [total, setTotal] = useState(0);
  const [threatsLoading, setThreatsLoading] = useState(true);
  const [cvesLoading, setCvesLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [filters, setFilters] = useState<FilterState>({
    source: '',
    type: '',
    severity: '',
    q: '',
  });

  const loadOverview = useCallback(async () => {
    try {
      const [s, m, h, t] = await Promise.all([
        fetchStats(),
        fetchMap(),
        fetchHealth(),
        fetchTrend(),
      ]);
      setStats(s);
      setPoints(m.points);
      setHealth(h.sources);
      setTrend({ enabled: t.enabled, points: t.points });
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load overview');
    }
  }, []);

  const loadCves = useCallback(async () => {
    setCvesLoading(true);
    try {
      const res = await fetchCves(40);
      setCves(res.cves);
    } catch {
      // non-fatal
    } finally {
      setCvesLoading(false);
    }
  }, []);

  // Initial load + periodic overview refresh.
  useEffect(() => {
    void loadOverview();
    void loadCves();
    const id = setInterval(() => {
      void loadOverview();
    }, REFRESH_MS);
    return () => clearInterval(id);
  }, [loadOverview, loadCves]);

  // Live push updates via SSE; the interval above remains as a fallback.
  useEffect(() => {
    const base = import.meta.env.VITE_API_BASE ?? '';
    const token = import.meta.env.VITE_API_TOKEN;
    let es: EventSource | null = null;
    try {
      // EventSource can't set headers, so the token (when present) rides as a query param.
      es = new EventSource(`${base}/api/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`);
      es.addEventListener('refresh', () => {
        void loadOverview();
      });
    } catch {
      // EventSource unavailable; polling still keeps the dashboard fresh.
    }
    return () => es?.close();
  }, [loadOverview]);

  // Debounced threats query whenever filters change.
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(async () => {
      setThreatsLoading(true);
      try {
        const res = await fetchThreats({
          source: filters.source || undefined,
          type: filters.type || undefined,
          severity: filters.severity || undefined,
          q: filters.q || undefined,
          limit: 300,
        });
        setThreats(res.threats);
        setTotal(res.total);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load threats');
      } finally {
        setThreatsLoading(false);
      }
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [filters]);

  const lastRefresh = stats?.lastRefresh ? new Date(stats.lastRefresh) : null;

  return (
    <div className="mx-auto max-w-[1400px] px-4 py-5 md:px-6">
      <header className="mb-5 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3">
          <img src="/shield.svg" alt="" className="h-9 w-9" />
          <div>
            <h1 className="text-xl font-bold text-white">Threat Intelligence Platform</h1>
            <p className="text-xs text-slate-400">
              Unified situational awareness across public cyber threat feeds
            </p>
          </div>
        </div>
        <div className="text-right text-xs text-slate-400">
          {lastRefresh ? (
            <>
              Feeds updated{' '}
              <span className="text-slate-200">{lastRefresh.toLocaleTimeString()}</span>
            </>
          ) : (
            'Warming up feeds…'
          )}
        </div>
      </header>

      {error && (
        <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-2 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="mb-4">
        <SourceHealthBar sources={health} />
      </div>

      <div className="mb-5">
        <StatsCards stats={stats} />
      </div>

      <div className="mb-5 grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ThreatMap points={points} />
        </div>
        <div>
          <CvePanel cves={cves} loading={cvesLoading} />
        </div>
      </div>

      <div className="mb-5">
        <TrendChart enabled={trend.enabled} points={trend.points} />
      </div>

      <div className="mb-3">
        <Filters value={filters} onChange={setFilters} />
      </div>

      <ThreatTable threats={threats} total={total} loading={threatsLoading} />

      <footer className="mt-8 border-t border-white/10 pt-4 text-center text-xs text-slate-500">
        Data: CISA KEV · abuse.ch Feodo Tracker · abuse.ch URLhaus · NVD. For defensive /
        research use.
      </footer>
    </div>
  );
}
