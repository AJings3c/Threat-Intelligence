import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType, type FormEvent } from 'react';
import {
  Activity,
  Bell,
  Binary,
  DatabaseZap,
  Gauge,
  Globe2,
  Languages,
  LayoutDashboard,
  ListFilter,
  Moon,
  Network,
  Radar,
  RefreshCw,
  Search,
  SlidersHorizontal,
  Sun,
} from 'lucide-react';
import type {
  CveItem,
  ConfigStatusResponse,
  EnrichmentProvider,
  HashIntelResponse,
  IntegrationKind,
  IntegrationTestResult,
  Language,
  NotifyTestResponse,
  SourceHealth,
  SourceHealthHistoryPoint,
  Stats,
  ThreatIndicator,
  ThreatSource,
  TrendPoint,
} from './types';
import {
  fetchCves,
  fetchConfigStatus,
  fetchHashIntel,
  fetchHealth,
  fetchMap,
  fetchSourceHistory,
  fetchStats,
  fetchThreats,
  fetchTrend,
  sendNotifyTest,
  testIntegration,
} from './api';
import { LANG_LABEL, UI_TEXT } from './i18n';
import { StatsCards } from './components/StatsCards';
import { ThreatMap } from './components/ThreatMap';
import { Filters, type FilterState } from './components/Filters';
import { ThreatTable } from './components/ThreatTable';
import { CvePanel } from './components/CvePanel';
import { SourceHealthBar } from './components/SourceHealthBar';
import { TrendChart } from './components/TrendChart';
import { HashIntelPanel } from './components/HashIntelPanel';
import { ConfigStatusPanel } from './components/ConfigStatusPanel';
import { IocInvestigationPanel } from './components/IocInvestigationPanel';
import { ArchitectureThreatModelPanel } from './components/ArchitectureThreatModelPanel';

const REFRESH_MS = 60_000;

export type WorkspaceId = 'overview' | 'sources' | 'investigation' | 'modeling' | 'feed';
export type DensityMode = 'comfortable' | 'compact';
export type ThemeMode = 'dark' | 'light';

const WORKSPACE_ORDER: WorkspaceId[] = ['overview', 'sources', 'investigation', 'modeling', 'feed'];

const WORKBENCH_TEXT: Record<
  Language,
  {
    productName: string;
    productKicker: string;
    commandLabel: string;
    commandPlaceholder: string;
    density: string;
    compact: string;
    comfortable: string;
    theme: string;
    darkTheme: string;
    lightTheme: string;
    sourceHealth: string;
    configuredSources: string;
    connected: string;
    degraded: string;
    lastRefresh: string;
    overviewTitle: string;
    overviewSubtitle: string;
    sourcesTitle: string;
    sourcesSubtitle: string;
    investigationTitle: string;
    investigationSubtitle: string;
    modelingTitle: string;
    modelingSubtitle: string;
    feedTitle: string;
    feedSubtitle: string;
    liveOps: string;
    sourceMatrix: string;
    modelScope: string;
    feedCount: string;
    workspace: Record<WorkspaceId, string>;
    skip: string;
    currentWorkspace: string;
  }
> = {
  en: {
    productName: 'Evidence Command Workbench',
    productKicker: 'Threat Intelligence Platform',
    commandLabel: 'IOC command',
    commandPlaceholder: 'Search domain, IP, URL, hash, CIDR, CVE',
    density: 'Density',
    compact: 'Compact',
    comfortable: 'Comfort',
    theme: 'Theme',
    darkTheme: 'Dark',
    lightTheme: 'Light',
    sourceHealth: 'Source health',
    configuredSources: 'Configured sources',
    connected: 'Connected',
    degraded: 'Degraded',
    lastRefresh: 'Last refresh',
    overviewTitle: 'Operational Overview',
    overviewSubtitle: 'Current feed health, geospatial signals, CVEs, malware and trend evidence.',
    sourcesTitle: 'Sources & Config',
    sourcesSubtitle: 'Credential state, test controls, enrichment providers and notification readiness.',
    investigationTitle: 'IOC Investigation',
    investigationSubtitle: 'Observable search, local evidence, STRIDE scenarios, enrichment and export.',
    modelingTitle: 'Threat Modeling',
    modelingSubtitle: 'Source-backed architecture model with DFD, STRIDE, DREAD, controls and attack paths.',
    feedTitle: 'Intel Feed',
    feedSubtitle: 'Filterable IOC table with source, confidence, reliability, country and recency.',
    liveOps: 'Live operations',
    sourceMatrix: 'Source matrix',
    modelScope: 'Model scope',
    feedCount: 'Feed count',
    workspace: {
      overview: 'Overview',
      sources: 'Sources',
      investigation: 'Investigation',
      modeling: 'Modeling',
      feed: 'Intel Feed',
    },
    skip: 'Skip to content',
    currentWorkspace: 'Current workspace',
  },
  zh: {
    productName: '证据指挥工作台',
    productKicker: '威胁情报平台',
    commandLabel: 'IOC 命令',
    commandPlaceholder: '搜索域名、IP、URL、哈希、CIDR、CVE',
    density: '密度',
    compact: '紧凑',
    comfortable: '舒适',
    theme: '主题',
    darkTheme: '深色',
    lightTheme: '浅色',
    sourceHealth: '情报源健康',
    configuredSources: '已配置来源',
    connected: '已连接',
    degraded: '异常',
    lastRefresh: '最近刷新',
    overviewTitle: '运营总览',
    overviewSubtitle: '当前情报源健康、地理信号、CVE、恶意软件与趋势证据。',
    sourcesTitle: '来源与配置',
    sourcesSubtitle: '凭据状态、测试控制、富化服务商与通知就绪状态。',
    investigationTitle: 'IOC 调查',
    investigationSubtitle: '可观测对象检索、本地证据、STRIDE 场景、富化与导出。',
    modelingTitle: '威胁建模',
    modelingSubtitle: '基于当前情报源的架构模型，包含 DFD、STRIDE、DREAD、控制项与攻击路径。',
    feedTitle: '情报列表',
    feedSubtitle: '可过滤 IOC 表格，展示来源、置信度、可靠性、国家/地区与时间。',
    liveOps: '实时运营',
    sourceMatrix: '来源矩阵',
    modelScope: '模型范围',
    feedCount: '情报数量',
    workspace: {
      overview: '总览',
      sources: '来源',
      investigation: '调查',
      modeling: '建模',
      feed: '情报列表',
    },
    skip: '跳转到内容',
    currentWorkspace: '当前工作区',
  },
};

const WORKSPACE_ICON: Record<WorkspaceId, ComponentType<{ className?: string }>> = {
  overview: LayoutDashboard,
  sources: DatabaseZap,
  investigation: Radar,
  modeling: Network,
  feed: ListFilter,
};

function getInitialTheme(): ThemeMode {
  try {
    const stored = window.localStorage.getItem('theme');
    return stored === 'light' || stored === 'dark' ? stored : 'dark';
  } catch {
    return 'dark';
  }
}

function BrandLogo({ size = 'md', theme }: { size?: 'sm' | 'md'; theme: ThemeMode }) {
  const sizeClass = size === 'sm' ? 'h-9 w-9' : 'h-11 w-11';
  const src = theme === 'light' ? '/brand-logo-light.png' : '/brand-logo-dark.png';
  return (
    <img
      src={src}
      alt=""
      className={`${sizeClass} shrink-0 object-contain`}
      aria-hidden="true"
    />
  );
}

function workspaceFromHash(): WorkspaceId {
  const value = window.location.hash.replace('#', '') as WorkspaceId;
  return WORKSPACE_ORDER.includes(value) ? value : 'overview';
}

function setHashWorkspace(workspace: WorkspaceId) {
  if (window.location.hash !== `#${workspace}`) {
    window.history.pushState(null, '', `#${workspace}`);
  }
}

function StatusMetric({
  icon: Icon,
  label,
  value,
  tone = 'neutral',
}: {
  icon: ComponentType<{ className?: string }>;
  label: string;
  value: string;
  tone?: 'neutral' | 'ok' | 'warn';
}) {
  const toneClass = tone === 'ok' ? 'text-emerald-300' : tone === 'warn' ? 'text-amber-300' : 'text-slate-200';
  return (
    <div className="surface-raised flex min-h-[84px] items-center gap-3 rounded-lg px-4 py-3">
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-line/70 bg-panel-3/80">
        <Icon className="h-4 w-4 text-teal-200" aria-hidden="true" />
      </div>
      <div className="min-w-0">
        <div className="text-xs font-semibold text-slate-500">{label}</div>
        <div className={`mt-1 truncate text-lg font-bold ${toneClass}`}>{value}</div>
      </div>
    </div>
  );
}

function WorkspaceTitle({
  icon: Icon,
  title,
  subtitle,
}: {
  icon: ComponentType<{ className?: string }>;
  title: string;
  subtitle: string;
}) {
  return (
    <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
      <div className="flex items-start gap-3">
        <div className="mt-1 flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-teal-300/30 bg-teal-300/10">
          <Icon className="h-5 w-5 text-teal-100" aria-hidden="true" />
        </div>
        <div>
          <h1 className="text-2xl font-bold leading-tight text-slate-50 md:text-3xl">{title}</h1>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-400">{subtitle}</p>
        </div>
      </div>
    </div>
  );
}

function WorkspaceNav({
  active,
  lang,
  onChange,
  compact = false,
}: {
  active: WorkspaceId;
  lang: Language;
  onChange: (workspace: WorkspaceId) => void;
  compact?: boolean;
}) {
  const copy = WORKBENCH_TEXT[lang];
  return (
    <nav className={compact ? 'flex gap-2 overflow-x-auto pb-1' : 'space-y-1'} aria-label={copy.productName}>
      {WORKSPACE_ORDER.map((workspace) => {
        const Icon = WORKSPACE_ICON[workspace];
        return (
          <button
            key={workspace}
            type="button"
            data-active={active === workspace}
            onClick={() => onChange(workspace)}
            className={compact ? 'nav-item shrink-0 px-3' : 'nav-item w-full'}
          >
            <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span className="whitespace-nowrap text-sm font-semibold">{copy.workspace[workspace]}</span>
          </button>
        );
      })}
    </nav>
  );
}

function OverviewWorkspace({
  stats,
  points,
  cves,
  cvesLoading,
  trend,
  hashIntel,
  hashesLoading,
  health,
  sourceHistory,
  lang,
  theme,
}: {
  stats: Stats | null;
  points: ThreatIndicator[];
  cves: CveItem[];
  cvesLoading: boolean;
  trend: { enabled: boolean; points: TrendPoint[] };
  hashIntel: HashIntelResponse | null;
  hashesLoading: boolean;
  health: SourceHealth[];
  sourceHistory: SourceHealthHistoryPoint[];
  lang: Language;
  theme: ThemeMode;
}) {
  const copy = WORKBENCH_TEXT[lang];
  return (
    <>
      <WorkspaceTitle icon={LayoutDashboard} title={copy.overviewTitle} subtitle={copy.overviewSubtitle} />
      <div className="space-y-5">
        <section className="surface rounded-lg px-4 py-3">
          <div className="mb-3 flex items-center gap-2 text-xs font-semibold text-slate-400">
            <Activity className="h-4 w-4 text-teal-200" aria-hidden="true" />
            {copy.sourceHealth}
          </div>
          <SourceHealthBar sources={health} history={sourceHistory} lang={lang} />
        </section>
        <StatsCards stats={stats} lang={lang} />
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(360px,0.9fr)]">
          <ThreatMap points={points} lang={lang} theme={theme} />
          <CvePanel cves={cves} loading={cvesLoading} lang={lang} />
        </div>
        <div className="grid gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <TrendChart enabled={trend.enabled} points={trend.points} lang={lang} />
          <HashIntelPanel data={hashIntel} loading={hashesLoading} lang={lang} />
        </div>
      </div>
    </>
  );
}

export default function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [points, setPoints] = useState<ThreatIndicator[]>([]);
  const [cves, setCves] = useState<CveItem[]>([]);
  const [hashIntel, setHashIntel] = useState<HashIntelResponse | null>(null);
  const [health, setHealth] = useState<SourceHealth[]>([]);
  const [sourceHistory, setSourceHistory] = useState<SourceHealthHistoryPoint[]>([]);
  const [trend, setTrend] = useState<{ enabled: boolean; points: TrendPoint[] }>({
    enabled: false,
    points: [],
  });
  const [configStatus, setConfigStatus] = useState<ConfigStatusResponse | null>(null);
  const [notifyTestResult, setNotifyTestResult] = useState<NotifyTestResponse | null>(null);
  const [integrationResults, setIntegrationResults] = useState<Record<string, IntegrationTestResult>>({});
  const [language, setLanguage] = useState<Language>('en');
  const [density, setDensity] = useState<DensityMode>('comfortable');
  const [theme, setTheme] = useState<ThemeMode>(() => getInitialTheme());
  const [activeWorkspace, setActiveWorkspace] = useState<WorkspaceId>(() => workspaceFromHash());
  const [commandValue, setCommandValue] = useState('');
  const [investigationSeed, setInvestigationSeed] = useState<{ value: string; nonce: number }>({ value: '', nonce: 0 });
  const [threats, setThreats] = useState<ThreatIndicator[]>([]);
  const [total, setTotal] = useState(0);
  const [threatsLoading, setThreatsLoading] = useState(true);
  const [cvesLoading, setCvesLoading] = useState(true);
  const [hashesLoading, setHashesLoading] = useState(true);
  const [configLoading, setConfigLoading] = useState(true);
  const [configChecking, setConfigChecking] = useState(false);
  const [notifyTestLoading, setNotifyTestLoading] = useState(false);
  const [integrationLoading, setIntegrationLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [filters, setFilters] = useState<FilterState>({
    source: '',
    type: '',
    severity: '',
    q: '',
  });

  const loadOverview = useCallback(async () => {
    try {
      const [s, m, h, t, sh] = await Promise.all([
        fetchStats(),
        fetchMap(),
        fetchHealth(),
        fetchTrend(),
        fetchSourceHistory(),
      ]);
      setStats(s);
      setPoints(m.points);
      setHealth(h.sources);
      setSourceHistory(sh.points);
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
      // CVE data is helpful but non-fatal.
    } finally {
      setCvesLoading(false);
    }
  }, []);

  const loadConfigStatus = useCallback(async (checking = false) => {
    if (checking) setConfigChecking(true);
    setConfigLoading(true);
    try {
      const res = await fetchConfigStatus();
      setConfigStatus(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load configuration');
    } finally {
      setConfigLoading(false);
      setConfigChecking(false);
    }
  }, []);

  const loadHashIntel = useCallback(async () => {
    setHashesLoading(true);
    try {
      const res = await fetchHashIntel(30);
      setHashIntel(res);
    } catch {
      // Hash intelligence is helpful but non-fatal.
    } finally {
      setHashesLoading(false);
    }
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    const logoHref = theme === 'light' ? '/brand-logo-light.png' : '/brand-logo-dark.png';
    root.dataset.theme = theme;
    root.classList.toggle('dark', theme === 'dark');
    root.classList.toggle('light', theme === 'light');
    root.style.colorScheme = theme;
    try {
      window.localStorage.setItem('theme', theme);
    } catch {
      // Theme still applies for the current session when storage is unavailable.
    }
    document.querySelector<HTMLLinkElement>('link[rel="icon"]')?.setAttribute('href', logoHref);
    document.querySelector<HTMLLinkElement>('link[rel="apple-touch-icon"]')?.setAttribute('href', logoHref);
  }, [theme]);

  useEffect(() => {
    void loadOverview();
    void loadCves();
    void loadHashIntel();
    const id = setInterval(() => {
      void loadOverview();
    }, REFRESH_MS);
    return () => clearInterval(id);
  }, [loadOverview, loadCves, loadHashIntel]);

  useEffect(() => {
    void loadConfigStatus();
  }, [loadConfigStatus]);

  useEffect(() => {
    const base = import.meta.env.VITE_API_BASE ?? '';
    const token = import.meta.env.VITE_API_TOKEN;
    let es: EventSource | null = null;
    try {
      es = new EventSource(`${base}/api/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`);
      es.addEventListener('refresh', () => {
        void loadOverview();
      });
    } catch {
      // Polling remains as a fallback when EventSource is unavailable.
    }
    return () => es?.close();
  }, [loadOverview]);

  useEffect(() => {
    const onHashChange = () => setActiveWorkspace(workspaceFromHash());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

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
  const t = UI_TEXT[language];
  const copy = WORKBENCH_TEXT[language];

  const handleNotifyTest = useCallback(async () => {
    setNotifyTestLoading(true);
    try {
      setNotifyTestResult(await sendNotifyTest());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send test digest');
    } finally {
      setNotifyTestLoading(false);
    }
  }, []);

  const handleIntegrationTest = useCallback(async (kind: IntegrationKind, id: ThreatSource | EnrichmentProvider) => {
    const key = `${kind}:${id}`;
    setIntegrationLoading(key);
    try {
      const result = await testIntegration(kind, id);
      setIntegrationResults((prev) => ({ ...prev, [key]: result }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Integration test failed');
    } finally {
      setIntegrationLoading(null);
    }
  }, []);

  const changeWorkspace = useCallback((workspace: WorkspaceId) => {
    setActiveWorkspace(workspace);
    setHashWorkspace(workspace);
  }, []);

  const handleCommandSubmit = useCallback(
    (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const value = commandValue.trim();
      if (!value) return;
      setInvestigationSeed({ value, nonce: Date.now() });
      changeWorkspace('investigation');
    },
    [changeWorkspace, commandValue],
  );

  const healthSummary = useMemo(() => {
    const connected = health.filter((source) => source.status === 'healthy' || source.status === 'warming').length;
    const degraded = health.filter((source) => source.status === 'error' || source.status === 'stale').length;
    return { connected, degraded, total: health.length };
  }, [health]);

  const configuredCount = configStatus?.sources.filter((source) => source.configured).length ?? 0;
  const activeIcon = WORKSPACE_ICON[activeWorkspace];

  return (
    <div className="workbench-shell" data-density={density}>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-panel-2 focus:px-4 focus:py-2 focus:text-sm focus:text-slate-100"
      >
        {copy.skip}
      </a>

      <aside className="fixed inset-y-0 left-0 z-30 hidden w-[var(--shell-width)] border-r border-line/60 bg-base/86 px-4 py-5 backdrop-blur-xl lg:flex lg:flex-col">
        <div className="mb-6 flex items-center gap-3">
          <BrandLogo theme={theme} />
          <div className="min-w-0">
            <div className="truncate text-xs font-semibold text-slate-500">{copy.productKicker}</div>
            <div className="text-sm font-bold leading-tight text-slate-50">{copy.productName}</div>
          </div>
        </div>

        <WorkspaceNav active={activeWorkspace} lang={language} onChange={changeWorkspace} />

        <div className="mt-auto space-y-3">
          <div className="surface rounded-lg p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-slate-400">
              <Gauge className="h-4 w-4 text-teal-200" aria-hidden="true" />
              {copy.liveOps}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="rounded border border-line/60 bg-panel-2/70 px-2 py-2">
                <div className="text-[11px] text-slate-500">{copy.connected}</div>
                <div className="text-lg font-bold text-emerald-300">{healthSummary.connected}</div>
              </div>
              <div className="rounded border border-line/60 bg-panel-2/70 px-2 py-2">
                <div className="text-[11px] text-slate-500">{copy.degraded}</div>
                <div className="text-lg font-bold text-amber-300">{healthSummary.degraded}</div>
              </div>
            </div>
          </div>
          <div className="text-xs leading-5 text-slate-500">
            {copy.lastRefresh}:{' '}
            <span className="text-slate-300">{lastRefresh ? lastRefresh.toLocaleTimeString() : t.warmingFeeds}</span>
          </div>
        </div>
      </aside>

      <main className="min-h-dvh lg:pl-[var(--shell-width)]">
        <header className="sticky top-0 z-20 border-b border-line/60 bg-base/82 backdrop-blur-xl">
          <div className="px-[var(--content-gutter)] py-4">
            <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
              <div className="flex items-center gap-3 lg:hidden">
                <BrandLogo size="sm" theme={theme} />
                <div>
                  <div className="text-xs font-semibold text-slate-500">{copy.productKicker}</div>
                  <div className="text-base font-bold text-slate-50">{copy.productName}</div>
                </div>
              </div>

              <form onSubmit={handleCommandSubmit} className="flex min-w-0 flex-1 flex-col gap-2 sm:flex-row sm:items-center xl:max-w-3xl">
                <label htmlFor="global-ioc-command" className="sr-only">
                  {copy.commandLabel}
                </label>
                <div className="relative min-w-0 flex-1">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" aria-hidden="true" />
                  <input
                    id="global-ioc-command"
                    type="search"
                    value={commandValue}
                    onChange={(event) => setCommandValue(event.target.value)}
                    placeholder={copy.commandPlaceholder}
                    className="control w-full pl-10 pr-3 text-sm placeholder:text-slate-600"
                  />
                </div>
                <button
                  type="submit"
                  disabled={!commandValue.trim()}
                  className="primary-action control inline-flex items-center justify-center gap-2 px-4 text-sm font-bold disabled:opacity-50"
                >
                  <Radar className="h-4 w-4" aria-hidden="true" />
                  {t.investigate}
                </button>
              </form>

              <div className="flex flex-wrap items-center gap-2">
                <div className="flex min-h-11 items-center rounded-lg border border-line/70 bg-panel-2/80 p-1">
                  <Languages className="ml-2 h-4 w-4 text-slate-500" aria-hidden="true" />
                  {(['en', 'zh'] as Language[]).map((item) => (
                    <button
                      key={item}
                      type="button"
                      onClick={() => setLanguage(item)}
                      className={`min-h-9 rounded-md px-3 text-xs font-semibold transition ${
                        language === item ? 'bg-teal-300/15 text-teal-100' : 'text-slate-400 hover:bg-white/5 hover:text-slate-100'
                      }`}
                    >
                      {LANG_LABEL[item]}
                    </button>
                  ))}
                </div>
                <div className="flex min-h-11 items-center rounded-lg border border-line/70 bg-panel-2/80 p-1">
                  <SlidersHorizontal className="ml-2 h-4 w-4 text-slate-500" aria-hidden="true" />
                  {(['comfortable', 'compact'] as DensityMode[]).map((item) => (
                    <button
                      key={item}
                      type="button"
                      onClick={() => setDensity(item)}
                      className={`min-h-9 rounded-md px-3 text-xs font-semibold transition ${
                        density === item ? 'bg-slate-100/10 text-slate-100' : 'text-slate-400 hover:bg-white/5 hover:text-slate-100'
                      }`}
                    >
                      {item === 'compact' ? copy.compact : copy.comfortable}
                    </button>
                  ))}
                </div>
                <div className="flex min-h-11 items-center rounded-lg border border-line/70 bg-panel-2/80 p-1" aria-label={copy.theme}>
                  <Sun className="ml-2 h-4 w-4 text-slate-500" aria-hidden="true" />
                  {(['dark', 'light'] as ThemeMode[]).map((item) => {
                    const Icon = item === 'dark' ? Moon : Sun;
                    return (
                      <button
                        key={item}
                        type="button"
                        onClick={() => setTheme(item)}
                        className={`min-h-9 rounded-md px-3 text-xs font-semibold transition ${
                          theme === item ? 'bg-teal-300/15 text-teal-100' : 'text-slate-400 hover:bg-white/5 hover:text-slate-100'
                        }`}
                        aria-pressed={theme === item}
                      >
                        <span className="inline-flex items-center gap-1.5">
                          <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                          {item === 'dark' ? copy.darkTheme : copy.lightTheme}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>

            <div className="mt-3 lg:hidden">
              <WorkspaceNav active={activeWorkspace} lang={language} onChange={changeWorkspace} compact />
            </div>
          </div>
        </header>

        <div id="main-content" className="px-[var(--content-gutter)] py-6">
          {error && (
            <div className="mb-5 flex items-start gap-3 rounded-lg border border-red-400/45 bg-red-500/10 px-4 py-3 text-sm text-red-200" role="alert">
              <Bell className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          <div className="mb-5 grid gap-3 md:grid-cols-3">
            <StatusMetric
              icon={activeIcon}
              label={copy.currentWorkspace}
              value={copy.workspace[activeWorkspace]}
            />
            <StatusMetric
              icon={DatabaseZap}
              label={copy.configuredSources}
              value={`${configuredCount}/${configStatus?.sources.length ?? healthSummary.total}`}
              tone={configuredCount > 0 ? 'ok' : 'neutral'}
            />
            <StatusMetric
              icon={RefreshCw}
              label={copy.lastRefresh}
              value={lastRefresh ? lastRefresh.toLocaleTimeString() : t.warmingFeeds}
              tone={healthSummary.degraded > 0 ? 'warn' : 'ok'}
            />
          </div>

          {activeWorkspace === 'overview' && (
            <OverviewWorkspace
              stats={stats}
              points={points}
              cves={cves}
              cvesLoading={cvesLoading}
              trend={trend}
              hashIntel={hashIntel}
              hashesLoading={hashesLoading}
              health={health}
              sourceHistory={sourceHistory}
              lang={language}
              theme={theme}
            />
          )}

          {activeWorkspace === 'sources' && (
            <>
              <WorkspaceTitle icon={DatabaseZap} title={copy.sourcesTitle} subtitle={copy.sourcesSubtitle} />
              <div className="space-y-5">
                <section className="surface rounded-lg px-4 py-3">
                  <div className="mb-3 flex items-center gap-2 text-xs font-semibold text-slate-400">
                    <Globe2 className="h-4 w-4 text-teal-200" aria-hidden="true" />
                    {copy.sourceMatrix}
                  </div>
                  <SourceHealthBar sources={health} history={sourceHistory} lang={language} />
                </section>
                <ConfigStatusPanel
                  data={configStatus}
                  loading={configLoading}
                  checking={configChecking}
                  testResult={notifyTestResult}
                  testLoading={notifyTestLoading}
                  integrationResults={integrationResults}
                  integrationLoading={integrationLoading}
                  onRefresh={() => void loadConfigStatus(true)}
                  onSendTest={() => void handleNotifyTest()}
                  onTestIntegration={(kind, id) => void handleIntegrationTest(kind, id)}
                  lang={language}
                />
              </div>
            </>
          )}

          {activeWorkspace === 'investigation' && (
            <>
              <WorkspaceTitle icon={Radar} title={copy.investigationTitle} subtitle={copy.investigationSubtitle} />
              <IocInvestigationPanel
                lang={language}
                initialIndicator={investigationSeed.value}
                initialNonce={investigationSeed.nonce}
              />
            </>
          )}

          {activeWorkspace === 'modeling' && (
            <>
              <WorkspaceTitle icon={Network} title={copy.modelingTitle} subtitle={copy.modelingSubtitle} />
              <ArchitectureThreatModelPanel lang={language} sourceHealth={health} />
            </>
          )}

          {activeWorkspace === 'feed' && (
            <>
              <WorkspaceTitle icon={Binary} title={copy.feedTitle} subtitle={copy.feedSubtitle} />
              <div className="sticky top-[104px] z-10 mb-3 rounded-lg border border-line/70 bg-base/88 p-3 backdrop-blur-xl">
                <Filters value={filters} onChange={setFilters} lang={language} />
              </div>
              <ThreatTable threats={threats} total={total} loading={threatsLoading} lang={language} />
            </>
          )}

          <footer className="mt-8 border-t border-line/60 pt-4 text-center text-xs text-slate-500">{t.footer}</footer>
        </div>
      </main>
    </div>
  );
}
