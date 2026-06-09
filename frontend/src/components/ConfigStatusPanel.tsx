import type {
  ConfigStatusResponse,
  EnrichmentProvider,
  IntegrationKind,
  IntegrationTestResult,
  Language,
  NotifyTestResponse,
  SourceHealthStatus,
  ThreatSource,
} from '../types';
import { SOURCE_HEALTH_LABEL, UI_TEXT } from '../i18n';

const STATUS_CLASS: Record<SourceHealthStatus, string> = {
  healthy: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  disabled: 'border-slate-500/30 bg-slate-500/10 text-slate-400',
  warming: 'border-sky-400/30 bg-sky-400/10 text-sky-300',
  error: 'border-red-400/30 bg-red-400/10 text-red-300',
  stale: 'border-yellow-400/30 bg-yellow-400/10 text-yellow-300',
  deprecated: 'border-purple-300/30 bg-purple-300/10 text-purple-200',
};

function timeLabel(value: string | null, lang: Language): string {
  const t = UI_TEXT[lang];
  if (!value) return t.never;
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return t.unknown;
  const mins = Math.floor((Date.now() - then) / 60000);
  if (mins < 1) return t.justNow;
  if (mins < 60) return lang === 'zh' ? `${mins} 分钟前` : `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return lang === 'zh' ? `${hrs} 小时前` : `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return lang === 'zh' ? `${days} 天前` : `${days}d ago`;
}

function StatusBadge({ status, lang }: { status: SourceHealthStatus; lang: Language }) {
  return (
    <span className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${STATUS_CLASS[status]}`}>
      {SOURCE_HEALTH_LABEL[lang][status]}
    </span>
  );
}

export function ConfigStatusPanel({
  data,
  loading,
  checking,
  testResult,
  testLoading,
  integrationResults,
  integrationLoading,
  lang,
  onRefresh,
  onSendTest,
  onTestIntegration,
}: {
  data: ConfigStatusResponse | null;
  loading: boolean;
  checking: boolean;
  testResult: NotifyTestResponse | null;
  testLoading: boolean;
  integrationResults: Record<string, IntegrationTestResult>;
  integrationLoading: string | null;
  lang: Language;
  onRefresh: () => void;
  onSendTest: () => void;
  onTestIntegration: (kind: IntegrationKind, id: ThreatSource | EnrichmentProvider) => void;
}) {
  const t = UI_TEXT[lang];
  const sources = data?.sources ?? [];
  const providers = data?.enrichmentProviders ?? [];
  const configuredSources = sources.filter((source) => source.configured).length;
  const configuredProviders = providers.filter((provider) => provider.configured).length;

  return (
    <div className="surface overflow-hidden rounded-lg">
      <div className="flex flex-col gap-3 border-b border-line/60 bg-panel-2/45 px-4 py-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="section-title">{t.configurationTitle}</h2>
          <div className="mt-1 text-xs text-slate-500">
            {loading
              ? t.loading
              : `${configuredSources}/${sources.length} ${t.sources} · ${configuredProviders}/${providers.length} ${t.enrichers}`}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={onRefresh}
            disabled={checking}
            className="primary-action control px-4 text-xs font-bold disabled:opacity-60"
          >
            {checking ? t.checking : t.checkConfiguration}
          </button>
          <button
            type="button"
            onClick={onSendTest}
            disabled={testLoading}
            className="soft-action control px-4 text-xs font-bold disabled:opacity-60"
          >
            {testLoading ? t.sending : t.sendTestDigest}
          </button>
        </div>
      </div>
      <div className="grid gap-0 divide-y divide-line/50 lg:grid-cols-[1fr_360px] lg:divide-x lg:divide-y-0">
        <div>
          {sources.map((source) => (
            <div key={source.source} className="grid gap-2 border-b border-line/40 px-4 py-3 last:border-b-0 md:grid-cols-[1fr_auto_auto_auto] md:items-center">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-slate-200">{source.label}</span>
                  <StatusBadge status={source.status} lang={lang} />
                  {source.credentialed && (
                    <span className="rounded border border-line/70 px-2 py-0.5 text-[11px] text-slate-400">
                      {source.configured ? t.configured : t.needsKey}
                    </span>
                  )}
                </div>
                <div className="mt-1 truncate text-xs text-slate-500">
                  {source.lastError ??
                    (source.requiredEnv.length > 0 ? source.requiredEnv.join(', ') : t.publicFeed)}
                </div>
                {integrationResults[`source:${source.source}`] && (
                  <div className="mt-1 text-xs text-slate-400">
                    {t.testResult}: {integrationResults[`source:${source.source}`].status} ·{' '}
                    {integrationResults[`source:${source.source}`].message}
                    {integrationResults[`source:${source.source}`].latencyMs !== null
                      ? ` · ${integrationResults[`source:${source.source}`].latencyMs}ms`
                      : ''}
                  </div>
                )}
              </div>
              <div className="text-xs text-slate-400">
                {source.count.toLocaleString()} {t.items}
              </div>
              <div className="text-xs text-slate-500">{timeLabel(source.lastFetched, lang)}</div>
              <button
                type="button"
                onClick={() => onTestIntegration('source', source.source)}
                disabled={integrationLoading === `source:${source.source}`}
                className="soft-action min-h-10 rounded px-3 text-xs font-semibold disabled:opacity-60"
              >
                {integrationLoading === `source:${source.source}` ? t.testing : t.test}
              </button>
            </div>
          ))}
        </div>
        <div className="px-4 py-3">
          <div className="text-xs font-semibold text-slate-300">{t.enrichmentProviders}</div>
          <div className="mt-3 space-y-2">
            {providers.map((provider) => (
              <div key={provider.provider} className="grid gap-2 border-b border-line/40 pb-2 last:border-b-0">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm capitalize text-slate-200">{provider.provider}</div>
                    <div className="text-[11px] text-slate-500">{provider.requiredEnv.join(', ')}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${
                        provider.configured
                          ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300'
                          : 'border-slate-500/30 bg-slate-500/10 text-slate-400'
                      }`}
                    >
                      {provider.configured ? t.configured : t.missing}
                    </span>
                    <button
                      type="button"
                      onClick={() => onTestIntegration('provider', provider.provider)}
                      disabled={integrationLoading === `provider:${provider.provider}`}
                      className="soft-action min-h-10 rounded px-3 text-xs font-semibold disabled:opacity-60"
                    >
                      {integrationLoading === `provider:${provider.provider}` ? t.testing : t.test}
                    </button>
                  </div>
                </div>
                {integrationResults[`provider:${provider.provider}`] && (
                  <div className="text-xs text-slate-400">
                    {t.testResult}: {integrationResults[`provider:${provider.provider}`].status} ·{' '}
                    {integrationResults[`provider:${provider.provider}`].message}
                    {integrationResults[`provider:${provider.provider}`].latencyMs !== null
                      ? ` · ${integrationResults[`provider:${provider.provider}`].latencyMs}ms`
                      : ''}
                  </div>
                )}
              </div>
            ))}
          </div>
          <div className="mt-4 border-t border-line/60 pt-3 text-xs text-slate-400">
            <div>
              {t.notify}: {data?.notify.enabled ? t.enabled : t.disabled}
            </div>
            <div>
              {t.persistence}: {data?.persistence.enabled ? t.enabled : t.disabled}
            </div>
            {testResult && (
              <div className="mt-2 rounded border border-line/70 bg-panel-2 px-3 py-2 text-slate-300">
                {Object.entries(testResult.result)
                  .map(([channel, result]) => `${channel}: ${result}`)
                  .join(' · ')}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
