import type {
  ConfigStatusResponse,
  EnrichmentProvider,
  IntegrationKind,
  IntegrationTestResult,
  NotifyTestResponse,
  SourceHealthStatus,
  ThreatSource,
} from '../types';

const STATUS_LABEL: Record<SourceHealthStatus, string> = {
  healthy: 'Healthy',
  disabled: 'Disabled',
  warming: 'Warming',
  error: 'Error',
  stale: 'Stale',
  deprecated: 'Deprecated',
};

const STATUS_CLASS: Record<SourceHealthStatus, string> = {
  healthy: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  disabled: 'border-slate-500/30 bg-slate-500/10 text-slate-400',
  warming: 'border-sky-400/30 bg-sky-400/10 text-sky-300',
  error: 'border-red-400/30 bg-red-400/10 text-red-300',
  stale: 'border-yellow-400/30 bg-yellow-400/10 text-yellow-300',
  deprecated: 'border-purple-300/30 bg-purple-300/10 text-purple-200',
};

function timeLabel(value: string | null): string {
  if (!value) return 'never';
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return 'unknown';
  const mins = Math.floor((Date.now() - then) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function StatusBadge({ status }: { status: SourceHealthStatus }) {
  return (
    <span className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${STATUS_CLASS[status]}`}>
      {STATUS_LABEL[status]}
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
  onRefresh: () => void;
  onSendTest: () => void;
  onTestIntegration: (kind: IntegrationKind, id: ThreatSource | EnrichmentProvider) => void;
}) {
  const sources = data?.sources ?? [];
  const providers = data?.enrichmentProviders ?? [];
  const configuredSources = sources.filter((source) => source.configured).length;
  const configuredProviders = providers.filter((provider) => provider.configured).length;

  return (
    <div className="rounded-xl border border-white/10 bg-panel/70 shadow-lg">
      <div className="flex flex-col gap-3 border-b border-white/10 px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Configuration Check</h2>
          <div className="mt-1 text-xs text-slate-500">
            {loading
              ? 'Loading'
              : `${configuredSources}/${sources.length} sources · ${configuredProviders}/${providers.length} enrichers`}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={onRefresh}
            disabled={checking}
            className="rounded-lg border border-sky-400/40 bg-sky-400/10 px-3 py-2 text-xs font-semibold text-sky-200 hover:bg-sky-400/15 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {checking ? 'Checking' : 'Check configuration'}
          </button>
          <button
            type="button"
            onClick={onSendTest}
            disabled={testLoading}
            className="rounded-lg border border-white/10 bg-panel-2 px-3 py-2 text-xs font-semibold text-slate-200 hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {testLoading ? 'Sending' : 'Send test digest'}
          </button>
        </div>
      </div>
      <div className="grid gap-0 divide-y divide-white/5 lg:grid-cols-[1fr_320px] lg:divide-x lg:divide-y-0">
        <div className="max-h-[300px] overflow-auto">
          {sources.map((source) => (
            <div key={source.source} className="grid gap-2 border-b border-white/5 px-4 py-3 last:border-b-0 md:grid-cols-[1fr_auto_auto_auto] md:items-center">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-slate-200">{source.label}</span>
                  <StatusBadge status={source.status} />
                  {source.credentialed && (
                    <span className="rounded border border-white/10 px-2 py-0.5 text-[11px] text-slate-400">
                      {source.configured ? 'Configured' : 'Needs key'}
                    </span>
                  )}
                </div>
                <div className="mt-1 truncate text-xs text-slate-500">
                  {source.lastError ??
                    (source.requiredEnv.length > 0 ? source.requiredEnv.join(', ') : 'public feed')}
                </div>
                {integrationResults[`source:${source.source}`] && (
                  <div className="mt-1 text-xs text-slate-400">
                    Test: {integrationResults[`source:${source.source}`].status} ·{' '}
                    {integrationResults[`source:${source.source}`].message}
                    {integrationResults[`source:${source.source}`].latencyMs !== null
                      ? ` · ${integrationResults[`source:${source.source}`].latencyMs}ms`
                      : ''}
                  </div>
                )}
              </div>
              <div className="text-xs text-slate-400">{source.count.toLocaleString()} items</div>
              <div className="text-xs text-slate-500">{timeLabel(source.lastFetched)}</div>
              <button
                type="button"
                onClick={() => onTestIntegration('source', source.source)}
                disabled={integrationLoading === `source:${source.source}`}
                className="rounded border border-white/10 bg-panel-2 px-2 py-1 text-[11px] font-semibold text-slate-300 hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {integrationLoading === `source:${source.source}` ? 'Testing' : 'Test'}
              </button>
            </div>
          ))}
        </div>
        <div className="px-4 py-3">
          <div className="text-xs font-semibold text-slate-300">Enrichment providers</div>
          <div className="mt-3 space-y-2">
            {providers.map((provider) => (
              <div key={provider.provider} className="grid gap-2 border-b border-white/5 pb-2 last:border-b-0">
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
                      {provider.configured ? 'Configured' : 'Missing'}
                    </span>
                    <button
                      type="button"
                      onClick={() => onTestIntegration('provider', provider.provider)}
                      disabled={integrationLoading === `provider:${provider.provider}`}
                      className="rounded border border-white/10 bg-panel-2 px-2 py-1 text-[11px] font-semibold text-slate-300 hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {integrationLoading === `provider:${provider.provider}` ? 'Testing' : 'Test'}
                    </button>
                  </div>
                </div>
                {integrationResults[`provider:${provider.provider}`] && (
                  <div className="text-xs text-slate-400">
                    Test: {integrationResults[`provider:${provider.provider}`].status} ·{' '}
                    {integrationResults[`provider:${provider.provider}`].message}
                    {integrationResults[`provider:${provider.provider}`].latencyMs !== null
                      ? ` · ${integrationResults[`provider:${provider.provider}`].latencyMs}ms`
                      : ''}
                  </div>
                )}
              </div>
            ))}
          </div>
          <div className="mt-4 border-t border-white/10 pt-3 text-xs text-slate-400">
            <div>Notify: {data?.notify.enabled ? 'enabled' : 'disabled'}</div>
            <div>Persistence: {data?.persistence.enabled ? 'enabled' : 'disabled'}</div>
            {testResult && (
              <div className="mt-2 rounded border border-white/10 bg-panel-2 px-3 py-2 text-slate-300">
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
