import { useState, useEffect } from 'react';
import { Activity, AlertCircle, CheckCircle, ExternalLink, Eye, Flame, Globe, Search } from 'lucide-react';
import { fetchEnrichmentProviders } from '../api';
import type { EnrichmentResponse, EnrichmentResult, Language, ProviderConfigStatus } from '../types';

const ENRICHMENT_TEXT = {
  en: {
    title: 'Enrichment Aggregate',
    noResults: 'No enrichment results available',
    error: 'Error',
    viewDetails: 'View details',
    providers: 'Providers',
    configured: 'configured',
    available: 'available',
    providerStatusUnavailable: 'Provider status unavailable',
    yes: 'Yes', no: 'No', items: 'items',
  },
  zh: {
    title: '富化聚合',
    noResults: '无富化结果',
    error: '错误',
    viewDetails: '查看详情',
    providers: '提供商',
    configured: '已配置',
    available: '可用',
    providerStatusUnavailable: '提供商状态不可用',
    yes: '是', no: '否', items: '项',
  },
};

const PROVIDER_ICONS: Record<string, typeof Search> = {
  virustotal: Search,
  shodan: Activity,
  censys: Globe,
  greynoise: Eye,
  urlscan: Flame,
};

const PROVIDER_COLORS: Record<string, string> = {
  virustotal: '#394eff',
  shodan: '#ef4444',
  censys: '#10b981',
  greynoise: '#8b5cf6',
  urlscan: '#f59e0b',
};

function ProviderCard({ result, lang }: { result: EnrichmentResult; lang: Language }) {
  const t = ENRICHMENT_TEXT[lang];
  const Icon = PROVIDER_ICONS[result.provider] || Search;
  const color = PROVIDER_COLORS[result.provider] || '#60a5fa';

  if (!result.ok) {
    return (
      <div className="rounded border border-line/70 bg-panel-2 p-3">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Icon className="h-4 w-4" style={{ color }} />
            <span className="font-semibold capitalize text-slate-200">{result.provider}</span>
          </div>
          <AlertCircle className="h-4 w-4 text-red-400" />
        </div>
        <p className="break-words text-xs text-slate-400">{result.error || t.error}</p>
      </div>
    );
  }

  const summary = result.summary || {};

  return (
    <div className="rounded border border-line/70 bg-panel-2 p-3">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4" style={{ color }} />
          <span className="font-semibold capitalize text-slate-200">{result.provider}</span>
        </div>
        <CheckCircle className="h-4 w-4 text-teal-400" />
      </div>

      <div className="space-y-1.5">
        {Object.entries(summary).map(([key, value]) => {
          if (value === null || value === undefined) return null;

          let displayValue: string;
          if (typeof value === 'boolean') {
            displayValue = value ? t.yes : t.no;
          } else if (typeof value === 'object' && !Array.isArray(value)) {
            displayValue = JSON.stringify(value);
          } else if (Array.isArray(value)) {
            displayValue = `${value.length} ${t.items}`;
          } else {
            displayValue = String(value);
          }

          return (
            <div key={key} className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-2 text-xs">
              <span className="text-slate-400 capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
              <span className="break-words text-right font-mono text-slate-300">{displayValue}</span>
            </div>
          );
        })}
      </div>

      {result.reference && (
        <a
          href={result.reference}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-3 inline-flex min-h-11 items-center gap-1 text-xs text-teal-400 hover:text-teal-300"
        >
          {t.viewDetails}
          <ExternalLink className="h-3 w-3" />
        </a>
      )}
    </div>
  );
}

export function EnrichmentAggregatePanel({
  enrichment,
  lang,
}: {
  enrichment: EnrichmentResponse;
  lang: Language;
}) {
  const [providers, setProviders] = useState<ProviderConfigStatus[]>([]);
  const [providerStatusLoaded, setProviderStatusLoaded] = useState(false);
  const t = ENRICHMENT_TEXT[lang];

  useEffect(() => {
    const loadProviders = async () => {
      setProviderStatusLoaded(false);
      try {
        const data = await fetchEnrichmentProviders();
        setProviders(data.providers);
        setProviderStatusLoaded(true);
      } catch {
        setProviders([]);
        setProviderStatusLoaded(false);
      }
    };

    void loadProviders();
  }, []);

  if (enrichment.results.length === 0) {
    return (
      <div className="rounded border border-line/70 bg-panel-2 px-3 py-4">
        <p className="text-xs text-slate-500">{t.noResults}</p>
      </div>
    );
  }

  const configuredCount = providers.filter((p) => p.configured).length;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-xs font-semibold text-slate-300">{t.title}</div>
          <div className="mt-0.5 break-all font-mono text-[11px] text-slate-500">
            {enrichment.indicatorType.toUpperCase()} · {enrichment.indicator}
          </div>
        </div>
        <span className="text-xs text-slate-500">
          {providerStatusLoaded
            ? `${configuredCount} ${t.configured} / ${providers.length} ${t.available}`
            : t.providerStatusUnavailable}
        </span>
      </div>

      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
        {enrichment.results.map((result) => (
          <ProviderCard key={result.provider} result={result} lang={lang} />
        ))}
      </div>
    </div>
  );
}
