import { useEffect, useState } from 'react';
import {
  enrichIoc,
  fetchInvestigationHistory,
  investigateIoc,
  investigationReport,
} from '../api';
import { SOURCE_LABELS, TYPE_LABELS } from '../constants';
import type {
  EnrichmentResponse,
  IndicatorType,
  InvestigationHistoryEntry,
  IocInvestigation,
  ThreatIndicator,
} from '../types';
import { SeverityBadge } from './SeverityBadge';

const INDICATOR_TYPES: Array<IndicatorType | ''> = ['', 'ip', 'domain', 'url', 'hash', 'cidr', 'cve'];

function compact(value: string): string {
  return value.length > 42 ? `${value.slice(0, 24)}...${value.slice(-12)}` : value;
}

function SourceLine({ item }: { item: ThreatIndicator }) {
  return (
    <div className="grid gap-2 border-b border-white/5 px-4 py-3 last:border-b-0 md:grid-cols-[auto_1fr_auto] md:items-center">
      <SeverityBadge severity={item.severity} />
      <div className="min-w-0">
        <div className="truncate font-mono text-[12px] text-sky-300" title={item.indicator}>
          {compact(item.indicator)}
        </div>
        <div className="mt-1 truncate text-xs text-slate-500">
          {SOURCE_LABELS[item.source]} · {TYPE_LABELS[item.type]}
          {item.confidence !== undefined ? ` · C${item.confidence}` : ''}
        </div>
      </div>
      <div className="text-xs text-slate-500">{item.sourceReliability ? `R${item.sourceReliability}` : 'R-'}</div>
    </div>
  );
}

function downloadText(filename: string, text: string, mime = 'text/plain'): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function shortTime(ts: number): string {
  return new Date(ts).toLocaleTimeString();
}

export function IocInvestigationPanel() {
  const [indicator, setIndicator] = useState('');
  const [type, setType] = useState<IndicatorType | ''>('');
  const [loading, setLoading] = useState(false);
  const [enrichLoading, setEnrichLoading] = useState(false);
  const [exportLoading, setExportLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IocInvestigation | null>(null);
  const [enrichment, setEnrichment] = useState<EnrichmentResponse | null>(null);
  const [history, setHistory] = useState<InvestigationHistoryEntry[]>([]);

  const loadHistory = async () => {
    try {
      const res = await fetchInvestigationHistory(12);
      setHistory(res.points);
    } catch {
      // History is helpful but non-fatal.
    }
  };

  useEffect(() => {
    void loadHistory();
  }, []);

  const run = async () => {
    const value = indicator.trim();
    if (!value) return;
    setLoading(true);
    setError(null);
    setEnrichment(null);
    try {
      setResult(await investigateIoc(value, type));
      void loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Investigation failed');
    } finally {
      setLoading(false);
    }
  };

  const runEnrichment = async () => {
    if (!result) return;
    setEnrichLoading(true);
    setError(null);
    try {
      setEnrichment(await enrichIoc(result.indicator, result.indicatorType));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Enrichment failed');
    } finally {
      setEnrichLoading(false);
    }
  };

  const exportReport = async (format: 'markdown' | 'json') => {
    if (!result) return;
    setExportLoading(format);
    try {
      const text = await investigationReport(result.indicator, result.indicatorType, format);
      downloadText(
        `ioc-threat-model-${result.indicatorType}-${Date.now()}.${format === 'json' ? 'json' : 'md'}`,
        format === 'json' ? JSON.stringify(JSON.parse(text), null, 2) : text,
        format === 'json' ? 'application/json' : 'text/markdown',
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Report export failed');
    } finally {
      setExportLoading(null);
    }
  };

  const exact = result?.exactMatches ?? [];
  const related = result?.relatedIndicators ?? [];

  return (
    <div className="rounded-xl border border-white/10 bg-panel/70 shadow-lg">
      <div className="border-b border-white/10 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-200">IOC Investigation & Threat Model</h2>
        <div className="mt-3 grid gap-2 md:grid-cols-[1fr_160px_auto]">
          <input
            type="search"
            value={indicator}
            onChange={(event) => setIndicator(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') void run();
            }}
            placeholder="domain, IP, URL, hash, CIDR, CVE"
            className="rounded-lg border border-white/10 bg-panel-2 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-accent focus:outline-none"
          />
          <select
            value={type}
            onChange={(event) => setType(event.target.value as IndicatorType | '')}
            className="rounded-lg border border-white/10 bg-panel-2 px-3 py-2 text-sm text-slate-100 focus:border-accent focus:outline-none"
          >
            {INDICATOR_TYPES.map((item) => (
              <option key={item || 'auto'} value={item}>
                {item ? item.toUpperCase() : 'Auto type'}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => void run()}
            disabled={loading || !indicator.trim()}
            className="rounded-lg border border-sky-400/40 bg-sky-400/10 px-4 py-2 text-sm font-semibold text-sky-200 hover:bg-sky-400/15 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? 'Investigating' : 'Investigate IOC'}
          </button>
        </div>
        {error && <div className="mt-2 text-xs text-red-300">{error}</div>}
      </div>

      {result ? (
        <div className="grid gap-0 divide-y divide-white/5 lg:grid-cols-[360px_1fr] lg:divide-x lg:divide-y-0">
          <div>
            <div className="border-b border-white/5 px-4 py-3">
              <div className="text-xs text-slate-500">Posture</div>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <span className="rounded border border-white/10 bg-panel-2 px-2 py-1 text-xs font-semibold text-slate-200">
                  {result.model.posture.replace('_', ' ')}
                </span>
                {result.model.highestSeverity && <SeverityBadge severity={result.model.highestSeverity} />}
                <span className="text-xs text-slate-500">C{result.model.confidence || '-'}</span>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => void runEnrichment()}
                  disabled={enrichLoading}
                  className="rounded border border-sky-400/40 bg-sky-400/10 px-2 py-1 text-[11px] font-semibold text-sky-200 hover:bg-sky-400/15 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {enrichLoading ? 'Enriching' : 'Run enrichment'}
                </button>
                <button
                  type="button"
                  onClick={() => void exportReport('markdown')}
                  disabled={exportLoading !== null}
                  className="rounded border border-white/10 bg-panel-2 px-2 py-1 text-[11px] font-semibold text-slate-300 hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {exportLoading === 'markdown' ? 'Exporting' : 'Export Markdown'}
                </button>
                <button
                  type="button"
                  onClick={() => void exportReport('json')}
                  disabled={exportLoading !== null}
                  className="rounded border border-white/10 bg-panel-2 px-2 py-1 text-[11px] font-semibold text-slate-300 hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {exportLoading === 'json' ? 'Exporting' : 'Export JSON'}
                </button>
              </div>
            </div>
            <div className="max-h-[360px] overflow-auto">
              <div className="px-4 py-2 text-xs font-semibold text-slate-300">
                Exact matches ({exact.length})
              </div>
              {exact.length > 0 ? exact.map((item) => <SourceLine key={item.id} item={item} />) : null}
              <div className="border-t border-white/5 px-4 py-2 text-xs font-semibold text-slate-300">
                Related ({related.length})
              </div>
              {related.slice(0, 8).map((item) => (
                <SourceLine key={item.id} item={item} />
              ))}
              {exact.length === 0 && related.length === 0 && (
                <div className="px-4 py-8 text-center text-sm text-slate-400">No local evidence.</div>
              )}
              {history.length > 0 && (
                <div className="border-t border-white/5 px-4 py-3">
                  <div className="text-xs font-semibold text-slate-300">Recent investigations</div>
                  <div className="mt-2 space-y-2">
                    {history.slice(0, 6).map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => {
                          setIndicator(item.indicator);
                          setType(item.indicatorType);
                        }}
                        className="block w-full rounded border border-white/10 bg-panel-2 px-2 py-1 text-left text-xs text-slate-400 hover:bg-white/5"
                      >
                        <span className="font-mono text-sky-300">{compact(item.indicator)}</span>
                        <span className="ml-2">{item.posture.replace('_', ' ')}</span>
                        <span className="ml-2 text-slate-500">{shortTime(item.ts)}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
          <div className="max-h-[420px] overflow-auto">
            {enrichment && (
              <div className="border-b border-white/5 px-4 py-3">
                <div className="text-xs font-semibold text-slate-400">Enrichment</div>
                <div className="mt-2 grid gap-2 md:grid-cols-3">
                  {enrichment.results.length > 0 ? (
                    enrichment.results.map((item) => (
                      <div key={item.provider} className="rounded border border-white/10 bg-panel-2 p-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold capitalize text-slate-200">{item.provider}</span>
                          <span className={item.ok ? 'text-xs text-emerald-300' : 'text-xs text-red-300'}>
                            {item.ok ? 'ok' : 'failed'}
                          </span>
                        </div>
                        <div className="mt-1 max-h-16 overflow-hidden break-all text-[11px] text-slate-500">
                          {item.ok ? JSON.stringify(item.summary) : item.error}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500">No enrichment providers configured for this IOC type.</div>
                  )}
                </div>
              </div>
            )}
            {result.model.scenarios.map((scenario) => (
              <div key={scenario.id} className="border-b border-white/5 px-4 py-3 last:border-b-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded border border-white/10 bg-panel-2 px-2 py-1 text-[11px] font-semibold text-slate-300">
                    {scenario.stride}
                  </span>
                  <SeverityBadge severity={scenario.severity} />
                  <span className="text-xs text-slate-500">C{scenario.confidence || '-'}</span>
                </div>
                <div className="mt-2 text-sm font-semibold text-slate-100">{scenario.title}</div>
                <div className="mt-2 grid gap-2 md:grid-cols-2">
                  <div>
                    <div className="text-xs font-semibold text-slate-400">Evidence</div>
                    <ul className="mt-1 space-y-1 text-xs text-slate-500">
                      {scenario.evidence.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-400">Mitigation</div>
                    <ul className="mt-1 space-y-1 text-xs text-slate-500">
                      {scenario.recommendations.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ))}
            <div className="px-4 py-3">
              <div className="text-xs font-semibold text-slate-400">Next steps</div>
              <div className="mt-2 flex flex-wrap gap-2">
                {result.model.nextSteps.map((step) => (
                  <span key={step} className="rounded border border-white/10 bg-panel-2 px-2 py-1 text-xs text-slate-400">
                    {step}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="px-4 py-8 text-center text-sm text-slate-400">Search an observable to build a local model.</div>
      )}
    </div>
  );
}
