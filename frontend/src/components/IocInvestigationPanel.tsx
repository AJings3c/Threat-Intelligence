import { lazy, Suspense, useEffect, useState } from 'react';
import { Download, FileJson, FlaskConical, Search } from 'lucide-react';
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
  Language,
  ThreatIndicator,
  ThreatSource,
} from '../types';
import { SeverityBadge } from './SeverityBadge';
import { POSTURE_LABEL, STRIDE_LABEL, UI_TEXT } from '../i18n';
import type { GraphColumn, GraphEdge, GraphNode } from './GraphDiagram';

const GraphDiagram = lazy(() => import('./GraphDiagram').then((module) => ({ default: module.GraphDiagram })));

const INDICATOR_TYPES: Array<IndicatorType | ''> = ['', 'ip', 'domain', 'url', 'hash', 'cidr', 'cve'];

function compact(value: string): string {
  return value.length > 42 ? `${value.slice(0, 24)}...${value.slice(-12)}` : value;
}

function SourceLine({ item, lang }: { item: ThreatIndicator; lang: Language }) {
  return (
    <div className="grid gap-2 border-b border-line/40 px-4 py-3 last:border-b-0 md:grid-cols-[auto_1fr_auto] md:items-center">
      <SeverityBadge severity={item.severity} lang={lang} />
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

function graphIndicator(value: string): string {
  return value.length > 28 ? `${value.slice(0, 16)}...${value.slice(-8)}` : value;
}

function buildIocGraph(result: IocInvestigation, lang: Language) {
  const t = UI_TEXT[lang];
  const evidenceItems = [...result.exactMatches.slice(0, 4), ...result.relatedIndicators.slice(0, 8)];
  const sourceCounts = new Map<ThreatSource, number>();
  for (const item of result.sourceSummary) sourceCounts.set(item.source, item.count);
  for (const item of evidenceItems) {
    const sources = item.sources ?? [item.source];
    for (const source of sources) sourceCounts.set(source, sourceCounts.get(source) ?? 1);
  }

  const sourceNodes = Array.from(sourceCounts.keys()).map((source) => `source:${source}`);
  const evidenceNodes = evidenceItems.map((item) => `evidence:${item.id}`);
  const scenarioNodes = result.model.scenarios.map((scenario) => `scenario:${scenario.id}`);
  const actionNodes = result.model.nextSteps.slice(0, 4).map((_, index) => `action:${index}`);
  const hasSourceEvidence = sourceNodes.length > 0 && evidenceNodes.length > 0;

  const nodes: GraphNode[] = [
    {
      id: 'indicator',
      label: graphIndicator(result.indicator),
      subLabel: `${result.indicatorType.toUpperCase()} · ${POSTURE_LABEL[lang][result.model.posture]}`,
      kind: 'indicator',
      severity: result.model.highestSeverity ?? undefined,
    },
    ...Array.from(sourceCounts.entries()).map(([source, count]) => ({
      id: `source:${source}`,
      label: SOURCE_LABELS[source],
      subLabel: `${count} ${t.items}`,
      kind: 'source' as const,
    })),
    ...(hasSourceEvidence
      ? evidenceItems.map((item) => ({
          id: `evidence:${item.id}`,
          label: graphIndicator(item.indicator),
          subLabel: `${TYPE_LABELS[item.type]} · ${SOURCE_LABELS[item.source]}`,
          kind: 'evidence' as const,
          severity: item.severity,
        }))
      : [
          {
            id: 'no-source-evidence',
            label: t.noSourceBackedEvidence,
            subLabel: t.noLocalEvidence,
            kind: 'status' as const,
          },
        ]),
    ...result.model.scenarios.map((scenario) => ({
      id: `scenario:${scenario.id}`,
      label: scenario.title,
      subLabel: `${STRIDE_LABEL[lang][scenario.stride]} · ${t.confidenceShort}${scenario.confidence || '-'}`,
      kind: 'scenario' as const,
      severity: scenario.severity,
    })),
    ...result.model.nextSteps.slice(0, 4).map((step, index) => ({
      id: `action:${index}`,
      label: step,
      kind: 'action' as const,
    })),
  ];

  const edges: GraphEdge[] = [];
  if (hasSourceEvidence) {
    for (const sourceNode of sourceNodes) edges.push({ from: 'indicator', to: sourceNode });
    for (const item of evidenceItems) {
      const sources = item.sources ?? [item.source];
      for (const source of sources) {
        if (sourceCounts.has(source)) edges.push({ from: `source:${source}`, to: `evidence:${item.id}` });
      }
      for (const scenarioNode of scenarioNodes) edges.push({ from: `evidence:${item.id}`, to: scenarioNode });
    }
  } else {
    edges.push({ from: 'indicator', to: 'no-source-evidence', dashed: true });
    for (const scenarioNode of scenarioNodes) edges.push({ from: 'no-source-evidence', to: scenarioNode, dashed: true });
  }
  for (const scenarioNode of scenarioNodes) {
    for (const actionNode of actionNodes) edges.push({ from: scenarioNode, to: actionNode });
  }

  const columns: GraphColumn[] = [
    { id: 'indicator', title: t.indicator, nodeIds: ['indicator'] },
    { id: 'sources', title: t.sourceEvidence, nodeIds: hasSourceEvidence ? sourceNodes : ['no-source-evidence'] },
    { id: 'evidence', title: t.exactAndRelated, nodeIds: evidenceNodes },
    { id: 'scenarios', title: t.scenarios, nodeIds: scenarioNodes },
    { id: 'actions', title: t.actions, nodeIds: actionNodes },
  ].filter((column) => column.nodeIds.length > 0);

  return { nodes, edges, columns };
}

export function IocInvestigationPanel({
  lang,
  initialIndicator,
  initialNonce = 0,
}: {
  lang: Language;
  initialIndicator?: string;
  initialNonce?: number;
}) {
  const t = UI_TEXT[lang];
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

  useEffect(() => {
    setResult(null);
    setEnrichment(null);
  }, [lang]);

  const run = async (overrideValue?: string, overrideType?: IndicatorType | '') => {
    const value = (overrideValue ?? indicator).trim();
    if (!value) return;
    if (overrideValue !== undefined) setIndicator(value);
    setLoading(true);
    setError(null);
    setEnrichment(null);
    try {
      setResult(await investigateIoc(value, overrideType ?? type, lang));
      void loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : t.investigationFailed);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const value = initialIndicator?.trim();
    if (!value || initialNonce === 0) return;
    setType('');
    void run(value, '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialNonce]);

  const runEnrichment = async () => {
    if (!result) return;
    setEnrichLoading(true);
    setError(null);
    try {
      setEnrichment(await enrichIoc(result.indicator, result.indicatorType));
    } catch (err) {
      setError(err instanceof Error ? err.message : t.enrichmentFailed);
    } finally {
      setEnrichLoading(false);
    }
  };

  const exportReport = async (format: 'markdown' | 'json') => {
    if (!result) return;
    setExportLoading(format);
    try {
      const text = await investigationReport(result.indicator, result.indicatorType, format, lang);
      downloadText(
        `ioc-threat-model-${result.indicatorType}-${Date.now()}.${format === 'json' ? 'json' : 'md'}`,
        format === 'json' ? JSON.stringify(JSON.parse(text), null, 2) : text,
        format === 'json' ? 'application/json' : 'text/markdown',
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : t.reportExportFailed);
    } finally {
      setExportLoading(null);
    }
  };

  const exact = result?.exactMatches ?? [];
  const related = result?.relatedIndicators ?? [];
  const iocGraph = result ? buildIocGraph(result, lang) : null;

  return (
    <div className="surface overflow-hidden rounded-lg">
      <div className="border-b border-line/60 bg-panel-2/45 px-4 py-4">
        <h2 className="section-title">{t.iocTitle}</h2>
        <div className="mt-3 grid gap-2 md:grid-cols-[1fr_160px_auto]">
          <input
            type="search"
            value={indicator}
            onChange={(event) => setIndicator(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') void run();
            }}
            placeholder={t.iocPlaceholder}
            className="control px-3 text-sm placeholder:text-slate-600"
          />
          <select
            value={type}
            onChange={(event) => setType(event.target.value as IndicatorType | '')}
            className="control px-3 text-sm"
          >
            {INDICATOR_TYPES.map((item) => (
              <option key={item || 'auto'} value={item}>
                {item ? item.toUpperCase() : t.autoType}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => void run()}
            disabled={loading || !indicator.trim()}
            className="primary-action control inline-flex items-center justify-center gap-2 px-4 text-sm font-bold disabled:opacity-60"
          >
            <Search className="h-4 w-4" aria-hidden="true" />
            {loading ? t.investigating : t.investigate}
          </button>
        </div>
        {error && <div className="mt-2 text-xs text-red-300">{error}</div>}
      </div>

      {result ? (
        <>
          <div className="grid gap-0 divide-y divide-line/50 lg:grid-cols-[380px_1fr] lg:divide-x lg:divide-y-0">
            <div>
              <div className="border-b border-line/50 px-4 py-4">
                <div className="text-xs text-slate-500">{t.posture}</div>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <span className="rounded border border-line/70 bg-panel-2 px-2 py-1 text-xs font-semibold text-slate-200">
                    {POSTURE_LABEL[lang][result.model.posture]}
                  </span>
                  {result.model.highestSeverity && <SeverityBadge severity={result.model.highestSeverity} lang={lang} />}
                  <span className="text-xs text-slate-500">
                    {t.confidenceShort}
                    {result.model.confidence || '-'}
                  </span>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => void runEnrichment()}
                    disabled={enrichLoading}
                    className="primary-action inline-flex min-h-9 items-center gap-1.5 rounded px-3 text-xs font-semibold disabled:opacity-60"
                  >
                    <FlaskConical className="h-3.5 w-3.5" aria-hidden="true" />
                    {enrichLoading ? t.enriching : t.runEnrichment}
                  </button>
                  <button
                    type="button"
                    onClick={() => void exportReport('markdown')}
                    disabled={exportLoading !== null}
                    className="soft-action inline-flex min-h-9 items-center gap-1.5 rounded px-3 text-xs font-semibold disabled:opacity-60"
                  >
                    <Download className="h-3.5 w-3.5" aria-hidden="true" />
                    {exportLoading === 'markdown' ? t.exporting : t.exportMarkdown}
                  </button>
                  <button
                    type="button"
                    onClick={() => void exportReport('json')}
                    disabled={exportLoading !== null}
                    className="soft-action inline-flex min-h-9 items-center gap-1.5 rounded px-3 text-xs font-semibold disabled:opacity-60"
                  >
                    <FileJson className="h-3.5 w-3.5" aria-hidden="true" />
                    {exportLoading === 'json' ? t.exporting : t.exportJson}
                  </button>
                </div>
              </div>
              <div>
                <div className="px-4 py-2 text-xs font-semibold text-slate-300">
                  {t.exactMatches} ({exact.length})
                </div>
                {exact.length > 0 ? exact.map((item) => <SourceLine key={item.id} item={item} lang={lang} />) : null}
                <div className="border-t border-line/40 px-4 py-2 text-xs font-semibold text-slate-300">
                  {t.related} ({related.length})
                </div>
                {related.slice(0, 8).map((item) => (
                  <SourceLine key={item.id} item={item} lang={lang} />
                ))}
                {exact.length === 0 && related.length === 0 && (
                  <div className="px-4 py-8 text-center text-sm text-slate-400">{t.noLocalEvidence}</div>
                )}
                {history.length > 0 && (
                  <div className="border-t border-line/40 px-4 py-3">
                    <div className="text-xs font-semibold text-slate-300">{t.recentInvestigations}</div>
                    <div className="mt-2 space-y-2">
                      {history.slice(0, 6).map((item) => (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => {
                            setIndicator(item.indicator);
                            setType(item.indicatorType);
                            void run(item.indicator, item.indicatorType);
                          }}
                          className="block min-h-10 w-full rounded border border-line/70 bg-panel-2 px-2 py-1 text-left text-xs text-slate-400 hover:bg-white/5"
                        >
                          <span className="font-mono text-sky-300">{compact(item.indicator)}</span>
                          <span className="ml-2">{POSTURE_LABEL[lang][item.posture]}</span>
                          <span className="ml-2 text-slate-500">{shortTime(item.ts)}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div>
              {enrichment && (
                <div className="border-b border-line/50 px-4 py-3">
                  <div className="text-xs font-semibold text-slate-400">{t.enrichment}</div>
                  <div className="mt-2 grid gap-2 md:grid-cols-3">
                    {enrichment.results.length > 0 ? (
                      enrichment.results.map((item) => (
                        <div key={item.provider} className="rounded border border-line/70 bg-panel-2 p-2">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-semibold capitalize text-slate-200">{item.provider}</span>
                            <span className={item.ok ? 'text-xs text-emerald-300' : 'text-xs text-red-300'}>
                              {item.ok ? t.ok : t.failed}
                            </span>
                          </div>
                          <div className="mt-1 max-h-16 overflow-hidden break-all text-[11px] text-slate-500">
                            {item.ok ? JSON.stringify(item.summary) : item.error}
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-xs text-slate-500">{t.noEnrichmentProviders}</div>
                    )}
                  </div>
                </div>
              )}
              {result.model.scenarios.map((scenario) => (
                <div key={scenario.id} className="border-b border-line/50 px-4 py-4 last:border-b-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded border border-line/70 bg-panel-2 px-2 py-1 text-[11px] font-semibold text-slate-300">
                      {STRIDE_LABEL[lang][scenario.stride]}
                    </span>
                    <SeverityBadge severity={scenario.severity} lang={lang} />
                    <span className="text-xs text-slate-500">
                      {t.confidenceShort}
                      {scenario.confidence || '-'}
                    </span>
                  </div>
                  <div className="mt-2 text-sm font-semibold text-slate-100">{scenario.title}</div>
                  <div className="mt-2 grid gap-2 md:grid-cols-2">
                    <div>
                      <div className="text-xs font-semibold text-slate-400">{t.evidence}</div>
                      <ul className="mt-1 space-y-1 text-xs text-slate-500">
                        {scenario.evidence.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-slate-400">{t.mitigation}</div>
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
                <div className="text-xs font-semibold text-slate-400">{t.nextSteps}</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {result.model.nextSteps.map((step) => (
                    <span key={step} className="rounded border border-line/70 bg-panel-2 px-2 py-1 text-xs text-slate-400">
                      {step}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
          {iocGraph && (
            <div className="border-t border-line/60 p-4">
              <Suspense fallback={<div className="surface rounded-lg px-4 py-10 text-center text-sm text-slate-400">{t.loading}</div>}>
                <GraphDiagram
                  title={t.sourceEvidenceGraph}
                  nodes={iocGraph.nodes}
                  edges={iocGraph.edges}
                  columns={iocGraph.columns}
                  lang={lang}
                />
              </Suspense>
            </div>
          )}
        </>
      ) : (
        <div className="px-4 py-8 text-center text-sm text-slate-400">{t.searchEmpty}</div>
      )}
    </div>
  );
}
