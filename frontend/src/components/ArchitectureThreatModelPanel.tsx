import { lazy, Suspense, useCallback, useEffect, useState } from 'react';
import { Download, RefreshCw } from 'lucide-react';
import { architectureReport, fetchArchitectureThreatModel } from '../api';
import type { ArchitectureThreatModel, Language, SourceHealth, StrideCategory } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { SOURCE_HEALTH_LABEL, STRIDE_LABEL, TREATMENT_LABEL, UI_TEXT } from '../i18n';
import type { GraphColumn, GraphEdge, GraphNode } from './GraphDiagram';

const GraphDiagram = lazy(() => import('./GraphDiagram').then((module) => ({ default: module.GraphDiagram })));

type ModelView = 'scenarios' | 'assets' | 'matrix' | 'controls';

function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function buildArchitectureGraph(model: ArchitectureThreatModel, sourceHealth: SourceHealth[], lang: Language) {
  const t = UI_TEXT[lang];
  const flow = model.dataFlows.find((item) => item.id === 'feed-flow') ?? model.dataFlows[0];
  const feedScenarioIds = model.scenarios
    .filter(
      (scenario) =>
        scenario.dataFlowIds?.includes('feed-flow') ||
        scenario.assetIds?.includes('feeds') ||
        scenario.assetIds?.includes('collectors'),
    )
    .slice(0, 5)
    .map((scenario) => scenario.id);
  const scenarioIds = feedScenarioIds.length > 0 ? feedScenarioIds : model.scenarios.slice(0, 5).map((scenario) => scenario.id);
  const controlIds = Array.from(
    new Set(
      model.scenarios
        .filter((scenario) => scenarioIds.includes(scenario.id))
        .flatMap((scenario) => scenario.controls ?? []),
    ),
  ).filter((controlId) => model.controls.some((control) => control.id === controlId));
  const sourceNodeIds = sourceHealth.map((source) => `source:${source.source}`);

  const nodes: GraphNode[] = [
    ...sourceHealth.map((source) => ({
      id: `source:${source.source}`,
      label: source.label,
      subLabel: `${SOURCE_HEALTH_LABEL[lang][source.status]} · ${source.count.toLocaleString()} ${t.items}`,
      kind: 'source' as const,
    })),
    ...(sourceHealth.length === 0
      ? [
          {
            id: 'source-unavailable',
            label: t.unavailable,
            subLabel: t.currentIntelSources,
            kind: 'status' as const,
          },
        ]
      : []),
    {
      id: 'feed-flow',
      label: flow?.name ?? t.collectionFlow,
      subLabel: flow ? `${flow.from} ${t.to} ${flow.to}` : t.dataFlows,
      kind: 'flow' as const,
    },
    ...model.scenarios
      .filter((scenario) => scenarioIds.includes(scenario.id))
      .map((scenario) => ({
        id: `scenario:${scenario.id}`,
        label: scenario.title,
        subLabel: `${STRIDE_LABEL[lang][scenario.stride]} · ${t.dread} ${scenario.dread?.total ?? '-'}/50`,
        kind: 'scenario' as const,
        severity: scenario.severity,
      })),
    ...model.controls
      .filter((control) => controlIds.includes(control.id))
      .map((control) => ({
        id: `control:${control.id}`,
        label: control.name,
        subLabel: `${TREATMENT_LABEL[lang][control.status]} · ${control.owner}`,
        kind: 'control' as const,
      })),
  ];

  const edges: GraphEdge[] = [];
  if (sourceNodeIds.length > 0) {
    for (const sourceNodeId of sourceNodeIds) edges.push({ from: sourceNodeId, to: 'feed-flow' });
  } else {
    edges.push({ from: 'source-unavailable', to: 'feed-flow', dashed: true });
  }
  for (const scenarioId of scenarioIds) edges.push({ from: 'feed-flow', to: `scenario:${scenarioId}` });
  for (const scenario of model.scenarios.filter((item) => scenarioIds.includes(item.id))) {
    for (const controlId of scenario.controls ?? []) {
      if (controlIds.includes(controlId)) edges.push({ from: `scenario:${scenario.id}`, to: `control:${controlId}` });
    }
  }

  const columns: GraphColumn[] = [
    {
      id: 'sources',
      title: t.currentIntelSources,
      nodeIds: sourceNodeIds.length > 0 ? sourceNodeIds : ['source-unavailable'],
    },
    { id: 'flow', title: t.collectionFlow, nodeIds: ['feed-flow'] },
    { id: 'scenarios', title: t.scenarios, nodeIds: scenarioIds.map((scenarioId) => `scenario:${scenarioId}`) },
    { id: 'controls', title: t.controls, nodeIds: controlIds.map((controlId) => `control:${controlId}`) },
  ].filter((column) => column.nodeIds.length > 0);

  return { nodes, edges, columns };
}

function SectionMetric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded border border-line/60 bg-panel-2/80 px-3 py-2">
      <div className="text-[11px] font-semibold text-slate-500">{label}</div>
      <div className="mt-1 text-sm font-bold text-slate-100">{value}</div>
    </div>
  );
}

export function ArchitectureThreatModelPanel({
  lang,
  sourceHealth,
}: {
  lang: Language;
  sourceHealth: SourceHealth[];
}) {
  const t = UI_TEXT[lang];
  const [model, setModel] = useState<ArchitectureThreatModel | null>(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);
  const [view, setView] = useState<ModelView>('scenarios');
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setModel(await fetchArchitectureThreatModel(lang));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.loadThreatModelFailed);
    } finally {
      setLoading(false);
    }
  }, [lang, t.loadThreatModelFailed]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!model) {
      setSelectedScenarioId(null);
      return;
    }
    if (!model.scenarios.some((scenario) => scenario.id === selectedScenarioId)) {
      setSelectedScenarioId(model.scenarios[0]?.id ?? null);
    }
  }, [model, selectedScenarioId]);

  const exportMarkdown = async () => {
    setExporting(true);
    try {
      downloadText(`architecture-threat-model-${Date.now()}.md`, await architectureReport('markdown', lang));
    } catch (err) {
      setError(err instanceof Error ? err.message : t.exportFailed);
    } finally {
      setExporting(false);
    }
  };

  const selectedScenario =
    model?.scenarios.find((scenario) => scenario.id === selectedScenarioId) ?? model?.scenarios[0] ?? null;
  const architectureGraph = model ? buildArchitectureGraph(model, sourceHealth, lang) : null;

  const viewLabels: Record<ModelView, string> = {
    scenarios: t.scenarios,
    assets: `${t.assets} / ${t.dataFlows}`,
    matrix: t.threatMatrix,
    controls: `${t.controls} / ${t.attackPaths}`,
  };

  return (
    <div className="surface overflow-hidden rounded-lg">
      <div className="flex flex-col gap-3 border-b border-line/60 bg-panel-2/45 px-4 py-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="section-title">{t.architectureTitle}</h2>
          <div className="mt-1 text-xs text-slate-500">
            {loading
              ? t.loading
              : model
                ? `${model.assets.length} ${t.assets} · ${model.dataFlows.length} ${t.flows} · ${model.scenarios.length} ${t.strideScenarios} · ${model.controls.length} ${t.controls}`
                : t.unavailable}
          </div>
          {model && (
            <div className="mt-1 text-xs text-slate-500">
              {model.methodology.framework} + {model.methodology.scoring} · {model.threatMatrix.length} {t.matrix} ·{' '}
              {model.attackPaths.length} {t.attackPaths}
            </div>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void load()}
            disabled={loading}
            className="primary-action control inline-flex items-center justify-center gap-2 px-4 text-xs font-bold disabled:opacity-60"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            {loading ? t.refreshing : t.refreshModel}
          </button>
          <button
            type="button"
            onClick={() => void exportMarkdown()}
            disabled={!model || exporting}
            className="soft-action control inline-flex items-center justify-center gap-2 px-4 text-xs font-bold disabled:opacity-60"
          >
            <Download className="h-4 w-4" aria-hidden="true" />
            {exporting ? t.exporting : t.exportMarkdown}
          </button>
        </div>
      </div>

      {error && <div className="border-b border-line/60 px-4 py-2 text-xs text-red-300">{error}</div>}

      {model ? (
        <div className="space-y-5 p-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <SectionMetric label={t.framework} value={model.methodology.framework} />
            <SectionMetric label={t.scoring} value={model.methodology.scoring} />
            <SectionMetric label={t.assets} value={model.assets.length.toLocaleString()} />
            <SectionMetric label={t.strideScenarios} value={model.scenarios.length.toLocaleString()} />
          </div>

          {architectureGraph && (
            <Suspense fallback={<div className="surface rounded-lg px-4 py-10 text-center text-sm text-slate-400">{t.loading}</div>}>
              <GraphDiagram
                title={t.architectureSourceGraph}
                nodes={architectureGraph.nodes}
                edges={architectureGraph.edges}
                columns={architectureGraph.columns}
                lang={lang}
              />
            </Suspense>
          )}

          <div className="flex flex-wrap gap-2 rounded-lg border border-line/60 bg-panel-2/65 p-1" role="tablist" aria-label={t.architectureTitle}>
            {(Object.keys(viewLabels) as ModelView[]).map((item) => (
              <button
                key={item}
                type="button"
                role="tab"
                aria-selected={view === item}
                onClick={() => setView(item)}
                className={`min-h-10 rounded-md px-3 text-xs font-semibold transition ${
                  view === item ? 'bg-teal-300/15 text-teal-100' : 'text-slate-400 hover:bg-white/5 hover:text-slate-100'
                }`}
              >
                {viewLabels[item]}
              </button>
            ))}
          </div>

          {view === 'scenarios' && (
            <div className="grid gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
              <section className="rounded-lg border border-line/60 bg-panel-2/65">
                <div className="border-b border-line/60 px-3 py-2 text-xs font-semibold text-slate-300">{t.topScenarios}</div>
                <div className="max-h-[560px] overflow-auto">
                  {model.scenarios.map((scenario) => (
                    <button
                      key={scenario.id}
                      type="button"
                      onClick={() => setSelectedScenarioId(scenario.id)}
                      className={`block w-full border-b border-line/40 px-3 py-3 text-left last:border-b-0 hover:bg-white/5 ${
                        selectedScenario?.id === scenario.id ? 'bg-teal-300/10' : ''
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[11px] font-semibold text-slate-400">{STRIDE_LABEL[lang][scenario.stride]}</span>
                        <SeverityBadge severity={scenario.severity} lang={lang} />
                      </div>
                      <div className="mt-2 text-xs font-semibold leading-5 text-slate-100">{scenario.title}</div>
                      {scenario.dread && (
                        <div className="mt-1 text-[11px] text-slate-500">
                          {t.dread} {scenario.dread.total}/50 · {t.riskAverage} {scenario.dread.average}
                        </div>
                      )}
                    </button>
                  ))}
                </div>
              </section>

              {selectedScenario && (
                <section className="rounded-lg border border-line/60 bg-panel-2/65 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded border border-line/70 bg-panel px-2 py-1 text-[11px] font-semibold text-slate-300">
                      {STRIDE_LABEL[lang][selectedScenario.stride]}
                    </span>
                    <SeverityBadge severity={selectedScenario.severity} lang={lang} />
                    {selectedScenario.treatment && (
                      <span className="rounded border border-line/70 px-2 py-1 text-[11px] font-semibold text-slate-400">
                        {t.treatment}: {TREATMENT_LABEL[lang][selectedScenario.treatment]}
                      </span>
                    )}
                  </div>
                  <h3 className="mt-3 text-lg font-semibold leading-7 text-slate-50">{selectedScenario.title}</h3>

                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    {selectedScenario.threat && (
                      <div>
                        <div className="text-xs font-semibold text-slate-400">{t.threat}</div>
                        <p className="mt-1 text-sm leading-6 text-slate-300">{selectedScenario.threat}</p>
                      </div>
                    )}
                    {selectedScenario.impact && (
                      <div>
                        <div className="text-xs font-semibold text-slate-400">{t.impact}</div>
                        <p className="mt-1 text-sm leading-6 text-slate-300">{selectedScenario.impact}</p>
                      </div>
                    )}
                  </div>

                  {selectedScenario.dread && (
                    <div className="mt-4 rounded border border-line/70 bg-panel px-3 py-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="text-xs font-semibold text-slate-300">
                          {t.dread} {selectedScenario.dread.total}/50
                        </div>
                        <div className="text-xs text-slate-500">
                          {t.riskAverage} {selectedScenario.dread.average}
                        </div>
                      </div>
                      <div className="mt-3 grid grid-cols-5 gap-2 text-center text-[11px] text-slate-300">
                        {[
                          selectedScenario.dread.damage,
                          selectedScenario.dread.reproducibility,
                          selectedScenario.dread.exploitability,
                          selectedScenario.dread.affectedUsers,
                          selectedScenario.dread.discoverability,
                        ].map((score, index) => (
                          <div key={index} className="rounded border border-line/70 px-2 py-2">
                            {score}
                          </div>
                        ))}
                      </div>
                      <ul className="mt-3 space-y-1 text-xs leading-5 text-slate-500">
                        {selectedScenario.dread.rationale.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    <div>
                      <div className="text-xs font-semibold text-slate-400">{t.evidence}</div>
                      <ul className="mt-1 space-y-1 text-xs leading-5 text-slate-500">
                        {selectedScenario.evidence.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-slate-400">{t.mitigation}</div>
                      <ul className="mt-1 space-y-1 text-xs leading-5 text-slate-500">
                        {selectedScenario.recommendations.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </section>
              )}
            </div>
          )}

          {view === 'assets' && (
            <div className="grid gap-4 xl:grid-cols-2">
              <section className="rounded-lg border border-line/60 bg-panel-2/65">
                <div className="border-b border-line/60 px-3 py-2 text-xs font-semibold text-slate-300">{t.assets}</div>
                <div className="divide-y divide-line/40">
                  {model.assets.map((asset) => (
                    <div key={asset.id} className="px-3 py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold text-slate-100">{asset.name}</span>
                        <SeverityBadge severity={asset.criticality} lang={lang} />
                      </div>
                      <div className="mt-1 text-xs text-slate-500">
                        {asset.kind} · {asset.trustZone}
                        {asset.owner ? ` · ${asset.owner}` : ''}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-lg border border-line/60 bg-panel-2/65">
                <div className="border-b border-line/60 px-3 py-2 text-xs font-semibold text-slate-300">{t.trustBoundaries}</div>
                <div className="divide-y divide-line/40">
                  {model.trustBoundaries.map((boundary) => (
                    <div key={boundary.id} className="px-3 py-3">
                      <div className="text-sm font-semibold text-slate-100">{boundary.name}</div>
                      <div className="mt-1 text-xs leading-5 text-slate-500">{boundary.description}</div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-lg border border-line/60 bg-panel-2/65 xl:col-span-2">
                <div className="border-b border-line/60 px-3 py-2 text-xs font-semibold text-slate-300">{t.dataFlows}</div>
                <div className="grid divide-y divide-line/40 lg:grid-cols-2 lg:divide-x lg:divide-y-0">
                  {model.dataFlows.map((flow) => (
                    <div key={flow.id} className="px-3 py-3">
                      <div className="text-sm font-semibold text-slate-100">{flow.name}</div>
                      <div className="mt-1 text-xs text-slate-500">
                        {flow.from} {'->'} {flow.to} · {flow.protocol}
                      </div>
                      {flow.threatSurface && <div className="mt-1 text-xs leading-5 text-slate-500">{flow.threatSurface.join(', ')}</div>}
                    </div>
                  ))}
                </div>
              </section>
            </div>
          )}

          {view === 'matrix' && (
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
              <section className="rounded-lg border border-line/60 bg-panel-2/65">
                <div className="border-b border-line/60 px-3 py-2 text-xs font-semibold text-slate-300">{t.threatMatrix}</div>
                <div className="overflow-x-auto">
                  <table className="data-table w-full min-w-[760px] border-collapse text-left text-sm">
                    <thead className="bg-panel">
                      <tr>
                        <th className="px-3 py-2">{t.indicator}</th>
                        <th className="px-3 py-2">{t.type}</th>
                        <th className="px-3 py-2">{t.severity}</th>
                        <th className="px-3 py-2">{t.scenarios}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {model.threatMatrix.map((row) => (
                        <tr key={`${row.elementType}-${row.elementId}`} className="border-t border-line/40">
                          <td className="px-3 py-2 font-semibold text-slate-100">{row.elementName}</td>
                          <td className="px-3 py-2 text-slate-400">{row.elementType}</td>
                          <td className="px-3 py-2">
                            <SeverityBadge severity={row.priority} lang={lang} />
                          </td>
                          <td className="px-3 py-2 text-xs leading-5 text-slate-500">
                            {Object.entries(row.stride)
                              .flatMap(([stride, values]) => values?.map((value) => `${STRIDE_LABEL[lang][stride as StrideCategory]}: ${value}`) ?? [])
                              .slice(0, 4)
                              .join(' · ')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <div className="space-y-4">
                <section className="rounded-lg border border-line/60 bg-panel-2/65 p-3">
                  <div className="text-xs font-semibold text-slate-300">{t.methodology}</div>
                  <ul className="mt-2 space-y-1 text-xs leading-5 text-slate-500">
                    {model.methodology.process.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </section>
                <section className="rounded-lg border border-line/60 bg-panel-2/65 p-3">
                  <div className="text-xs font-semibold text-slate-300">{t.assumptions}</div>
                  <ul className="mt-2 space-y-1 text-xs leading-5 text-slate-500">
                    {model.assumptions.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </section>
                <section className="rounded-lg border border-line/60 bg-panel-2/65 p-3">
                  <div className="text-xs font-semibold text-slate-300">{t.references}</div>
                  <div className="mt-2 space-y-2">
                    {model.methodology.references.map((reference) => (
                      <a key={reference.url} href={reference.url} target="_blank" rel="noreferrer" className="block text-xs text-sky-300 hover:underline">
                        {reference.title}
                      </a>
                    ))}
                  </div>
                </section>
              </div>
            </div>
          )}

          {view === 'controls' && (
            <div className="grid gap-4 xl:grid-cols-2">
              <section className="rounded-lg border border-line/60 bg-panel-2/65">
                <div className="border-b border-line/60 px-3 py-2 text-xs font-semibold text-slate-300">{t.attackPaths}</div>
                <div className="divide-y divide-line/40">
                  {model.attackPaths.map((path) => (
                    <div key={path.id} className="px-3 py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={path.severity} lang={lang} />
                        <span className="text-[11px] text-slate-500">{path.actor}</span>
                      </div>
                      <div className="mt-2 text-sm font-semibold leading-5 text-slate-100">{path.objective}</div>
                      <div className="mt-1 text-xs leading-5 text-slate-500">{path.path.join(' -> ')}</div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-lg border border-line/60 bg-panel-2/65">
                <div className="border-b border-line/60 px-3 py-2 text-xs font-semibold text-slate-300">{t.controls}</div>
                <div className="divide-y divide-line/40">
                  {model.controls.map((control) => (
                    <div key={control.id} className="px-3 py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded border border-line/70 px-2 py-0.5 text-[11px] font-semibold text-slate-400">
                          {TREATMENT_LABEL[lang][control.status]}
                        </span>
                        <span className="text-[11px] text-slate-500">{control.owner}</span>
                      </div>
                      <div className="mt-2 text-sm font-semibold leading-5 text-slate-100">{control.name}</div>
                      <div className="mt-1 text-xs leading-5 text-slate-500">{control.verification.join(' · ')}</div>
                    </div>
                  ))}
                </div>
              </section>
            </div>
          )}
        </div>
      ) : (
        <div className="px-4 py-10 text-center text-sm text-slate-400">{t.noArchitectureModel}</div>
      )}
    </div>
  );
}
