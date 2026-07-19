import { useMemo, type KeyboardEvent } from 'react';
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  AlertCircle,
  BookOpen,
  ChevronRight,
  ExternalLink,
  FileText,
  Network,
  RefreshCw,
  Rows3,
  ShieldCheck,
} from 'lucide-react';
import type { KnowledgeEntity, KnowledgeGraph, Language } from '../../types';
import {
  EntityTypeLabel,
  FactProvenance,
  formatDate,
  safeHttpUrl,
  TEXT,
  TlpBadge,
  TYPE_COLOR,
  type InspectorMode,
} from './shared';
import { graphElements } from './graphElements';

interface KnowledgeInspectorProps {
  lang: Language;
  selectedId: string | null;
  entity: KnowledgeEntity | null;
  graph: KnowledgeGraph | null;
  depth: number;
  mode: InspectorMode;
  entityLoading: boolean;
  graphLoading: boolean;
  detailError: string | null;
  graphError: string | null;
  onSelectEntity: (id: string) => void;
  onDepthChange: (depth: number) => void;
  onModeChange: (mode: InspectorMode) => void;
  onRefresh: () => void;
}

export function KnowledgeInspector({
  lang,
  selectedId,
  entity,
  graph,
  depth,
  mode,
  entityLoading,
  graphLoading,
  detailError,
  graphError,
  onSelectEntity,
  onDepthChange,
  onModeChange,
  onRefresh,
}: KnowledgeInspectorProps) {
  const t = TEXT[lang];
  const flow = useMemo(() => (graph ? graphElements(graph, lang) : { nodes: [], edges: [] }), [graph, lang]);
  const graphEntityById = useMemo(
    () => new Map((graph?.entities ?? []).map((item) => [item.id, item])),
    [graph],
  );
  const detailLoading = entityLoading || graphLoading;

  const handleTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>): void => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    const tabs = Array.from(
      event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]') ?? [],
    );
    if (tabs.length === 0) return;
    event.preventDefault();
    const current = tabs.indexOf(event.currentTarget);
    const next = event.key === 'Home'
      ? 0
      : event.key === 'End'
        ? tabs.length - 1
        : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    const tab = tabs[next];
    const nextMode = tab?.dataset.mode as InspectorMode | undefined;
    if (!tab || !nextMode) return;
    onModeChange(nextMode);
    tab.focus();
  };

  return (
    <section className="surface min-w-0 overflow-hidden rounded-lg">
      {detailLoading && !entity ? (
        <div className="min-h-[620px] animate-pulse p-5" role="status" aria-label={t.loading}>
          <div className="h-4 w-32 rounded bg-slate-700/70" />
          <div className="mt-3 h-7 w-2/3 rounded bg-slate-700/60" />
          <div className="mt-4 h-4 w-full rounded bg-slate-800/80" />
          <div className="mt-2 h-4 w-4/5 rounded bg-slate-800/80" />
          <div className="mt-8 h-[420px] rounded bg-slate-800/60" />
        </div>
      ) : detailError && selectedId ? (
        <div className="flex min-h-[620px] flex-col items-center justify-center px-6 text-center" role="alert">
          <AlertCircle className="h-8 w-8 text-red-300" aria-hidden="true" />
          <p className="mt-3 text-sm font-semibold text-slate-200">{t.detailFailed}</p>
          <p className="mt-1 max-w-md break-words text-xs leading-5 text-slate-500">{detailError}</p>
          <button
            type="button"
            onClick={onRefresh}
            className="primary-action control mt-4 inline-flex items-center gap-2 px-4 text-sm font-bold"
          >
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            {t.retry}
          </button>
        </div>
      ) : !entity ? (
        <div className="flex min-h-[620px] flex-col items-center justify-center px-6 text-center">
          <BookOpen className="h-8 w-8 text-slate-600" aria-hidden="true" />
          <p className="mt-3 max-w-sm text-sm leading-6 text-slate-400">{t.noSelection}</p>
        </div>
      ) : (
        <>
          <header className="border-b border-line/60 p-5">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <EntityTypeLabel entity={entity} lang={lang} />
                  <TlpBadge value={entity.tlp} />
                  <span className={`inline-flex min-h-6 items-center rounded border px-2 py-0.5 text-[11px] font-bold ${entity.revoked ? 'border-red-400/45 text-red-300' : 'border-emerald-400/40 text-emerald-300'}`}>
                    {entity.revoked ? t.revoked : t.active}
                  </span>
                </div>
                <h2 className="mt-2 break-words text-xl font-bold leading-8 text-slate-50">{entity.name}</h2>
                <p className="mt-1 break-all font-mono text-xs text-slate-500">{entity.id}</p>
                {entity.description && <p className="mt-3 max-w-4xl break-words text-sm leading-6 text-slate-300">{entity.description}</p>}
              </div>
              <button
                type="button"
                onClick={onRefresh}
                disabled={detailLoading}
                className="soft-action control inline-flex h-11 w-11 shrink-0 items-center justify-center disabled:opacity-50"
                aria-label={t.refresh}
                title={t.refresh}
              >
                <RefreshCw className={`h-4 w-4 ${detailLoading ? 'animate-spin' : ''}`} aria-hidden="true" />
              </button>
            </div>

            <dl className="mt-5 grid gap-x-5 gap-y-3 border-t border-line/45 pt-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-xs font-semibold text-slate-500">{t.confidence}</dt>
                <dd className="mt-1 text-sm font-bold text-slate-200">{entity.confidence !== undefined ? `${entity.confidence}%` : t.unknown}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold text-slate-500">{t.modified}</dt>
                <dd className="mt-1 text-sm font-semibold text-slate-300">{formatDate(entity.modifiedAt, lang)}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold text-slate-500">{t.sources}</dt>
                <dd className="mt-1 text-sm font-bold text-slate-200">{entity.sources.length.toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold text-slate-500">{t.evidence}</dt>
                <dd className="mt-1 text-sm font-bold text-slate-200">{entity.evidence.length.toLocaleString()}</dd>
              </div>
            </dl>

            {(entity.aliases.length > 0 || entity.validFrom || entity.validUntil) && (
              <div className="mt-4 grid gap-4 border-t border-line/45 pt-4 lg:grid-cols-[minmax(0,1fr)_minmax(240px,0.45fr)]">
                <div>
                  <div className="text-xs font-semibold text-slate-500">{t.aliases}</div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {entity.aliases.length > 0 ? entity.aliases.map((alias) => (
                      <span key={alias} className="rounded border border-line/65 bg-panel-2/75 px-2 py-1 text-xs text-slate-300">{alias}</span>
                    )) : <span className="text-xs text-slate-500">-</span>}
                  </div>
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-500">{t.validity}</div>
                  <div className="mt-2 text-xs leading-5 text-slate-300">{formatDate(entity.validFrom, lang)} - {formatDate(entity.validUntil, lang)}</div>
                </div>
              </div>
            )}
          </header>

          <div className="flex flex-col gap-3 border-b border-line/60 px-4 py-3 md:flex-row md:items-center md:justify-between">
            <div
              className="flex max-w-full overflow-x-auto rounded-lg border border-line/70 bg-panel-2/80 p-1"
              role="tablist"
              aria-label={t.inspectorViews}
            >
              {([
                ['graph', t.graph, Network],
                ['relations', t.relations, Rows3],
                ['evidence', t.evidence, FileText],
              ] as const).map(([value, label, Icon]) => (
                <button
                  key={value}
                  type="button"
                  role="tab"
                  id={`knowledge-tab-${value}`}
                  data-mode={value}
                  aria-controls={`knowledge-panel-${value}`}
                  aria-selected={mode === value}
                  tabIndex={mode === value ? 0 : -1}
                  onClick={() => onModeChange(value)}
                  onKeyDown={handleTabKeyDown}
                  className={`inline-flex min-h-11 shrink-0 items-center gap-2 rounded-md px-3 text-xs font-semibold transition ${mode === value ? 'bg-teal-300/15 text-teal-100' : 'text-slate-400 hover:bg-white/5 hover:text-slate-100'}`}
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                  {label}
                </button>
              ))}
            </div>
            {mode === 'graph' && (
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-slate-500">{t.depth}</span>
                <div className="flex rounded-lg border border-line/70 bg-panel-2/80 p-1">
                  {([1, 2, 3] as const).map((value) => (
                    <button
                      key={value}
                      type="button"
                      onClick={() => onDepthChange(value)}
                      aria-pressed={depth === value}
                      className={`h-11 min-h-11 w-11 rounded-md text-xs font-bold ${depth === value ? 'bg-slate-100/10 text-slate-100' : 'text-slate-400 hover:bg-white/5'}`}
                    >
                      {value}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {mode === 'graph' && (
            <div
              id="knowledge-panel-graph"
              role="tabpanel"
              aria-labelledby="knowledge-tab-graph"
              className="graph-canvas h-[520px] min-h-[420px] bg-panel/40"
            >
              {graphLoading ? (
                <div className="h-full animate-pulse p-5" role="status" aria-label={t.loading}>
                  <div className="h-full rounded bg-slate-800/60" />
                </div>
              ) : graphError ? (
                <div className="flex h-full flex-col items-center justify-center px-6 text-center" role="alert">
                  <AlertCircle className="h-7 w-7 text-red-300" aria-hidden="true" />
                  <p className="mt-3 text-sm font-semibold text-slate-200">{t.graphFailed}</p>
                  <p className="mt-1 max-w-md break-words text-xs leading-5 text-slate-500">{graphError}</p>
                  <button type="button" onClick={onRefresh} className="soft-action control mt-4 inline-flex items-center gap-2 px-4 text-sm font-semibold">
                    <RefreshCw className="h-4 w-4" aria-hidden="true" />{t.retry}
                  </button>
                </div>
              ) : graph ? (
                <ReactFlow
                  key={`${graph.rootId}:${graph.depth}:${flow.nodes.length}:${flow.edges.length}`}
                  nodes={flow.nodes}
                  edges={flow.edges}
                  fitView
                  fitViewOptions={{ padding: 0.18 }}
                  minZoom={0.3}
                  maxZoom={1.7}
                  nodesConnectable={false}
                  onNodeClick={(_, node) => onSelectEntity(node.id)}
                  proOptions={{ hideAttribution: true }}
                >
                  <Background color="#334155" gap={24} size={1} />
                  <Controls position="bottom-left" showInteractive={false} />
                  <MiniMap
                    pannable
                    zoomable
                    style={{ width: 150, height: 104 }}
                    nodeColor={(node) => TYPE_COLOR[graphEntityById.get(node.id)?.type ?? 'indicator']}
                  />
                </ReactFlow>
              ) : null}
            </div>
          )}

          {mode === 'relations' && (
            <div id="knowledge-panel-relations" role="tabpanel" aria-labelledby="knowledge-tab-relations">
              {graphError && (
                <div className="flex items-start justify-between gap-4 border-b border-red-400/35 bg-red-500/10 px-4 py-3 text-sm text-red-200" role="alert">
                  <span className="break-words">{t.graphFailed} {graphError}</span>
                  <button type="button" onClick={onRefresh} className="soft-action control shrink-0 px-3 text-xs font-semibold">{t.retry}</button>
                </div>
              )}
              {graphLoading && <div className="h-36 animate-pulse bg-slate-800/35" role="status" aria-label={t.loading} />}
              <div className="divide-y divide-line/45">
                {(graph?.relationships ?? []).map((relationship) => {
                  const source = graphEntityById.get(relationship.sourceRef);
                  const target = graphEntityById.get(relationship.targetRef);
                  return (
                    <details key={relationship.id} className="group">
                      <summary className="grid min-h-16 cursor-pointer list-none items-center gap-2 px-4 py-3 hover:bg-white/[0.035] sm:grid-cols-[1fr_auto_1fr_auto_auto]">
                        <span className="min-w-0 break-words text-sm font-semibold text-slate-200">{source?.name ?? relationship.sourceRef}</span>
                        <span className="font-mono text-xs font-semibold text-sky-300">{relationship.relationshipType}</span>
                        <span className="min-w-0 break-words text-sm font-semibold text-slate-200">{target?.name ?? relationship.targetRef}</span>
                        <span className="text-xs text-slate-400">{relationship.confidence !== undefined ? `${relationship.confidence}%` : t.unknown}</span>
                        <span className="flex items-center justify-between gap-2"><TlpBadge value={relationship.tlp} /><ChevronRight className="h-4 w-4 text-slate-500 transition-transform group-open:rotate-90" aria-hidden="true" /></span>
                      </summary>
                      <div className="flex flex-wrap items-center gap-2 border-t border-line/40 bg-panel-2/25 px-4 py-2">
                        <button type="button" onClick={() => onSelectEntity(relationship.sourceRef)} className="soft-action control px-3 text-xs font-semibold">{t.source}: {source?.name ?? relationship.sourceRef}</button>
                        <button type="button" onClick={() => onSelectEntity(relationship.targetRef)} className="soft-action control px-3 text-xs font-semibold">{t.target}: {target?.name ?? relationship.targetRef}</button>
                      </div>
                      <FactProvenance
                        description={relationship.description}
                        sources={relationship.sources}
                        evidence={relationship.evidence}
                        externalReferences={relationship.externalReferences}
                        validFrom={relationship.validFrom}
                        validUntil={relationship.validUntil}
                        lang={lang}
                      />
                    </details>
                  );
                })}
              </div>
              {!graphLoading && !graphError && (graph?.relationships.length ?? 0) === 0 && <div className="px-5 py-14 text-center text-sm text-slate-400">{t.noRelations}</div>}
              {(graph?.sightings.length ?? 0) > 0 && (
                <div className="border-t border-line/60">
                  <div className="px-4 py-3 text-xs font-bold text-slate-400">{t.sightings}</div>
                  <div className="divide-y divide-line/40">
                    {graph?.sightings.map((sighting) => (
                      <details key={sighting.id} className="group">
                        <summary className="grid min-h-14 cursor-pointer list-none items-center gap-2 px-4 py-3 hover:bg-white/[0.035] sm:grid-cols-[minmax(0,1fr)_auto_auto_auto]">
                          <span className="break-all font-mono text-xs text-slate-300">{sighting.id}</span>
                          <span className="text-xs text-slate-400">{t.count}: {sighting.count.toLocaleString()}</span>
                          <span className="text-xs text-slate-400">{t.lastSeen}: {formatDate(sighting.lastSeen, lang)}</span>
                          <span className="flex items-center gap-2"><TlpBadge value={sighting.tlp} /><ChevronRight className="h-4 w-4 text-slate-500 transition-transform group-open:rotate-90" aria-hidden="true" /></span>
                        </summary>
                        <FactProvenance
                          sources={sighting.sources}
                          evidence={sighting.evidence}
                          externalReferences={sighting.externalReferences}
                          validFrom={sighting.firstSeen}
                          validUntil={sighting.lastSeen}
                          lang={lang}
                        />
                      </details>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {mode === 'evidence' && (
            <div id="knowledge-panel-evidence" role="tabpanel" aria-labelledby="knowledge-tab-evidence" className="grid divide-y divide-line/50 lg:grid-cols-3 lg:divide-x lg:divide-y-0">
              <section className="min-w-0 p-4">
                <h3 className="flex items-center gap-2 text-sm font-bold text-slate-200"><ShieldCheck className="h-4 w-4 text-emerald-300" aria-hidden="true" />{t.sources}</h3>
                <div className="mt-3 divide-y divide-line/40">
                  {entity.sources.map((source, index) => (
                    <div key={`${source.kind}:${source.name}:${index}`} className="py-3 first:pt-0">
                      <div className="break-words text-sm font-semibold text-slate-200">{source.name}</div>
                      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-500">
                        <span>{source.kind}</span>
                        {source.reliability && <span>{source.reliability}</span>}
                        {source.collectedAt && <span>{formatDate(source.collectedAt, lang)}</span>}
                      </div>
                    </div>
                  ))}
                  {entity.sources.length === 0 && <p className="py-6 text-sm text-slate-500">{t.noSources}</p>}
                </div>
              </section>

              <section className="min-w-0 p-4">
                <h3 className="flex items-center gap-2 text-sm font-bold text-slate-200"><ExternalLink className="h-4 w-4 text-sky-300" aria-hidden="true" />{t.externalIds}</h3>
                <div className="mt-3 divide-y divide-line/40">
                  {entity.externalReferences.map((reference, index) => {
                    const href = safeHttpUrl(reference.url);
                    return (
                    <div key={`${reference.sourceName}:${reference.externalId ?? reference.url ?? index}`} className="py-3 first:pt-0">
                      <div className="text-xs font-semibold text-slate-500">{reference.sourceName}</div>
                      {href ? (
                        <a href={href} target="_blank" rel="noreferrer" className="mt-1 inline-flex max-w-full items-start gap-1 break-all text-sm font-semibold text-sky-300 hover:underline">
                          <span>{reference.externalId ?? reference.url}</span>
                          <ExternalLink className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                        </a>
                      ) : <div className="mt-1 break-all text-sm font-semibold text-slate-300">{reference.externalId ?? '-'}</div>}
                      {reference.description && <p className="mt-1 break-words text-xs leading-5 text-slate-500">{reference.description}</p>}
                    </div>
                    );
                  })}
                  {entity.externalReferences.length === 0 && <p className="py-6 text-sm text-slate-500">{t.noReferences}</p>}
                </div>
              </section>

              <section className="min-w-0 p-4">
                <h3 className="flex items-center gap-2 text-sm font-bold text-slate-200"><FileText className="h-4 w-4 text-purple-300" aria-hidden="true" />{t.evidence}</h3>
                <div className="mt-3 max-h-[520px] divide-y divide-line/40 overflow-y-auto pr-1">
                  {entity.evidence.map((item) => {
                    const href = safeHttpUrl(item.reference);
                    return (
                    <div key={item.id} className="py-3 first:pt-0">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-slate-500">{item.kind}</span>
                        <span className="flex items-center gap-2">
                          {item.confidence !== undefined && <span className="text-xs font-semibold text-slate-400">{item.confidence}%</span>}
                          {item.tlp && <TlpBadge value={item.tlp} />}
                        </span>
                      </div>
                      <p className="mt-1 break-words text-sm leading-5 text-slate-300">{item.summary}</p>
                      <div className="mt-2 space-y-1 text-xs text-slate-500">
                        <div>{item.source.name}</div>
                        <div>{t.collected}: {formatDate(item.collectedAt, lang)}</div>
                        {item.observedAt && <div>{t.observed}: {formatDate(item.observedAt, lang)}</div>}
                        {item.objectRefs.length > 0 && <div className="break-all">{t.objectRefs}: {item.objectRefs.join(', ')}</div>}
                      </div>
                      {href && (
                        <a href={href} target="_blank" rel="noreferrer" className="mt-2 inline-flex max-w-full items-start gap-1 break-all text-xs font-semibold text-sky-300 hover:underline">
                          <span>{item.reference}</span><ExternalLink className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                        </a>
                      )}
                    </div>
                    );
                  })}
                  {entity.evidence.length === 0 && <p className="py-6 text-sm text-slate-500">{t.noEvidence}</p>}
                </div>
              </section>
            </div>
          )}
        </>
      )}
    </section>
  );
}
