import { useCallback, useEffect, useState } from 'react';
import { AlertCircle } from 'lucide-react';
import {
  fetchKnowledgeEntities,
  fetchKnowledgeEntity,
  fetchKnowledgeGraph,
  fetchKnowledgeTypes,
} from '../api';
import type {
  KnowledgeEntity,
  KnowledgeEntityPage,
  KnowledgeEntityType,
  KnowledgeGraph,
  Language,
} from '../types';
import { KnowledgeDirectory } from './knowledge/KnowledgeDirectory';
import { KnowledgeInspector } from './knowledge/KnowledgeInspector';
import { TEXT, type InspectorMode } from './knowledge/shared';

const PAGE_SIZE = 40;
const FALLBACK_TYPES: KnowledgeEntityType[] = [
  'threat-actor',
  'intrusion-set',
  'campaign',
  'malware',
  'tool',
  'attack-pattern',
  'identity',
  'vulnerability',
  'infrastructure',
  'indicator',
];

export function KnowledgeWorkspace({ lang }: { lang: Language }) {
  const t = TEXT[lang];
  const [availableTypes, setAvailableTypes] = useState<KnowledgeEntityType[]>(FALLBACK_TYPES);
  const [type, setType] = useState<KnowledgeEntityType | 'all'>('all');
  const [searchInput, setSearchInput] = useState('');
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<KnowledgeEntityPage>({ entities: [], total: 0, limit: PAGE_SIZE, offset: 0 });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [entity, setEntity] = useState<KnowledgeEntity | null>(null);
  const [graph, setGraph] = useState<KnowledgeGraph | null>(null);
  const [depth, setDepth] = useState(1);
  const [mode, setMode] = useState<InspectorMode>('graph');
  const [listLoading, setListLoading] = useState(true);
  const [entityLoading, setEntityLoading] = useState(false);
  const [graphLoading, setGraphLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [detailNonce, setDetailNonce] = useState(0);

  useEffect(() => {
    let current = true;
    fetchKnowledgeTypes()
      .then((response) => {
        if (current && response.entityTypes.length > 0) setAvailableTypes(response.entityTypes);
      })
      .catch(() => undefined);
    return () => {
      current = false;
    };
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setQuery(searchInput.trim());
      setOffset(0);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [searchInput]);

  useEffect(() => {
    let current = true;
    setListLoading(true);
    setError(null);
    fetchKnowledgeEntities({
      types: type === 'all' ? undefined : [type],
      q: query || undefined,
      limit: PAGE_SIZE,
      offset,
    })
      .then((response) => {
        if (!current) return;
        setPage(response);
        setSelectedId((previous) =>
          previous && response.entities.some((item) => item.id === previous)
            ? previous
            : (response.entities[0]?.id ?? null),
        );
      })
      .catch((reason: unknown) => {
        if (!current) return;
        setPage({ entities: [], total: 0, limit: PAGE_SIZE, offset });
        setSelectedId(null);
        setError(reason instanceof Error ? reason.message : '');
      })
      .finally(() => {
        if (current) setListLoading(false);
      });
    return () => {
      current = false;
    };
  }, [offset, query, type]);

  useEffect(() => {
    if (!selectedId) {
      setEntity(null);
      setEntityLoading(false);
      setDetailError(null);
      return;
    }
    let current = true;
    setEntity(null);
    setEntityLoading(true);
    setDetailError(null);
    fetchKnowledgeEntity(selectedId)
      .then((nextEntity) => {
        if (!current) return;
        setEntity(nextEntity);
      })
      .catch((reason: unknown) => {
        if (!current) return;
        setEntity(null);
        setDetailError(reason instanceof Error ? reason.message : t.detailFailed);
      })
      .finally(() => {
        if (current) setEntityLoading(false);
      });
    return () => {
      current = false;
    };
  }, [detailNonce, selectedId, t.detailFailed]);

  useEffect(() => {
    if (!selectedId) {
      setGraph(null);
      setGraphLoading(false);
      setGraphError(null);
      return;
    }
    let current = true;
    setGraph(null);
    setGraphLoading(true);
    setGraphError(null);
    fetchKnowledgeGraph(selectedId, depth)
      .then((nextGraph) => {
        if (current) setGraph(nextGraph);
      })
      .catch((reason: unknown) => {
        if (!current) return;
        setGraph(null);
        setGraphError(reason instanceof Error ? reason.message : t.graphFailed);
      })
      .finally(() => {
        if (current) setGraphLoading(false);
      });
    return () => {
      current = false;
    };
  }, [depth, detailNonce, selectedId, t.graphFailed]);

  const selectEntity = useCallback((id: string) => {
    if (id === selectedId) return;
    setEntity(null);
    setGraph(null);
    setDetailError(null);
    setGraphError(null);
    setSelectedId(id);
  }, [selectedId]);

  return (
    <div className="space-y-4">
      {error !== null && (
        <div className="flex items-start gap-3 rounded-lg border border-red-400/45 bg-red-500/10 px-4 py-3 text-sm text-red-200" role="alert">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <div>
            <div className="font-semibold">{t.unavailable}</div>
            {error && <div className="mt-1 break-words text-xs text-red-200/90">{error}</div>}
          </div>
        </div>
      )}

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(320px,0.78fr)_minmax(0,1.8fr)]">
        <KnowledgeDirectory
          lang={lang}
          availableTypes={availableTypes}
          selectedType={type}
          searchInput={searchInput}
          page={page}
          offset={offset}
          selectedId={selectedId}
          loading={listLoading}
          failed={error !== null}
          onSearchInputChange={setSearchInput}
          onTypeChange={(value) => {
            setType(value);
            setOffset(0);
          }}
          onSelectEntity={selectEntity}
          onPreviousPage={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          onNextPage={() => setOffset(offset + PAGE_SIZE)}
        />
        <KnowledgeInspector
          lang={lang}
          selectedId={selectedId}
          entity={entity}
          graph={graph}
          depth={depth}
          mode={mode}
          entityLoading={entityLoading}
          graphLoading={graphLoading}
          detailError={detailError}
          graphError={graphError}
          onSelectEntity={selectEntity}
          onDepthChange={setDepth}
          onModeChange={setMode}
          onRefresh={() => setDetailNonce((value) => value + 1)}
        />
      </div>
    </div>
  );
}
