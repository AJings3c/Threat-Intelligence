import { AlertCircle, BookOpen, ChevronLeft, ChevronRight, Search, X } from 'lucide-react';
import type { KnowledgeEntityPage, KnowledgeEntityType, Language } from '../../types';
import { EntityTypeLabel, LoadingRows, TEXT, TlpBadge, TYPE_LABEL } from './shared';

interface KnowledgeDirectoryProps {
  lang: Language;
  availableTypes: KnowledgeEntityType[];
  selectedType: KnowledgeEntityType | 'all';
  searchInput: string;
  page: KnowledgeEntityPage;
  offset: number;
  selectedId: string | null;
  loading: boolean;
  failed: boolean;
  onSearchInputChange: (value: string) => void;
  onTypeChange: (value: KnowledgeEntityType | 'all') => void;
  onSelectEntity: (id: string) => void;
  onPreviousPage: () => void;
  onNextPage: () => void;
}

export function KnowledgeDirectory({
  lang,
  availableTypes,
  selectedType,
  searchInput,
  page,
  offset,
  selectedId,
  loading,
  failed,
  onSearchInputChange,
  onTypeChange,
  onSelectEntity,
  onPreviousPage,
  onNextPage,
}: KnowledgeDirectoryProps) {
  const t = TEXT[lang];
  const totalPages = Math.max(1, Math.ceil(page.total / Math.max(1, page.limit)));
  const currentPage = Math.floor(page.offset / Math.max(1, page.limit)) + 1;

  return (
    <section className="surface overflow-hidden rounded-lg xl:sticky xl:top-[112px]">
      <div className="border-b border-line/60 p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-teal-200" aria-hidden="true" />
            <h2 className="section-title">{t.directory}</h2>
          </div>
          <span className="text-xs font-semibold text-slate-500">{page.total.toLocaleString()} {t.resultCount}</span>
        </div>
        <div className="mt-3 space-y-2">
          <label className="relative block">
            <span className="sr-only">{t.search}</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" aria-hidden="true" />
            <input
              type="search"
              maxLength={200}
              value={searchInput}
              onChange={(event) => onSearchInputChange(event.target.value)}
              placeholder={t.search}
              className="control w-full pl-10 pr-11 text-sm placeholder:text-slate-500"
            />
            {searchInput && (
              <button
                type="button"
                onClick={() => onSearchInputChange('')}
                className="absolute right-0 top-1/2 flex h-11 min-h-11 w-11 -translate-y-1/2 items-center justify-center rounded text-slate-400 hover:bg-white/5 hover:text-slate-100"
                aria-label={t.clearSearch}
                title={t.clearSearch}
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            )}
          </label>
          <label className="block">
            <span className="sr-only">{t.allTypes}</span>
            <select
              value={selectedType}
              onChange={(event) => onTypeChange(event.target.value as KnowledgeEntityType | 'all')}
              className="control w-full px-3 text-sm"
            >
              <option value="all">{t.allTypes}</option>
              {availableTypes.map((item) => (
                <option key={item} value={item}>{TYPE_LABEL[lang][item]}</option>
              ))}
            </select>
          </label>
        </div>
      </div>

      <div className="max-h-[56dvh] min-h-[360px] overflow-y-auto xl:max-h-[calc(100dvh-25rem)]">
        {loading ? (
          <LoadingRows />
        ) : failed ? (
          <div className="flex min-h-[300px] flex-col items-center justify-center px-6 text-center">
            <AlertCircle className="h-7 w-7 text-red-300" aria-hidden="true" />
            <p className="mt-3 max-w-xs text-sm leading-6 text-slate-400">{t.unavailable}</p>
          </div>
        ) : page.entities.length === 0 ? (
          <div className="flex min-h-[300px] flex-col items-center justify-center px-6 text-center">
            <Search className="h-7 w-7 text-slate-600" aria-hidden="true" />
            <p className="mt-3 max-w-xs text-sm leading-6 text-slate-400">{t.noEntities}</p>
          </div>
        ) : (
          <div className="divide-y divide-line/40">
            {page.entities.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectEntity(item.id)}
                data-active={selectedId === item.id}
                aria-pressed={selectedId === item.id}
                className="block w-full px-4 py-3 text-left transition hover:bg-white/[0.04] data-[active=true]:bg-teal-300/10"
              >
                <div className="flex items-center justify-between gap-2">
                  <EntityTypeLabel entity={item} lang={lang} />
                  <TlpBadge value={item.tlp} />
                </div>
                <div className="mt-1.5 break-words text-sm font-bold leading-5 text-slate-100">{item.name}</div>
                <div className="mt-1 flex min-w-0 items-center justify-between gap-3 text-xs text-slate-500">
                  <span className="truncate font-mono">{item.id}</span>
                  <span className="shrink-0">{item.confidence ?? '-'}{item.confidence !== undefined ? '%' : ''}</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between gap-2 border-t border-line/60 px-3 py-2">
        <button
          type="button"
          onClick={onPreviousPage}
          disabled={offset === 0 || loading}
          className="soft-action control inline-flex h-11 w-11 items-center justify-center disabled:opacity-40"
          aria-label={t.previous}
          title={t.previous}
        >
          <ChevronLeft className="h-4 w-4" aria-hidden="true" />
        </button>
        <span className="text-xs font-semibold text-slate-500">
          {lang === 'zh' ? `${t.page} ${currentPage} ${t.of} ${totalPages} 页` : `${t.page} ${currentPage} ${t.of} ${totalPages}`}
        </span>
        <button
          type="button"
          onClick={onNextPage}
          disabled={offset + page.limit >= page.total || loading}
          className="soft-action control inline-flex h-11 w-11 items-center justify-center disabled:opacity-40"
          aria-label={t.next}
          title={t.next}
        >
          <ChevronRight className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
    </section>
  );
}
