import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { ExternalLink, X } from 'lucide-react';
import type { Language, ThreatIndicator } from '../types';
import { SOURCE_LABELS } from '../constants';
import { THREAT_TYPE_LABEL, UI_TEXT } from '../i18n';
import { SeverityBadge } from './SeverityBadge';

const TABLE_TEXT: Record<
  Language,
  { clear: string; tags: string; reference: string; evidenceMeta: string; selectIndicator: string }
> = {
  en: {
    clear: 'Clear selected indicator',
    tags: 'Tags',
    reference: 'Open reference',
    evidenceMeta: 'Confidence / Reliability / TLP',
    selectIndicator: 'Select an indicator row to inspect source, confidence, tags and reference evidence.',
  },
  zh: {
    clear: '清除选中指标',
    tags: '标签',
    reference: '打开参考链接',
    evidenceMeta: '置信度 / 可靠性 / TLP',
    selectIndicator: '选择一条指标记录，查看来源、置信度、标签和参考证据。',
  },
};

function timeAgo(iso: string | undefined, lang: Language): string {
  if (!iso) return '-';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '-';
  const diff = Date.now() - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return lang === 'zh' ? `${mins} 分钟前` : `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return lang === 'zh' ? `${hrs} 小时前` : `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return lang === 'zh' ? `${days} 天前` : `${days}d ago`;
}

function compact(value: string, max = 72): string {
  return value.length > max ? `${value.slice(0, max - 14)}...${value.slice(-10)}` : value;
}

function DetailRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded border border-line/60 bg-panel-2/70 px-3 py-2">
      <div className="text-[11px] font-semibold text-slate-500">{label}</div>
      <div className="mt-1 break-words text-xs leading-5 text-slate-300">{value}</div>
    </div>
  );
}

export function ThreatTable({
  threats,
  total,
  loading,
  lang,
}: {
  threats: ThreatIndicator[];
  total: number;
  loading: boolean;
  lang: Language;
}) {
  const t = UI_TEXT[lang];
  const copy = TABLE_TEXT[lang];
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedThreat = useMemo(
    () => (selectedId ? threats.find((threat) => threat.id === selectedId) ?? null : null),
    [selectedId, threats],
  );

  useEffect(() => {
    if (!selectedId) return;
    if (!threats.some((threat) => threat.id === selectedId)) setSelectedId(null);
  }, [selectedId, threats]);

  return (
    <div className="surface overflow-hidden rounded-lg">
      <div className="flex flex-col gap-2 border-b border-line/60 bg-panel-2/45 px-4 py-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="section-title">{t.liveThreatFeed}</h2>
          <p className="section-kicker">
            {loading ? t.loading : `${threats.length} / ${total.toLocaleString()} ${t.matches}`}
          </p>
        </div>
      </div>

      <div className="grid gap-0 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="overflow-x-auto">
          <table className="data-table w-full min-w-[900px] border-collapse text-left text-sm">
            <thead className="sticky top-0 z-10 bg-panel-2 text-slate-400">
              <tr>
                <th className="px-4 py-3">{t.severity}</th>
                <th className="px-4 py-3">{t.indicator}</th>
                <th className="px-4 py-3">{t.type}</th>
                <th className="px-4 py-3">{t.source}</th>
                <th className="px-4 py-3">{t.country}</th>
                <th className="px-4 py-3">{t.lastSeen}</th>
              </tr>
            </thead>
            <tbody>
              {loading && threats.length === 0
                ? Array.from({ length: 8 }).map((_, index) => (
                    <tr key={index} className="border-t border-line/40">
                      <td colSpan={6} className="px-4 py-3">
                        <div className="h-8 animate-pulse rounded bg-white/5" />
                      </td>
                    </tr>
                  ))
                : threats.map((threat) => (
                    <tr
                      key={threat.id}
                      tabIndex={0}
                      aria-selected={selectedThreat?.id === threat.id}
                      onClick={() => setSelectedId(threat.id)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          setSelectedId(threat.id);
                        }
                      }}
                      className={`border-t border-line/40 transition hover:bg-white/[0.04] ${
                        selectedThreat?.id === threat.id ? 'bg-teal-300/10' : ''
                      }`}
                    >
                      <td className="px-4 py-3">
                        <SeverityBadge severity={threat.severity} lang={lang} />
                      </td>
                      <td className="max-w-[360px] px-4 py-3">
                        <div className="truncate font-mono text-[13px] text-sky-300" title={threat.indicator}>
                          {threat.reference ? (
                            <a href={threat.reference} target="_blank" rel="noreferrer" className="hover:underline" onClick={(event) => event.stopPropagation()}>
                              {threat.indicator}
                            </a>
                          ) : (
                            <span>{threat.indicator}</span>
                          )}
                        </div>
                        {threat.title && <div className="truncate text-xs text-slate-400">{threat.title}</div>}
                      </td>
                      <td className="px-4 py-3 text-slate-300">{THREAT_TYPE_LABEL[lang][threat.type]}</td>
                      <td className="px-4 py-3 text-slate-300">
                        <div>{SOURCE_LABELS[threat.source]}</div>
                        {(threat.confidence !== undefined || threat.sourceReliability || threat.tlp) && (
                          <div className="text-xs text-slate-500">
                            {threat.confidence !== undefined ? `C${threat.confidence}` : 'C-'}
                            {threat.sourceReliability ? ` · R${threat.sourceReliability}` : ''}
                            {threat.tlp ? ` · TLP:${threat.tlp.toUpperCase()}` : ''}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-slate-300">{threat.country ?? '-'}</td>
                      <td className="px-4 py-3 text-slate-400">{timeAgo(threat.lastSeen ?? threat.firstSeen, lang)}</td>
                    </tr>
                  ))}
              {!loading && threats.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-slate-400">
                    {t.noIndicatorsMatch}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <aside className="border-t border-line/60 bg-panel/70 xl:border-l xl:border-t-0">
          <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
            <div className="text-xs font-semibold text-slate-300">{t.indicator}</div>
            {selectedThreat && (
              <button
                type="button"
                aria-label={copy.clear}
                onClick={() => setSelectedId(null)}
                className="soft-action inline-flex h-9 w-9 items-center justify-center rounded"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            )}
          </div>
          {selectedThreat ? (
            <div className="space-y-3 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={selectedThreat.severity} lang={lang} />
                <span className="rounded border border-line/70 px-2 py-1 text-[11px] font-semibold text-slate-400">
                  {THREAT_TYPE_LABEL[lang][selectedThreat.type]}
                </span>
              </div>
              <div className="break-words font-mono text-sm font-semibold leading-6 text-sky-200">
                {compact(selectedThreat.indicator, 120)}
              </div>
              {selectedThreat.title && <p className="text-sm leading-6 text-slate-300">{selectedThreat.title}</p>}
              {selectedThreat.description && <p className="text-xs leading-5 text-slate-500">{selectedThreat.description}</p>}

              <div className="grid gap-2">
                <DetailRow label={t.source} value={SOURCE_LABELS[selectedThreat.source]} />
                <DetailRow label={t.country} value={selectedThreat.country ?? '-'} />
                <DetailRow
                  label={t.lastSeen}
                  value={`${timeAgo(selectedThreat.lastSeen ?? selectedThreat.firstSeen, lang)} · ${selectedThreat.lastSeen ?? selectedThreat.firstSeen ?? '-'}`}
                />
                <DetailRow
                  label={copy.evidenceMeta}
                  value={`${selectedThreat.confidence !== undefined ? `C${selectedThreat.confidence}` : 'C-'}${
                    selectedThreat.sourceReliability ? ` · R${selectedThreat.sourceReliability}` : ''
                  }${selectedThreat.tlp ? ` · TLP:${selectedThreat.tlp.toUpperCase()}` : ''}`}
                />
                {selectedThreat.tags.length > 0 && (
                  <DetailRow
                    label={copy.tags}
                    value={
                      <div className="flex flex-wrap gap-1">
                        {selectedThreat.tags.slice(0, 12).map((tag) => (
                          <span key={tag} className="rounded border border-line/70 px-1.5 py-0.5 text-[11px] text-slate-400">
                            {tag}
                          </span>
                        ))}
                      </div>
                    }
                  />
                )}
              </div>

              {selectedThreat.reference && (
                <a
                  href={selectedThreat.reference}
                  target="_blank"
                  rel="noreferrer"
                  className="primary-action control inline-flex w-full items-center justify-center gap-2 px-4 text-sm font-bold"
                >
                  <ExternalLink className="h-4 w-4" aria-hidden="true" />
                  <span className="truncate">{copy.reference}</span>
                </a>
              )}
            </div>
          ) : (
            <div className="px-4 py-10 text-center text-sm leading-6 text-slate-500">{copy.selectIndicator}</div>
          )}
        </aside>
      </div>
    </div>
  );
}
