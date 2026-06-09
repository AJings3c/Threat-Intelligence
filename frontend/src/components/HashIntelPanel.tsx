import type { HashIntelResponse, Language } from '../types';
import { SOURCE_LABELS } from '../constants';
import { UI_TEXT } from '../i18n';
import { SeverityBadge } from './SeverityBadge';

function compactHash(value: string): string {
  if (value.length <= 24) return value;
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function timeAgo(iso: string | null | undefined, lang: Language): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const mins = Math.floor((Date.now() - then) / 60000);
  if (mins < 60) return lang === 'zh' ? `${mins} 分钟` : `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return lang === 'zh' ? `${hrs} 小时` : `${hrs}h`;
  const days = Math.floor(hrs / 24);
  return lang === 'zh' ? `${days} 天` : `${days}d`;
}

export function HashIntelPanel({
  data,
  loading,
  lang,
}: {
  data: HashIntelResponse | null;
  loading: boolean;
  lang: Language;
}) {
  const t = UI_TEXT[lang];
  const hashes = data?.hashes ?? [];
  const families = data?.families ?? [];

  return (
    <div className="surface overflow-hidden rounded-lg">
      <div className="flex items-center justify-between border-b border-line/60 bg-panel-2/45 px-4 py-4">
        <h2 className="section-title">{t.hashIntelTitle}</h2>
        <span className="text-xs text-slate-400">
          {loading ? t.loading : `${data?.total ?? 0} ${t.hashes}`}
        </span>
      </div>
      <div className="grid gap-0 divide-y divide-line/50 md:grid-cols-2 md:divide-x md:divide-y-0">
        <div className="max-h-[260px] overflow-auto">
          {hashes.slice(0, 12).map((hash) => {
            const content = (
              <>
                <div className="min-w-0">
                  <div className="truncate font-mono text-[12px] text-sky-300" title={hash.indicator}>
                    {compactHash(hash.indicator)}
                  </div>
                  <div className="mt-1 truncate text-xs text-slate-500">
                    {hash.malwareFamily ?? hash.title ?? SOURCE_LABELS[hash.source]}
                  </div>
                </div>
                <div className="shrink-0 text-right">
                  <SeverityBadge severity={hash.severity} lang={lang} />
                  <div className="mt-1 text-[11px] text-slate-500">{timeAgo(hash.lastSeen ?? hash.firstSeen, lang)}</div>
                </div>
              </>
            );
            const className =
              'flex items-start justify-between gap-3 border-b border-line/40 px-4 py-3 last:border-b-0 hover:bg-white/[0.04]';
            return hash.reference ? (
              <a key={hash.id} href={hash.reference} target="_blank" rel="noreferrer" className={className}>
                {content}
              </a>
            ) : (
              <div key={hash.id} className={className}>
                {content}
              </div>
            );
          })}
          {!loading && hashes.length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-slate-400">{t.noHashIocs}</div>
          )}
        </div>
        <div className="max-h-[260px] overflow-auto">
          {families.slice(0, 12).map((family) => (
            <div key={family.family} className="border-b border-line/40 px-4 py-3 last:border-b-0">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0 truncate text-sm font-semibold text-slate-200">
                  {family.family}
                </div>
                <div className="shrink-0 text-xs font-semibold text-slate-400">
                  {family.count.toLocaleString()}
                </div>
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
                <span>H:{family.high}</span>
                <span>C:{family.critical}</span>
                <span>{family.sources.map((source) => SOURCE_LABELS[source]).join(', ')}</span>
              </div>
            </div>
          ))}
          {!loading && families.length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-slate-400">{t.noMalwareFamilies}</div>
          )}
        </div>
      </div>
    </div>
  );
}
