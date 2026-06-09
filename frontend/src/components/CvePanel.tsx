import type { CveItem, Language } from '../types';
import { UI_TEXT } from '../i18n';
import { SeverityBadge } from './SeverityBadge';

export function CvePanel({ cves, loading, lang }: { cves: CveItem[]; loading: boolean; lang: Language }) {
  const t = UI_TEXT[lang];

  return (
    <div className="surface overflow-hidden rounded-lg">
      <div className="flex items-center justify-between border-b border-line/60 bg-panel-2/45 px-4 py-4">
        <h2 className="section-title">{t.latestCves}</h2>
        <span className="text-xs text-slate-400">{loading ? t.loading : `${cves.length}`}</span>
      </div>
      <div className="max-h-[520px] divide-y divide-line/40 overflow-auto">
        {cves.map((c) => (
          <a
            key={c.id}
            href={c.reference}
            target="_blank"
            rel="noreferrer"
            className="block px-4 py-3 hover:bg-white/[0.04]"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[13px] text-sky-300">{c.id}</span>
              <div className="flex items-center gap-2">
                {c.cvssScore !== undefined && (
                  <span className="text-xs font-semibold text-slate-300">{c.cvssScore.toFixed(1)}</span>
                )}
                <SeverityBadge severity={c.severity} lang={lang} />
              </div>
            </div>
            {c.epssScore !== undefined && (
              <div className="mt-1 text-[11px] font-medium text-slate-500">
                EPSS {(c.epssScore * 100).toFixed(2)}% · P{Math.round((c.epssPercentile ?? 0) * 100)}
              </div>
            )}
            <p className="mt-1 line-clamp-2 text-xs text-slate-400">{c.description}</p>
          </a>
        ))}
        {!loading && cves.length === 0 && (
          <div className="px-4 py-10 text-center text-sm text-slate-400">{t.noRecentCves}</div>
        )}
      </div>
    </div>
  );
}
