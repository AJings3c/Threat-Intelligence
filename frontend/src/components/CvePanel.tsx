import type { CveItem } from '../types';
import { SeverityBadge } from './SeverityBadge';

export function CvePanel({ cves, loading }: { cves: CveItem[]; loading: boolean }) {
  return (
    <div className="rounded-xl border border-white/10 bg-panel/70 shadow-lg">
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-200">Latest CVEs (NVD)</h2>
        <span className="text-xs text-slate-400">{loading ? 'Loading…' : `${cves.length}`}</span>
      </div>
      <div className="max-h-[520px] divide-y divide-white/5 overflow-auto">
        {cves.map((c) => (
          <a
            key={c.id}
            href={c.reference}
            target="_blank"
            rel="noreferrer"
            className="block px-4 py-3 hover:bg-white/5"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[13px] text-sky-300">{c.id}</span>
              <div className="flex items-center gap-2">
                {c.cvssScore !== undefined && (
                  <span className="text-xs font-semibold text-slate-300">{c.cvssScore.toFixed(1)}</span>
                )}
                <SeverityBadge severity={c.severity} />
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
          <div className="px-4 py-10 text-center text-sm text-slate-400">No recent CVEs.</div>
        )}
      </div>
    </div>
  );
}
