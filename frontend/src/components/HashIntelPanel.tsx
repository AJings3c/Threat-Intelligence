import type { HashIntelResponse } from '../types';
import { SOURCE_LABELS } from '../constants';
import { SeverityBadge } from './SeverityBadge';

function compactHash(value: string): string {
  if (value.length <= 24) return value;
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function timeAgo(iso?: string | null): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const mins = Math.floor((Date.now() - then) / 60000);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  return `${Math.floor(hrs / 24)}d`;
}

export function HashIntelPanel({
  data,
  loading,
}: {
  data: HashIntelResponse | null;
  loading: boolean;
}) {
  const hashes = data?.hashes ?? [];
  const families = data?.families ?? [];

  return (
    <div className="rounded-xl border border-white/10 bg-panel/70 shadow-lg">
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-200">Hash & Malware Intel</h2>
        <span className="text-xs text-slate-400">
          {loading ? 'Loading…' : `${data?.total ?? 0} hashes`}
        </span>
      </div>
      <div className="grid gap-0 divide-y divide-white/5 md:grid-cols-2 md:divide-x md:divide-y-0">
        <div className="max-h-[260px] overflow-auto">
          {hashes.slice(0, 12).map((hash) => (
            <a
              key={hash.id}
              href={hash.reference}
              target="_blank"
              rel="noreferrer"
              className="flex items-start justify-between gap-3 border-b border-white/5 px-4 py-3 last:border-b-0 hover:bg-white/5"
            >
              <div className="min-w-0">
                <div className="truncate font-mono text-[12px] text-sky-300" title={hash.indicator}>
                  {compactHash(hash.indicator)}
                </div>
                <div className="mt-1 truncate text-xs text-slate-500">
                  {hash.malwareFamily ?? hash.title ?? SOURCE_LABELS[hash.source]}
                </div>
              </div>
              <div className="shrink-0 text-right">
                <SeverityBadge severity={hash.severity} />
                <div className="mt-1 text-[11px] text-slate-500">{timeAgo(hash.lastSeen ?? hash.firstSeen)}</div>
              </div>
            </a>
          ))}
          {!loading && hashes.length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-slate-400">No hash IOCs yet.</div>
          )}
        </div>
        <div className="max-h-[260px] overflow-auto">
          {families.slice(0, 12).map((family) => (
            <div key={family.family} className="border-b border-white/5 px-4 py-3 last:border-b-0">
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
            <div className="px-4 py-8 text-center text-sm text-slate-400">No malware families yet.</div>
          )}
        </div>
      </div>
    </div>
  );
}
