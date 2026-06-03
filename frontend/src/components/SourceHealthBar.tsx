import type { SourceHealth } from '../types';

function freshness(ageMs: number | null): string {
  if (ageMs === null) return 'never';
  const mins = Math.floor(ageMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  return `${Math.floor(mins / 60)}h ago`;
}

export function SourceHealthBar({ sources }: { sources: SourceHealth[] }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {sources.map((s) => (
        <div
          key={s.source}
          className="flex items-center gap-2 rounded-lg border border-white/10 bg-panel/60 px-3 py-1.5"
          title={s.lastError ?? `Updated ${freshness(s.ageMs)}`}
        >
          <span
            className={`inline-block h-2 w-2 rounded-full ${
              s.ok ? 'bg-emerald-400' : 'bg-red-400'
            }`}
          />
          <span className="text-xs text-slate-300">{s.label}</span>
          <span className="text-xs font-semibold text-slate-400">
            {s.count.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}
