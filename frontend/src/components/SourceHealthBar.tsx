import type { SourceHealth, SourceHealthHistoryPoint, ThreatSource } from '../types';

function freshness(ageMs: number | null): string {
  if (ageMs === null) return 'never';
  const mins = Math.floor(ageMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  return `${Math.floor(mins / 60)}h ago`;
}

function historySummary(points: SourceHealthHistoryPoint[]): Map<ThreatSource, number> {
  const failures = new Map<ThreatSource, number>();
  for (const point of points) {
    if (point.ok && !point.stale) continue;
    failures.set(point.source, (failures.get(point.source) ?? 0) + 1);
  }
  return failures;
}

function statusColor(source: SourceHealth): string {
  if (source.status === 'disabled') return 'bg-slate-500';
  if (source.status === 'error') return 'bg-red-400';
  if (source.deprecated) return 'bg-purple-300';
  if (source.stale) return 'bg-yellow-300';
  if (source.status === 'warming') return 'bg-sky-300';
  return 'bg-emerald-400';
}

function tooltip(source: SourceHealth, failures: number): string {
  const status =
    source.status === 'disabled'
      ? `not configured${source.requiredEnv.length > 0 ? ` (${source.requiredEnv.join(', ')})` : ''}`
      : source.status === 'warming'
        ? 'warming up'
        : source.lastError ??
          source.deprecationMessage ??
          (source.stale ? 'stale source data' : `Updated ${freshness(source.ageMs)}`);
  return failures > 0 ? `${status} · ${failures} historical issue(s)` : status;
}

export function SourceHealthBar({
  sources,
  history,
}: {
  sources: SourceHealth[];
  history: SourceHealthHistoryPoint[];
}) {
  const failures = historySummary(history);
  return (
    <div className="flex flex-wrap items-center gap-2">
      {sources.map((s) => {
        const issueCount = s.status === 'disabled' ? 0 : failures.get(s.source) ?? 0;
        return (
          <div
            key={s.source}
            className="flex items-center gap-2 rounded-lg border border-white/10 bg-panel/60 px-3 py-1.5"
            title={tooltip(s, issueCount)}
          >
            <span className={`inline-block h-2 w-2 rounded-full ${statusColor(s)}`} />
            <span className="text-xs text-slate-300">{s.label}</span>
            <span className="text-xs font-semibold text-slate-400">
              {s.count.toLocaleString()}
            </span>
            {issueCount > 0 && (
              <span className="rounded border border-yellow-400/30 px-1 text-[10px] font-semibold text-yellow-300">
                {issueCount}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
