import type { Stats } from '../types';
import { SEVERITY_COLORS } from '../constants';

function Card({
  label,
  value,
  sub,
}: {
  label: string;
  value: string | number;
  sub?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-white/10 bg-panel/70 p-4 shadow-lg backdrop-blur">
      <div className="text-xs uppercase tracking-wider text-slate-400">{label}</div>
      <div className="mt-1 text-3xl font-bold text-white">{value}</div>
      {sub && <div className="mt-2 text-xs text-slate-400">{sub}</div>}
    </div>
  );
}

export function StatsCards({ stats }: { stats: Stats | null }) {
  if (!stats) {
    return (
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-28 animate-pulse rounded-xl border border-white/10 bg-panel/40"
          />
        ))}
      </div>
    );
  }

  const sev = stats.bySeverity;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      <Card label="Active Indicators" value={stats.totalIndicators.toLocaleString()} />
      <Card label="Recent CVEs" value={stats.totalCves.toLocaleString()} />
      <Card
        label="Severity Mix"
        value={`${sev.critical ?? 0}C`}
        sub={
          <div className="flex flex-wrap gap-2">
            {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
              <span key={s} className="flex items-center gap-1">
                <span
                  className="inline-block h-2 w-2 rounded-full"
                  style={{ background: SEVERITY_COLORS[s] }}
                />
                {s[0].toUpperCase()}:{sev[s] ?? 0}
              </span>
            ))}
          </div>
        }
      />
      <Card
        label="Top Origin"
        value={stats.topCountries[0]?.country ?? '—'}
        sub={
          stats.topCountries.length > 0
            ? `${stats.topCountries[0].count.toLocaleString()} indicators`
            : 'No geo data yet'
        }
      />
    </div>
  );
}
