import type { Language, Stats } from '../types';
import { SEVERITY_COLORS } from '../constants';
import { SEVERITY_LABEL, UI_TEXT } from '../i18n';

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
    <div className="surface-raised rounded-lg p-4">
      <div className="text-xs font-semibold uppercase text-slate-500">{label}</div>
      <div className="mt-1 text-3xl font-bold text-white">{value}</div>
      {sub && <div className="mt-2 text-xs text-slate-400">{sub}</div>}
    </div>
  );
}

export function StatsCards({ stats, lang }: { stats: Stats | null; lang: Language }) {
  const t = UI_TEXT[lang];

  if (!stats) {
    return (
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="surface h-28 animate-pulse rounded-lg"
          />
        ))}
      </div>
    );
  }

  const sev = stats.bySeverity;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      <Card label={t.activeIndicators} value={stats.totalIndicators.toLocaleString()} />
      <Card label={t.recentCves} value={stats.totalCves.toLocaleString()} />
      <Card
        label={t.severityMix}
        value={`${sev.critical ?? 0}C`}
        sub={
          <div className="flex flex-wrap gap-2">
            {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
              <span key={s} className="flex items-center gap-1">
                <span
                  className="inline-block h-2 w-2 rounded-full"
                  style={{ background: SEVERITY_COLORS[s] }}
                />
                {SEVERITY_LABEL[lang][s]}:{sev[s] ?? 0}
              </span>
            ))}
          </div>
        }
      />
      <Card
        label={t.topOrigin}
        value={stats.topCountries[0]?.country ?? '-'}
        sub={
          stats.topCountries.length > 0
            ? `${stats.topCountries[0].count.toLocaleString()} ${t.indicators}`
            : t.noGeoDataYet
        }
      />
    </div>
  );
}
