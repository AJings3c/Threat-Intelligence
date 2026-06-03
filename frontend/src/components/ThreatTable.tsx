import type { ThreatIndicator } from '../types';
import { SOURCE_LABELS, TYPE_LABELS } from '../constants';
import { SeverityBadge } from './SeverityBadge';

function timeAgo(iso?: string): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const diff = Date.now() - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export function ThreatTable({
  threats,
  total,
  loading,
}: {
  threats: ThreatIndicator[];
  total: number;
  loading: boolean;
}) {
  return (
    <div className="rounded-xl border border-white/10 bg-panel/70 shadow-lg">
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-200">Live Threat Feed</h2>
        <span className="text-xs text-slate-400">
          {loading ? 'Loading…' : `${threats.length} of ${total.toLocaleString()} matches`}
        </span>
      </div>
      <div className="max-h-[520px] overflow-auto">
        <table className="w-full border-collapse text-left text-sm">
          <thead className="sticky top-0 bg-panel-2 text-xs uppercase tracking-wider text-slate-400">
            <tr>
              <th className="px-4 py-2 font-medium">Severity</th>
              <th className="px-4 py-2 font-medium">Indicator</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Source</th>
              <th className="px-4 py-2 font-medium">Country</th>
              <th className="px-4 py-2 font-medium">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {threats.map((t) => (
              <tr key={t.id} className="border-t border-white/5 hover:bg-white/5">
                <td className="px-4 py-2">
                  <SeverityBadge severity={t.severity} />
                </td>
                <td className="max-w-[320px] px-4 py-2">
                  <div className="truncate font-mono text-[13px] text-sky-300">
                    {t.reference ? (
                      <a
                        href={t.reference}
                        target="_blank"
                        rel="noreferrer"
                        className="hover:underline"
                        title={t.indicator}
                      >
                        {t.indicator}
                      </a>
                    ) : (
                      <span title={t.indicator}>{t.indicator}</span>
                    )}
                  </div>
                  {t.title && <div className="truncate text-xs text-slate-400">{t.title}</div>}
                </td>
                <td className="px-4 py-2 text-slate-300">{TYPE_LABELS[t.type]}</td>
                <td className="px-4 py-2 text-slate-300">{SOURCE_LABELS[t.source]}</td>
                <td className="px-4 py-2 text-slate-300">{t.country ?? '—'}</td>
                <td className="px-4 py-2 text-slate-400">{timeAgo(t.lastSeen ?? t.firstSeen)}</td>
              </tr>
            ))}
            {!loading && threats.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-slate-400">
                  No indicators match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
