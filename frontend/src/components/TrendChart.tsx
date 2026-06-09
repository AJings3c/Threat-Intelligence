import type { Language, TrendPoint } from '../types';
import { UI_TEXT } from '../i18n';

const W = 600;
const H = 160;
const PAD = 8;

function Empty({ msg }: { msg: string }) {
  return <div className="px-4 py-10 text-center text-xs text-slate-500">{msg}</div>;
}

export function TrendChart({
  enabled,
  points,
  lang,
}: {
  enabled: boolean;
  points: TrendPoint[];
  lang: Language;
}) {
  const t = UI_TEXT[lang];
  let body;
  if (!enabled) {
    body = <Empty msg={t.trendHistoryDisabled} />;
  } else if (points.length < 2) {
    body = <Empty msg={t.trendCollecting} />;
  } else {
    const xs = points.map((p) => p.ts);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const maxY = Math.max(...points.map((p) => p.total), 1);
    const x = (t: number) => PAD + ((t - minX) / (maxX - minX || 1)) * (W - 2 * PAD);
    const y = (v: number) => H - PAD - (v / maxY) * (H - 2 * PAD);
    const line = points.map((p) => `${x(p.ts).toFixed(1)},${y(p.total).toFixed(1)}`).join(' ');
    const area = `${PAD},${H - PAD} ${line} ${W - PAD},${H - PAD}`;
    const last = points[points.length - 1];
    body = (
      <>
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-40 w-full">
          <polygon points={area} fill="rgba(56,189,248,0.12)" />
          <polyline points={line} fill="none" stroke="#38bdf8" strokeWidth={2} />
        </svg>
        <div className="flex justify-between px-4 pb-3 text-xs text-slate-400">
          <span>{new Date(minX).toLocaleDateString()}</span>
          <span className="text-slate-300">
            {t.now}: {last.total.toLocaleString()} {t.indicators}
          </span>
          <span>{new Date(maxX).toLocaleDateString()}</span>
        </div>
      </>
    );
  }

  return (
    <div className="surface overflow-hidden rounded-lg">
      <div className="flex items-center justify-between border-b border-line/60 bg-panel-2/45 px-4 py-4">
        <h2 className="section-title">{t.trendTitle}</h2>
      </div>
      {body}
    </div>
  );
}
