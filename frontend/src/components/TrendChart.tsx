import type { TrendPoint } from '../types';

const W = 600;
const H = 160;
const PAD = 8;

function Empty({ msg }: { msg: string }) {
  return <div className="px-4 py-10 text-center text-xs text-slate-500">{msg}</div>;
}

export function TrendChart({ enabled, points }: { enabled: boolean; points: TrendPoint[] }) {
  let body;
  if (!enabled) {
    body = <Empty msg="History disabled — set DATA_DIR to record indicator trends." />;
  } else if (points.length < 2) {
    body = <Empty msg="Collecting data — the trend appears after a few refresh cycles." />;
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
          <span className="text-slate-300">Now: {last.total.toLocaleString()} indicators</span>
          <span>{new Date(maxX).toLocaleDateString()}</span>
        </div>
      </>
    );
  }

  return (
    <div className="rounded-xl border border-white/10 bg-panel/70 shadow-lg">
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-200">Indicator Trend (30d)</h2>
      </div>
      {body}
    </div>
  );
}
