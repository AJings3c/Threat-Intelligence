import type { Severity, ThreatSource, ThreatType } from '../types';
import { SEVERITY_ORDER, SOURCE_LABELS, TYPE_LABELS } from '../constants';

export interface FilterState {
  source: ThreatSource | '';
  type: ThreatType | '';
  severity: Severity | '';
  q: string;
}

export function Filters({
  value,
  onChange,
}: {
  value: FilterState;
  onChange: (next: FilterState) => void;
}) {
  const select =
    'rounded-lg border border-white/10 bg-panel px-3 py-2 text-sm text-slate-200 focus:border-accent focus:outline-none';

  return (
    <div className="flex flex-wrap items-center gap-2">
      <input
        type="search"
        placeholder="Search indicator, malware, country, tag…"
        value={value.q}
        onChange={(e) => onChange({ ...value, q: e.target.value })}
        className={`${select} min-w-[220px] flex-1`}
      />
      <select
        value={value.source}
        onChange={(e) => onChange({ ...value, source: e.target.value as FilterState['source'] })}
        className={select}
      >
        <option value="">All sources</option>
        {(Object.keys(SOURCE_LABELS) as ThreatSource[]).map((s) => (
          <option key={s} value={s}>
            {SOURCE_LABELS[s]}
          </option>
        ))}
      </select>
      <select
        value={value.type}
        onChange={(e) => onChange({ ...value, type: e.target.value as FilterState['type'] })}
        className={select}
      >
        <option value="">All types</option>
        {(Object.keys(TYPE_LABELS) as ThreatType[]).map((t) => (
          <option key={t} value={t}>
            {TYPE_LABELS[t]}
          </option>
        ))}
      </select>
      <select
        value={value.severity}
        onChange={(e) =>
          onChange({ ...value, severity: e.target.value as FilterState['severity'] })
        }
        className={select}
      >
        <option value="">All severities</option>
        {SEVERITY_ORDER.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>
    </div>
  );
}
