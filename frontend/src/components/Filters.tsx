import type { Language, Severity, ThreatSource, ThreatType } from '../types';
import { SEVERITY_ORDER, SOURCE_LABELS } from '../constants';
import { SEVERITY_LABEL, THREAT_TYPE_LABEL, UI_TEXT } from '../i18n';

export interface FilterState {
  source: ThreatSource | '';
  type: ThreatType | '';
  severity: Severity | '';
  q: string;
}

export function Filters({
  value,
  onChange,
  lang,
}: {
  value: FilterState;
  onChange: (next: FilterState) => void;
  lang: Language;
}) {
  const t = UI_TEXT[lang];
  const select = 'control px-3 text-sm';

  return (
    <div className="flex flex-wrap items-center gap-2">
      <label htmlFor="feed-search" className="sr-only">
        {t.searchFilterPlaceholder}
      </label>
      <input
        id="feed-search"
        type="search"
        placeholder={t.searchFilterPlaceholder}
        value={value.q}
        onChange={(e) => onChange({ ...value, q: e.target.value })}
        className={`${select} min-w-[220px] flex-1`}
      />
      <label htmlFor="feed-source" className="sr-only">
        {t.source}
      </label>
      <select
        id="feed-source"
        value={value.source}
        onChange={(e) => onChange({ ...value, source: e.target.value as FilterState['source'] })}
        className={select}
      >
        <option value="">{t.allSources}</option>
        {(Object.keys(SOURCE_LABELS) as ThreatSource[]).map((s) => (
          <option key={s} value={s}>
            {SOURCE_LABELS[s]}
          </option>
        ))}
      </select>
      <label htmlFor="feed-type" className="sr-only">
        {t.type}
      </label>
      <select
        id="feed-type"
        value={value.type}
        onChange={(e) => onChange({ ...value, type: e.target.value as FilterState['type'] })}
        className={select}
      >
        <option value="">{t.allTypes}</option>
        {(Object.keys(THREAT_TYPE_LABEL[lang]) as ThreatType[]).map((type) => (
          <option key={type} value={type}>
            {THREAT_TYPE_LABEL[lang][type]}
          </option>
        ))}
      </select>
      <label htmlFor="feed-severity" className="sr-only">
        {t.severity}
      </label>
      <select
        id="feed-severity"
        value={value.severity}
        onChange={(e) =>
          onChange({ ...value, severity: e.target.value as FilterState['severity'] })
        }
        className={select}
      >
        <option value="">{t.allSeverities}</option>
        {SEVERITY_ORDER.map((s) => (
          <option key={s} value={s}>
            {SEVERITY_LABEL[lang][s]}
          </option>
        ))}
      </select>
    </div>
  );
}
