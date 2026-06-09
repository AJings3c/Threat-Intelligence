import type { Language, Severity } from '../types';
import { SEVERITY_BADGE } from '../constants';
import { SEVERITY_LABEL } from '../i18n';

export function SeverityBadge({ severity, lang = 'en' }: { severity: Severity; lang?: Language }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-[11px] font-semibold uppercase ${SEVERITY_BADGE[severity]}`}
    >
      {SEVERITY_LABEL[lang][severity]}
    </span>
  );
}
