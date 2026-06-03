import type { Severity } from '../types';
import { SEVERITY_BADGE } from '../constants';

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${SEVERITY_BADGE[severity]}`}
    >
      {severity}
    </span>
  );
}
