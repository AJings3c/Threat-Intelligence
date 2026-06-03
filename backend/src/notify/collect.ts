import type { ThreatIndicator, CveItem, Severity, ThreatSource } from '../types.js';
import { SOURCE_LABELS } from '../store.js';
import { severityRank } from './config.js';
import type { AlertItem } from './format.js';

export interface CollectInput {
  indicators: ThreatIndicator[];
  cves: CveItem[];
  /** IDs already alerted on; matching items are skipped (dedup / baseline). */
  seen: Set<string>;
  minSeverity: Severity;
  /** Restrict to these sources, or null for all. */
  sources: ThreatSource[] | null;
}

/**
 * Pure selection of alert-worthy items: applies the severity threshold, optional
 * source allow-list, and the "seen" dedup set, then orders highest-severity first.
 * Extracted from the Notifier so the dedup/baseline/filter behavior is unit-testable
 * without the singleton store or any network.
 */
export function collectNewAlerts(input: CollectInput): AlertItem[] {
  const minRank = severityRank(input.minSeverity);
  const allow = input.sources;
  const items: AlertItem[] = [];

  for (const t of input.indicators) {
    if (severityRank(t.severity) < minRank) continue;
    if (allow && !allow.includes(t.source)) continue;
    if (input.seen.has(t.id)) continue;
    items.push({
      id: t.id,
      sourceLabel: SOURCE_LABELS[t.source],
      severity: t.severity,
      title: t.title ?? t.type,
      indicator: t.indicator,
      reference: t.reference,
      country: t.country,
    });
  }

  // Also alert on standalone CVEs (NVD) meeting the threshold.
  const nvdAllowed = !allow || allow.includes('nvd');
  if (nvdAllowed) {
    for (const c of input.cves) {
      if (severityRank(c.severity) < minRank) continue;
      if (input.seen.has(c.id)) continue;
      items.push({
        id: c.id,
        sourceLabel: SOURCE_LABELS.nvd,
        severity: c.severity,
        title: c.title,
        indicator: c.id,
        reference: c.reference,
      });
    }
  }

  // Highest severity first for a useful digest ordering.
  items.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  return items;
}
