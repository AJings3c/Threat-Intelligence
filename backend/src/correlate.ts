import type { ThreatIndicator, ThreatSource, Severity } from './types.js';

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const SEVERITY_BONUS: Record<Severity, number> = { low: 0, medium: 5, high: 15, critical: 25 };

// Confidence (0-100): independent corroborating sources dominate, severity adds a bump,
// and a CISA KEV hit (government-confirmed exploitation) is treated as authoritative.
export function scoreConfidence(sources: ThreatSource[], severity: Severity): number {
  const unique = new Set(sources);
  const base = unique.size >= 3 ? 80 : unique.size === 2 ? 65 : 45;
  const authoritative = unique.has('cisa_kev') ? 10 : 0;
  return Math.min(100, base + authoritative + SEVERITY_BONUS[severity]);
}

// Collapse indicators that share the same normalized (type, value) across sources into a
// single record, recording every reporting source and a derived confidence score.
export function dedupeIndicators(items: ThreatIndicator[]): ThreatIndicator[] {
  const byKey = new Map<string, ThreatIndicator>();
  for (const item of items) {
    const key = `${item.indicatorType}:${item.indicator.toLowerCase()}`;
    const existing = byKey.get(key);
    if (!existing) {
      const sources = [item.source];
      byKey.set(key, { ...item, sources, confidence: scoreConfidence(sources, item.severity) });
      continue;
    }
    const sources = existing.sources ?? [existing.source];
    if (!sources.includes(item.source)) sources.push(item.source);
    const severity =
      SEVERITY_RANK[item.severity] > SEVERITY_RANK[existing.severity] ? item.severity : existing.severity;
    existing.sources = sources;
    existing.severity = severity;
    existing.tags = Array.from(new Set([...existing.tags, ...item.tags]));
    existing.confidence = scoreConfidence(sources, severity);
    existing.title ??= item.title;
    existing.description ??= item.description;
    existing.malwareFamily ??= item.malwareFamily;
    existing.reference ??= item.reference;
    if (item.firstSeen && (!existing.firstSeen || item.firstSeen < existing.firstSeen)) {
      existing.firstSeen = item.firstSeen;
    }
    if (item.lastSeen && (!existing.lastSeen || item.lastSeen > existing.lastSeen)) {
      existing.lastSeen = item.lastSeen;
    }
  }
  return Array.from(byKey.values());
}
