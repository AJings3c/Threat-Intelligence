import type { ThreatIndicator, ThreatSource, Severity, SourceReliability, Tlp } from './types.js';
import { sourceProfile } from './sourceProfiles.js';

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const SEVERITY_BONUS: Record<Severity, number> = { low: 0, medium: 5, high: 15, critical: 25 };
const RELIABILITY_RANK: Record<SourceReliability, number> = { A: 6, B: 5, C: 4, D: 3, E: 2, F: 1 };
const TLP_RANK: Record<Tlp, number> = { clear: 0, green: 1, amber: 2, red: 3 };

function bestReliability(sources: ThreatSource[]): SourceReliability {
  return sources
    .map((source) => sourceProfile(source).reliability)
    .sort((a, b) => RELIABILITY_RANK[b] - RELIABILITY_RANK[a])[0];
}

function mostRestrictiveTlp(sources: ThreatSource[]): Tlp {
  return sources
    .map((source) => sourceProfile(source).tlp)
    .sort((a, b) => TLP_RANK[b] - TLP_RANK[a])[0];
}

// Confidence (0-100): source reliability weights dominate, severity adds a bump,
// and cross-source corroboration naturally raises the score through accumulated weight.
export function scoreConfidence(sources: ThreatSource[], severity: Severity): number {
  const unique = new Set(sources);
  const weight = Array.from(unique).reduce(
    (sum, source) => sum + sourceProfile(source).confidenceWeight,
    0,
  );
  const base = Math.min(85, 35 + weight);
  return Math.min(100, base + SEVERITY_BONUS[severity]);
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
      byKey.set(key, {
        ...item,
        sources,
        confidence: scoreConfidence(sources, item.severity),
        sourceReliability: bestReliability(sources),
        tlp: mostRestrictiveTlp(sources),
      });
      continue;
    }
    const sources = existing.sources ?? [existing.source];
    if (!sources.includes(item.source)) sources.push(item.source);
    const severity =
      SEVERITY_RANK[item.severity] > SEVERITY_RANK[existing.severity] ? item.severity : existing.severity;
    existing.sources = sources;
    existing.severity = severity;
    existing.sourceReliability = bestReliability(sources);
    existing.tlp = mostRestrictiveTlp(sources);
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
