import type { IndicatorType, Severity, ThreatIndicator } from './types';

export type ActivityCategoryId =
  | 'phishing'
  | 'command-and-control'
  | 'malware'
  | 'vulnerability'
  | 'scanner'
  | 'network'
  | 'social'
  | 'other';

export function evidenceCategory(indicator: ThreatIndicator): ActivityCategoryId {
  if (indicator.type === 'phishing_url') return 'phishing';
  if (indicator.type === 'c2_server') return 'command-and-control';
  if (indicator.type === 'malware_host' || indicator.type === 'malicious_hash' || indicator.type === 'malicious_url') {
    return 'malware';
  }
  if (indicator.type === 'exploited_vuln' || indicator.type === 'vulnerability') return 'vulnerability';
  if (indicator.type === 'scanner_network') return 'scanner';
  if (indicator.type === 'malicious_network') return 'network';
  if (indicator.type === 'social_intel') return 'social';
  return 'other';
}

export interface ProvenanceGraphNode {
  id: string;
  label: string;
  type: IndicatorType | 'source';
  severity: Severity | null;
  confidence: number | null;
}

export interface ProvenanceGraphEdge {
  source: string;
  target: string;
  relation: 'reported_by';
  strength: number;
}

export function buildProvenanceGraph(
  indicators: ThreatIndicator[],
  limit = 100,
): { nodes: ProvenanceGraphNode[]; edges: ProvenanceGraphEdge[] } {
  const visibleIndicators = indicators.slice(0, Math.max(0, limit));
  const indicatorNodes: ProvenanceGraphNode[] = visibleIndicators.map((indicator) => ({
    id: indicator.id,
    label: indicator.indicator,
    type: indicator.indicatorType,
    severity: indicator.severity,
    confidence: indicator.confidence ?? 50,
  }));
  const sourceNames = Array.from(
    new Set(visibleIndicators.flatMap((indicator) => indicator.sources ?? [indicator.source])),
  ).sort();
  const sourceNodes: ProvenanceGraphNode[] = sourceNames.map((source) => ({
    id: `source:${source}`,
    label: source,
    type: 'source',
    severity: null,
    confidence: null,
  }));
  const edges: ProvenanceGraphEdge[] = visibleIndicators.flatMap((indicator) =>
    (indicator.sources ?? [indicator.source]).map((source) => ({
      source: indicator.id,
      target: `source:${source}`,
      relation: 'reported_by' as const,
      strength: 0.55,
    })),
  );
  return { nodes: [...indicatorNodes, ...sourceNodes], edges };
}
