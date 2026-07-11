import { describe, expect, it } from 'vitest';
import { buildProvenanceGraph, evidenceCategory } from './evidence';
import type { ThreatIndicator } from './types';

function indicator(overrides: Partial<ThreatIndicator> = {}): ThreatIndicator {
  return {
    id: 'ioc-1',
    source: 'feodo',
    type: 'c2_server',
    indicator: '203.0.113.10',
    indicatorType: 'ip',
    severity: 'high',
    tags: [],
    ...overrides,
  };
}

describe('evidence-backed visual models', () => {
  it('classifies IOC evidence without claiming an ATT&CK tactic or technique', () => {
    expect(evidenceCategory(indicator())).toBe('command-and-control');
    expect(evidenceCategory(indicator({ type: 'phishing_url' }))).toBe('phishing');
    expect(evidenceCategory(indicator({ type: 'vulnerability' }))).toBe('vulnerability');
  });

  it('builds only indicator-to-source provenance edges', () => {
    const graph = buildProvenanceGraph([
      indicator({ id: 'ioc-1', sources: ['feodo', 'threatfox'] }),
      indicator({ id: 'ioc-2', indicator: '203.0.113.11', sources: ['feodo'] }),
    ]);

    expect(graph.nodes.filter((node) => node.type === 'source').map((node) => node.id)).toEqual([
      'source:feodo',
      'source:threatfox',
    ]);
    expect(graph.edges).toHaveLength(3);
    expect(graph.edges.every((edge) => edge.relation === 'reported_by' && edge.target.startsWith('source:'))).toBe(true);
    expect(graph.edges.some((edge) => edge.source === 'ioc-1' && edge.target === 'ioc-2')).toBe(false);
  });
});
