import { describe, expect, it } from 'vitest';
import { buildArchitectureThreatModel } from '../src/architectureThreatModel.js';
import { architectureThreatModelMarkdown, investigationMarkdown } from '../src/reports.js';
import type { IocInvestigation, SourceHealth } from '../src/types.js';

const health: SourceHealth[] = [
  {
    source: 'otx',
    label: 'AlienVault OTX',
    ok: false,
    status: 'disabled',
    configured: false,
    credentialed: true,
    requiredEnv: ['OTX_API_KEY'],
    stale: false,
    deprecated: false,
    count: 0,
    lastFetched: null,
    lastError: null,
    ageMs: null,
    refreshIntervalMs: 1000,
  },
];

describe('architecture threat model', () => {
  it('builds assets, flows, boundaries, and STRIDE scenarios', () => {
    const model = buildArchitectureThreatModel({ totalIndicators: 12, totalCves: 3 }, health);

    expect(model.assets.length).toBeGreaterThan(0);
    expect(model.dataFlows.some((flow) => flow.crossesTrustBoundary)).toBe(true);
    expect(model.trustBoundaries.length).toBeGreaterThan(0);
    expect(model.scenarios.map((scenario) => scenario.stride)).toContain('Information Disclosure');
    expect(architectureThreatModelMarkdown(model)).toContain('# Architecture Threat Model');
  });

  it('renders IOC investigation markdown reports', () => {
    const result: IocInvestigation = {
      indicator: 'example.com',
      indicatorType: 'domain',
      exactMatches: [],
      relatedIndicators: [],
      sourceSummary: [],
      model: {
        posture: 'no_match',
        highestSeverity: null,
        confidence: 0,
        scenarios: [
          {
            id: 'spoofing',
            title: 'Phishing risk',
            stride: 'Spoofing',
            severity: 'medium',
            confidence: 0,
            evidence: ['No local match'],
            recommendations: ['Check DNS logs'],
          },
        ],
        nextSteps: ['Run enrichment'],
      },
    };

    const markdown = investigationMarkdown(result);
    expect(markdown).toContain('# IOC Threat Model: example.com');
    expect(markdown).toContain('STRIDE Scenarios');
  });
});
