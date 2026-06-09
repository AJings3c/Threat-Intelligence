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
    expect(model.methodology).toMatchObject({ framework: 'STRIDE', scoring: 'DREAD' });
    expect(model.layers.map((layer) => layer.layer)).toContain('application');
    expect(model.threatMatrix.some((row) => row.elementId === 'browser-api')).toBe(true);
    expect(model.attackPaths.length).toBeGreaterThan(0);
    expect(model.controls.map((control) => control.id)).toContain('role-scoped-auth');
    expect(model.scenarios.some((scenario) => scenario.dread?.total)).toBe(true);
    expect(model.scenarios.map((scenario) => scenario.stride)).toContain('Information Disclosure');
    expect(architectureThreatModelMarkdown(model)).toContain('# Architecture Threat Model');
    expect(architectureThreatModelMarkdown(model)).toContain('DREAD');
  });

  it('builds Chinese architecture models and reports', () => {
    const model = buildArchitectureThreatModel({ totalIndicators: 12, totalCves: 3 }, health, 'zh');

    expect(model.scope).toBe('威胁情报平台');
    expect(model.assets[0].name).toBe('安全分析员');
    expect(model.scenarios[0].title).toContain('不可信上游情报');
    expect(architectureThreatModelMarkdown(model, 'zh')).toContain('# 架构威胁模型');
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
    expect(investigationMarkdown(result, 'zh')).toContain('# IOC 威胁模型: example.com');
  });
});
