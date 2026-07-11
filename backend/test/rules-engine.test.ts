import { describe, expect, it, vi } from 'vitest';
import { evaluateRule, executeActions } from '../src/rules/engine.js';
import type { Rule, ThreatIndicator } from '../src/types.js';

describe('rules engine', () => {
  it('passes the real indicator type to enrichment actions', async () => {
    const enrich = vi.fn().mockResolvedValue(undefined);
    const rule: Rule = {
      id: 'rule-1',
      name: 'enrich urls',
      triggerType: 'ioc_match',
      triggerConfig: {},
      actions: [{ type: 'enrich', config: {} }],
      enabled: true,
      createdAt: Date.now(),
    };
    const indicator: ThreatIndicator = {
      id: 'ioc-1',
      source: 'urlhaus',
      type: 'malicious_url',
      indicator: 'https://example.com/path',
      indicatorType: 'url',
      severity: 'high',
      tags: [],
    };

    await expect(executeActions(rule, indicator, { enrich })).resolves.toMatchObject({ success: true });
    expect(enrich).toHaveBeenCalledWith('https://example.com/path', 'url');
  });

  it('fails closed when an action is declared but not implemented', async () => {
    const rule: Rule = {
      id: 'rule-unsupported',
      name: 'block IOC',
      triggerType: 'ioc_match',
      triggerConfig: {},
      actions: [{ type: 'block', config: {} }],
      enabled: true,
      createdAt: Date.now(),
    };
    const indicator: ThreatIndicator = {
      id: 'ioc-2',
      source: 'feodo',
      type: 'c2_server',
      indicator: '192.0.2.10',
      indicatorType: 'ip',
      severity: 'critical',
      tags: [],
    };

    await expect(executeActions(rule, indicator, {})).resolves.toMatchObject({
      success: false,
      errors: ['block action failed: block action is not implemented'],
    });
  });

  it('rejects schedule triggers until a scheduler exists', () => {
    const rule: Rule = {
      id: 'rule-schedule',
      name: 'scheduled rule',
      triggerType: 'schedule',
      triggerConfig: {},
      actions: [],
      enabled: true,
      createdAt: Date.now(),
    };
    const indicator: ThreatIndicator = {
      id: 'ioc-3',
      source: 'urlhaus',
      type: 'malicious_url',
      indicator: 'https://example.test/payload',
      indicatorType: 'url',
      severity: 'high',
      tags: [],
    };

    expect(() => evaluateRule(rule, indicator)).toThrow('schedule trigger is not implemented');
  });
});
