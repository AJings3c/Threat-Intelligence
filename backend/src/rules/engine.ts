import { randomUUID } from 'node:crypto';
import { recordRuleExecution } from '../persist.js';
import { listRules } from './index.js';
import type { Rule, ThreatIndicator } from '../types.js';

export interface RuleEvaluationResult {
  matched: boolean;
  rule: Rule;
  indicator?: ThreatIndicator;
}

export function evaluateRule(rule: Rule, indicator: ThreatIndicator): boolean {
  const { triggerType, triggerConfig } = rule;

  switch (triggerType) {
    case 'ioc_match':
      return evaluateIocMatch(indicator, triggerConfig);
    case 'threshold':
      return evaluateThreshold(indicator, triggerConfig);
    case 'schedule':
      return false;
    default:
      return false;
  }
}

function evaluateIocMatch(indicator: ThreatIndicator, config: Record<string, unknown>): boolean {
  if (config.severity && indicator.severity !== config.severity) {
    return false;
  }

  if (config.source && indicator.source !== config.source) {
    return false;
  }

  if (config.indicatorType && indicator.indicatorType !== config.indicatorType) {
    return false;
  }

  if (config.minConfidence && (indicator.confidence ?? 0) < (config.minConfidence as number)) {
    return false;
  }

  if (config.tags && Array.isArray(config.tags)) {
    const requiredTags = config.tags as string[];
    const hasAllTags = requiredTags.every((tag) => indicator.tags.includes(tag));
    if (!hasAllTags) return false;
  }

  return true;
}

function evaluateThreshold(indicator: ThreatIndicator, config: Record<string, unknown>): boolean {
  if (config.confidenceThreshold && (indicator.confidence ?? 0) >= (config.confidenceThreshold as number)) {
    return true;
  }

  if (config.sourceCountThreshold && (indicator.sources?.length ?? 1) >= (config.sourceCountThreshold as number)) {
    return true;
  }

  return false;
}

export async function executeActions(
  rule: Rule,
  indicator: ThreatIndicator,
  actionHandlers: {
    webhook?: (url: string, payload: unknown) => Promise<void>;
    enrich?: (iocValue: string) => Promise<void>;
  },
): Promise<{ success: boolean; errors: string[] }> {
  const errors: string[] = [];
  let allSuccess = true;

  for (const action of rule.actions) {
    try {
      if (action.type === 'webhook' && actionHandlers.webhook) {
        const url = action.config.url as string;
        if (!url) {
          errors.push('webhook action missing url config');
          allSuccess = false;
          continue;
        }
        await actionHandlers.webhook(url, {
          rule: { id: rule.id, name: rule.name },
          indicator: {
            id: indicator.id,
            value: indicator.indicator,
            type: indicator.indicatorType,
            severity: indicator.severity,
            confidence: indicator.confidence,
            sources: indicator.sources,
          },
          timestamp: new Date().toISOString(),
        });
      } else if (action.type === 'enrich' && actionHandlers.enrich) {
        await actionHandlers.enrich(indicator.indicator);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push(`${action.type} action failed: ${message}`);
      allSuccess = false;
    }
  }

  const execution = {
    id: randomUUID(),
    ruleId: rule.id,
    triggeredAt: Date.now(),
    actionsTaken: JSON.stringify(rule.actions),
    success: allSuccess ? 1 : 0,
  };

  recordRuleExecution(execution);

  return { success: allSuccess, errors };
}

export async function evaluateAllRules(
  indicators: ThreatIndicator[],
  actionHandlers: {
    webhook?: (url: string, payload: unknown) => Promise<void>;
    enrich?: (iocValue: string) => Promise<void>;
  },
): Promise<RuleEvaluationResult[]> {
  const enabledRules = listRules(true);
  const results: RuleEvaluationResult[] = [];

  for (const rule of enabledRules) {
    for (const indicator of indicators) {
      if (evaluateRule(rule, indicator)) {
        results.push({ matched: true, rule, indicator });
        await executeActions(rule, indicator, actionHandlers);
      }
    }
  }

  return results;
}
