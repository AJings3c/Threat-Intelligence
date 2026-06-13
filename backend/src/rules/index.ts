import { randomUUID } from 'node:crypto';
import {
  createRule as persistCreateRule,
  updateRule as persistUpdateRule,
  getRule as persistGetRule,
  getRules as persistGetRules,
  getRuleExecutions as persistGetRuleExecutions,
} from '../persist.js';
import type { Rule, RuleAction, RuleExecution, RuleTriggerType } from '../types.js';

export interface CreateRuleInput {
  name: string;
  triggerType: RuleTriggerType;
  triggerConfig: Record<string, unknown>;
  actions: RuleAction[];
  enabled?: boolean;
}

export interface UpdateRuleInput {
  enabled?: boolean;
}

export function createRule(input: CreateRuleInput): Rule {
  const rule: Rule = {
    id: randomUUID(),
    name: input.name,
    triggerType: input.triggerType,
    triggerConfig: input.triggerConfig,
    actions: input.actions,
    enabled: input.enabled ?? true,
    createdAt: Date.now(),
  };

  persistCreateRule({
    id: rule.id,
    name: rule.name,
    triggerType: rule.triggerType,
    triggerConfig: JSON.stringify(rule.triggerConfig),
    actions: JSON.stringify(rule.actions),
    enabled: rule.enabled ? 1 : 0,
    createdAt: rule.createdAt,
  });

  return rule;
}

export function updateRule(id: string, input: UpdateRuleInput): Rule | null {
  const existing = getRule(id);
  if (!existing) return null;

  persistUpdateRule(id, { enabled: input.enabled !== undefined ? (input.enabled ? 1 : 0) : undefined });

  return {
    ...existing,
    enabled: input.enabled ?? existing.enabled,
  };
}

export function getRule(id: string): Rule | null {
  const row = persistGetRule(id) as {
    id: string;
    name: string;
    trigger_type: RuleTriggerType;
    trigger_config: string;
    actions: string;
    enabled: number;
    created_at: number;
  } | null;

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    triggerType: row.trigger_type,
    triggerConfig: JSON.parse(row.trigger_config),
    actions: JSON.parse(row.actions),
    enabled: row.enabled === 1,
    createdAt: row.created_at,
  };
}

export function listRules(enabledOnly = false): Rule[] {
  const rows = persistGetRules(enabledOnly) as Array<{
    id: string;
    name: string;
    trigger_type: RuleTriggerType;
    trigger_config: string;
    actions: string;
    enabled: number;
    created_at: number;
  }>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    triggerType: row.trigger_type,
    triggerConfig: JSON.parse(row.trigger_config),
    actions: JSON.parse(row.actions),
    enabled: row.enabled === 1,
    createdAt: row.created_at,
  }));
}

export function getRuleExecutionHistory(ruleId: string, limit = 50): RuleExecution[] {
  const rows = persistGetRuleExecutions(ruleId, limit) as Array<{
    id: string;
    rule_id: string;
    triggered_at: number;
    actions_taken: string;
    success: number;
  }>;

  return rows.map((row) => ({
    id: row.id,
    ruleId: row.rule_id,
    triggeredAt: row.triggered_at,
    actionsTaken: JSON.parse(row.actions_taken),
    success: row.success === 1,
  }));
}
