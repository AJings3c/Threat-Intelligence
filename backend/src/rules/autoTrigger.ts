import { evaluateRule, executeActions } from './engine.js';
import { listRules } from './index.js';
import type { IndicatorType, ThreatIndicator } from '../types.js';
import { errorMessage, fetchWithTimeout } from '../util.js';
import { enrichWithCache } from '../enrichCache.js';

export interface AutoTriggerHandlers {
  webhook?: (url: string, payload: unknown) => Promise<void>;
  enrich?: (iocValue: string, indicatorType: IndicatorType) => Promise<void>;
}

const defaultWebhookHandler = async (url: string, payload: unknown): Promise<void> => {
  const response = await fetchWithTimeout(
    url,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
    10_000,
  );

  if (!response.ok) {
    throw new Error(`Webhook returned HTTP ${response.status}`);
  }
};

const defaultEnrichHandler = async (iocValue: string, indicatorType: IndicatorType): Promise<void> => {
  await enrichWithCache(iocValue, indicatorType);
};

export async function evaluateNewIndicators(
  newIndicators: ThreatIndicator[],
  handlers?: AutoTriggerHandlers,
): Promise<{ evaluatedCount: number; triggeredCount: number; errors: string[] }> {
  const enabledRules = listRules(true);

  if (enabledRules.length === 0 || newIndicators.length === 0) {
    return { evaluatedCount: 0, triggeredCount: 0, errors: [] };
  }

  const webhookHandler = handlers?.webhook || defaultWebhookHandler;
  const enrichHandler = handlers?.enrich || defaultEnrichHandler;

  let evaluatedCount = 0;
  let triggeredCount = 0;
  const errors: string[] = [];

  for (const indicator of newIndicators) {
    for (const rule of enabledRules) {
      evaluatedCount++;

      try {
        const matched = evaluateRule(rule, indicator);

        if (matched) {
          triggeredCount++;
          const result = await executeActions(rule, indicator, {
            webhook: webhookHandler,
            enrich: enrichHandler,
          });

          if (!result.success) {
            errors.push(...result.errors);
          }
        }
      } catch (err) {
        errors.push(`Rule ${rule.name} evaluation failed: ${errorMessage(err)}`);
      }
    }
  }

  return { evaluatedCount, triggeredCount, errors };
}

export function setupAutoTrigger(
  store: {
    onRefresh: (listener: () => void) => () => void;
    getIndicators: () => ThreatIndicator[];
  },
  handlers?: AutoTriggerHandlers,
): () => void {
  let previousIndicatorIds = new Set(store.getIndicators().map((indicator) => indicator.id));
  let pendingEvaluation = Promise.resolve();

  const listener = () => {
    const currentThreats = store.getIndicators();
    const currentIds = new Set(currentThreats.map((indicator) => indicator.id));
    const newIndicators = currentThreats.filter((indicator) => !previousIndicatorIds.has(indicator.id));
    previousIndicatorIds = currentIds;

    if (newIndicators.length === 0) return;
    pendingEvaluation = pendingEvaluation.then(async () => {
      const result = await evaluateNewIndicators(newIndicators, handlers);

      if (result.triggeredCount > 0) {
        console.log(
          `[rules] Auto-trigger: evaluated ${result.evaluatedCount} rule-indicator pairs, triggered ${result.triggeredCount} actions`,
        );
      }

      if (result.errors.length > 0) {
        console.error(`[rules] Auto-trigger errors:`, result.errors);
      }
    }).catch((err) => console.error(`[rules] Auto-trigger failed: ${errorMessage(err)}`));
  };

  return store.onRefresh(listener);
}
