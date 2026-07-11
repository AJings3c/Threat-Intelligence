import { describe, expect, it, vi } from 'vitest';
import type { Rule, ThreatIndicator } from '../src/types.js';

const rule: Rule = {
  id: 'auto-rule',
  name: 'new IOC webhook',
  triggerType: 'ioc_match',
  triggerConfig: {},
  actions: [{ type: 'webhook', config: { url: 'https://example.test/hook' } }],
  enabled: true,
  createdAt: 1,
};

vi.mock('../src/rules/index.js', () => ({
  listRules: () => [rule],
}));

import { setupAutoTrigger } from '../src/rules/autoTrigger.js';

function indicator(id: string): ThreatIndicator {
  return {
    id,
    source: 'feodo',
    type: 'c2_server',
    indicator: `192.0.2.${id}`,
    indicatorType: 'ip',
    severity: 'high',
    tags: [],
  };
}

describe('automatic rule triggering', () => {
  it('seeds the existing baseline and evaluates only indicators added later', async () => {
    let indicators = [indicator('1')];
    let refreshListener: (() => void) | null = null;
    const webhook = vi.fn().mockResolvedValue(undefined);
    const unsubscribe = setupAutoTrigger(
      {
        getIndicators: () => indicators,
        onRefresh: (listener) => {
          refreshListener = listener;
          return vi.fn();
        },
      },
      { webhook },
    );

    expect(unsubscribe).toBeTypeOf('function');
    refreshListener?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(webhook).not.toHaveBeenCalled();

    indicators = [...indicators, indicator('2')];
    refreshListener?.();
    await vi.waitFor(() => expect(webhook).toHaveBeenCalledTimes(1));
    expect(webhook.mock.calls[0][1]).toMatchObject({ indicator: { id: '2' } });
  });
});
