import { describe, expect, it } from 'vitest';
import { prometheusMetrics } from '../src/metrics.js';

describe('Prometheus metrics', () => {
  it('renders intelligence, source health, persistence, and job gauges', () => {
    const output = prometheusMetrics({
      totalIndicators: 12,
      totalCves: 3,
      lastRefreshAt: 2_000,
      persistenceEnabled: true,
      uptimeSeconds: 42,
      jobs: { queued: 2, running: 1, succeeded: 4, failed: 0, dead: 1 },
      health: [
        {
          source: 'nvd',
          label: 'NVD',
          ok: true,
          status: 'healthy',
          configured: true,
          credentialed: false,
          requiredEnv: [],
          stale: false,
          deprecated: false,
          count: 3,
          lastFetched: '2026-07-11T00:00:00.000Z',
          lastError: null,
          ageMs: 0,
          refreshIntervalMs: 1000,
        },
      ],
    });

    expect(output).toContain('threat_intel_indicators 12');
    expect(output).toContain('threat_intel_source_healthy{source="nvd"} 1');
    expect(output).toContain('threat_intel_background_jobs{status="dead"} 1');
    expect(output).toContain('threat_intel_process_uptime_seconds 42');
  });
});
