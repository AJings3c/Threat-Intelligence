import type { SourceHealth } from './types.js';
import type { BackgroundJobStatus } from './persist.js';

interface MetricsInput {
  totalIndicators: number;
  totalCves: number;
  lastRefreshAt: number | null;
  health: SourceHealth[];
  persistenceEnabled: boolean;
  jobs: Record<BackgroundJobStatus, number>;
  uptimeSeconds?: number;
}

function label(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

export function prometheusMetrics(input: MetricsInput): string {
  const lines = [
    '# HELP threat_intel_indicators Current normalized indicator count.',
    '# TYPE threat_intel_indicators gauge',
    `threat_intel_indicators ${input.totalIndicators}`,
    '# HELP threat_intel_cves Current normalized CVE count.',
    '# TYPE threat_intel_cves gauge',
    `threat_intel_cves ${input.totalCves}`,
    '# HELP threat_intel_last_refresh_timestamp_seconds Last completed refresh as Unix time.',
    '# TYPE threat_intel_last_refresh_timestamp_seconds gauge',
    `threat_intel_last_refresh_timestamp_seconds ${input.lastRefreshAt ? input.lastRefreshAt / 1000 : 0}`,
    '# HELP threat_intel_persistence_enabled Whether durable SQLite persistence is active.',
    '# TYPE threat_intel_persistence_enabled gauge',
    `threat_intel_persistence_enabled ${input.persistenceEnabled ? 1 : 0}`,
    '# HELP threat_intel_source_healthy Whether a source is currently healthy.',
    '# TYPE threat_intel_source_healthy gauge',
    '# HELP threat_intel_source_stale Whether a source result is stale.',
    '# TYPE threat_intel_source_stale gauge',
    '# HELP threat_intel_source_items Current item count retained for a source.',
    '# TYPE threat_intel_source_items gauge',
  ];
  for (const source of input.health) {
    const sourceLabel = label(source.source);
    lines.push(`threat_intel_source_healthy{source="${sourceLabel}"} ${source.ok ? 1 : 0}`);
    lines.push(`threat_intel_source_stale{source="${sourceLabel}"} ${source.stale ? 1 : 0}`);
    lines.push(`threat_intel_source_items{source="${sourceLabel}"} ${source.count}`);
  }
  lines.push(
    '# HELP threat_intel_background_jobs Durable jobs grouped by status.',
    '# TYPE threat_intel_background_jobs gauge',
  );
  for (const [status, count] of Object.entries(input.jobs)) {
    lines.push(`threat_intel_background_jobs{status="${label(status)}"} ${count}`);
  }
  lines.push(
    '# HELP threat_intel_process_uptime_seconds Backend process uptime.',
    '# TYPE threat_intel_process_uptime_seconds gauge',
    `threat_intel_process_uptime_seconds ${input.uptimeSeconds ?? process.uptime()}`,
  );
  return `${lines.join('\n')}\n`;
}
