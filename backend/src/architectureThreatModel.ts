import type { ArchitectureThreatModel, Severity, SourceHealth, ThreatModelScenario } from './types.js';

interface StatsLike {
  totalIndicators: number;
  totalCves: number;
}

function scenario(
  id: string,
  title: string,
  stride: ThreatModelScenario['stride'],
  severity: Severity,
  confidence: number,
  evidence: string[],
  recommendations: string[],
): ThreatModelScenario {
  return { id, title, stride, severity, confidence, evidence, recommendations };
}

export function buildArchitectureThreatModel(stats: StatsLike, health: SourceHealth[]): ArchitectureThreatModel {
  const disabled = health.filter((source) => source.status === 'disabled');
  const failing = health.filter((source) => source.status === 'error' || source.status === 'stale');
  const configuredCredentialed = health.filter((source) => source.credentialed && source.configured);
  const publicSourceCount = health.filter((source) => !source.credentialed).length;

  return {
    scope: 'Threat Intelligence Platform',
    generatedAt: new Date().toISOString(),
    assets: [
      {
        id: 'analyst',
        name: 'Security analyst',
        kind: 'user',
        trustZone: 'operator',
        criticality: 'medium',
        data: ['investigation decisions', 'exported reports'],
      },
      {
        id: 'dashboard',
        name: 'React dashboard',
        kind: 'service',
        trustZone: 'application',
        criticality: 'medium',
        data: ['IOC searches', 'configuration status', 'model output'],
      },
      {
        id: 'api',
        name: 'Express API',
        kind: 'service',
        trustZone: 'application',
        criticality: 'high',
        data: ['normalized indicators', 'source health', 'enrichment responses'],
      },
      {
        id: 'store',
        name: 'Aggregator store and optional SQLite persistence',
        kind: 'data_store',
        trustZone: 'data',
        criticality: 'high',
        data: ['first/last seen', 'investigation history', 'audit events', 'geo cache'],
      },
      {
        id: 'feeds',
        name: 'External threat-intelligence feeds',
        kind: 'external_source',
        trustZone: 'internet',
        criticality: 'high',
        data: ['public IOCs', 'credentialed feed data', 'CVE data'],
      },
      {
        id: 'secrets',
        name: 'API keys and notification webhooks',
        kind: 'secret',
        trustZone: 'deployment',
        criticality: 'critical',
        data: ['OTX/AbuseIPDB/VT/Shodan/Censys credentials', 'push channel webhooks'],
      },
      {
        id: 'consumers',
        name: 'SIEM, TAXII, and notification consumers',
        kind: 'integration',
        trustZone: 'external_consumer',
        criticality: 'medium',
        data: ['STIX objects', 'digest messages', 'reports'],
      },
    ],
    trustBoundaries: [
      {
        id: 'browser-api',
        name: 'Browser to API',
        description: 'Operators send searches and actions from the dashboard to the API.',
        assets: ['analyst', 'dashboard', 'api'],
      },
      {
        id: 'api-internet',
        name: 'API to internet feeds',
        description: 'Collectors and enrichers receive untrusted upstream data and provider responses.',
        assets: ['api', 'feeds'],
      },
      {
        id: 'api-data',
        name: 'API to persistence',
        description: 'The API writes operational history, audit data, and cached observations.',
        assets: ['api', 'store'],
      },
      {
        id: 'api-consumers',
        name: 'API to downstream consumers',
        description: 'Exports and notifications leave the platform boundary.',
        assets: ['api', 'consumers'],
      },
    ],
    dataFlows: [
      {
        id: 'search-flow',
        from: 'dashboard',
        to: 'api',
        name: 'IOC search and threat modeling',
        protocol: 'HTTPS/JSON',
        crossesTrustBoundary: true,
        data: ['indicator', 'indicator type', 'model response'],
      },
      {
        id: 'feed-flow',
        from: 'feeds',
        to: 'api',
        name: 'Feed collection and enrichment',
        protocol: 'HTTPS/JSON, CSV, STIX/TAXII',
        crossesTrustBoundary: true,
        data: ['IOCs', 'CVEs', 'provider summaries'],
      },
      {
        id: 'persist-flow',
        from: 'api',
        to: 'store',
        name: 'Operational persistence',
        protocol: 'SQLite',
        crossesTrustBoundary: false,
        data: ['history', 'audit events', 'source health'],
      },
      {
        id: 'export-flow',
        from: 'api',
        to: 'consumers',
        name: 'STIX/TAXII/report/notification export',
        protocol: 'HTTPS/JSON, STIX 2.1, Markdown',
        crossesTrustBoundary: true,
        data: ['indicator bundle', 'threat model', 'alert digest'],
      },
    ],
    scenarios: [
      scenario(
        'spoofed-feed-data',
        'Untrusted upstream feed data pollutes local intelligence',
        'Spoofing',
        failing.length > 0 ? 'high' : 'medium',
        70,
        [
          `${publicSourceCount} public sources are ingested from the internet`,
          `${stats.totalIndicators} indicators are currently normalized`,
          failing.length > 0 ? `${failing.length} sources are stale or failing` : 'No stale/error sources in current health',
        ],
        [
          'Preserve source provenance, reliability, TLP, and confidence near every indicator',
          'Corroborate high-impact decisions across multiple sources or enrichment providers',
          'Alert on source health regression before using stale-only evidence',
        ],
      ),
      scenario(
        'tampered-model-output',
        'A client or intermediary tampers with exported reports or model output',
        'Tampering',
        'high',
        65,
        ['Reports and STIX/TAXII exports leave the API trust boundary', 'Operators may use exports in downstream workflows'],
        [
          'Serve exports only over TLS behind trusted ingress',
          'Record audit events for report generation and configuration tests',
          'Add file signing or checksum validation for regulated downstream exchange',
        ],
      ),
      scenario(
        'missing-audit-accountability',
        'Configuration and investigation actions cannot be attributed',
        'Repudiation',
        'medium',
        60,
        ['Configuration tests and enrichment calls can create external provider traffic', 'Investigation history is operational evidence'],
        [
          'Use role-scoped API tokens for analyst/admin actions',
          'Persist audit events when DATA_DIR is configured',
          'Review audit logs during incident review and source onboarding',
        ],
      ),
      scenario(
        'secret-disclosure',
        'Provider credentials or webhook URLs are exposed',
        'Information Disclosure',
        configuredCredentialed.length > 0 ? 'critical' : 'high',
        80,
        [
          `${configuredCredentialed.length} credentialed sources are configured`,
          `${disabled.length} credentialed sources are currently disabled or missing configuration`,
        ],
        [
          'Never return secret values from configuration APIs',
          'Keep credentials in environment or secret manager only',
          'Rotate provider keys after failed deployment or suspicious audit entries',
        ],
      ),
      scenario(
        'enrichment-abuse',
        'High-volume enrichment requests exhaust API quota or degrade service',
        'Denial of Service',
        'high',
        75,
        ['On-demand enrichment calls external providers', 'IOC searches and reports are interactive analyst workflows'],
        [
          'Keep rate limiting enabled for API routes',
          'Cache enrichment results or add provider-specific backoff before production scale',
          'Restrict enrichment and config testing to analyst/admin roles',
        ],
      ),
      scenario(
        'overbroad-admin-token',
        'A broad API token enables unauthorized configuration tests or outbound messages',
        'Elevation of Privilege',
        'high',
        70,
        ['Notify test sends real messages', 'Configuration test can call credentialed providers'],
        [
          'Use viewer, analyst, and admin token sets instead of one shared token',
          'Require admin role for notification and integration test endpoints',
          'Keep production deployments behind an auth proxy when browser users are untrusted',
        ],
      ),
    ],
    assumptions: [
      'The model is generated from the platform architecture and current source health, not a customer-specific DFD.',
      'Credential presence is treated as a secret-handling risk even though secret values are never returned.',
      'Provider and source connectivity tests are operator-triggered because they may consume quota.',
    ],
    nextSteps: [
      'Replace this generated architecture model with a deployment-specific DFD for regulated environments',
      'Map concrete assets, data classifications, trust boundaries, and owners before production launch',
      'Review every high or critical STRIDE scenario during source onboarding',
    ],
  };
}
