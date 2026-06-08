export type ThreatSource =
  | 'cisa_kev'
  | 'feodo'
  | 'urlhaus'
  | 'nvd'
  | 'x'
  | 'facebook'
  | 'openphish'
  | 'threatfox'
  | 'malwarebazaar'
  | 'spamhaus_drop'
  | 'dshield'
  | 'phishtank'
  | 'abuseipdb'
  | 'otx'
  | 'taxii_import';
export type ThreatType =
  | 'c2_server'
  | 'malware_host'
  | 'malicious_url'
  | 'phishing_url'
  | 'malicious_hash'
  | 'malicious_network'
  | 'scanner_network'
  | 'exploited_vuln'
  | 'vulnerability'
  | 'social_intel';
export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'cidr' | 'cve';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Tlp = 'clear' | 'green' | 'amber' | 'red';
export type SourceReliability = 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
export type SourceHealthStatus = 'healthy' | 'disabled' | 'warming' | 'error' | 'stale' | 'deprecated';
export type EnrichmentProvider = 'virustotal' | 'shodan' | 'censys';
export type IntegrationKind = 'source' | 'provider';
export type IntegrationTestStatus = 'ok' | 'missing_config' | 'failed' | 'unsupported';

export interface ThreatIndicator {
  id: string;
  source: ThreatSource;
  type: ThreatType;
  indicator: string;
  indicatorType: IndicatorType;
  severity: Severity;
  title?: string;
  description?: string;
  malwareFamily?: string;
  country?: string;
  lat?: number;
  lon?: number;
  tags: string[];
  reference?: string;
  firstSeen?: string;
  lastSeen?: string;
  sources?: ThreatSource[];
  confidence?: number;
  sourceReliability?: SourceReliability;
  tlp?: Tlp;
}

export interface CveItem {
  id: string;
  source: ThreatSource;
  title: string;
  description: string;
  severity: Severity;
  cvssScore?: number;
  cvssVector?: string;
  epssScore?: number;
  epssPercentile?: number;
  epssDate?: string;
  sourceReliability?: SourceReliability;
  tlp?: Tlp;
  published?: string;
  lastModified?: string;
  reference: string;
  knownExploited: boolean;
}

export interface SourceHealth {
  source: ThreatSource;
  label: string;
  ok: boolean;
  status: SourceHealthStatus;
  configured: boolean;
  credentialed: boolean;
  requiredEnv: string[];
  stale: boolean;
  deprecated: boolean;
  deprecationMessage?: string;
  count: number;
  lastFetched: string | null;
  lastError: string | null;
  ageMs: number | null;
  refreshIntervalMs: number;
}

export interface SourceHealthHistoryPoint {
  ts: number;
  source: ThreatSource;
  ok: boolean;
  stale: boolean;
  count: number;
  error: string | null;
}

export interface Stats {
  totalIndicators: number;
  totalCves: number;
  bySource: Record<ThreatSource, number>;
  byType: Record<ThreatType, number>;
  bySeverity: Record<Severity, number>;
  topCountries: { country: string; count: number }[];
  lastRefresh: number;
}

export interface ThreatsResponse {
  threats: ThreatIndicator[];
  total: number;
  generatedAt: string;
}

export interface MapResponse {
  points: ThreatIndicator[];
  generatedAt: string;
}

export interface CveResponse {
  cves: CveItem[];
  total: number;
}

export interface MalwareFamilySummary {
  family: string;
  count: number;
  sources: ThreatSource[];
  critical: number;
  high: number;
  medium: number;
  low: number;
  lastSeen: string | null;
}

export interface HashIntelResponse {
  hashes: ThreatIndicator[];
  total: number;
  families: MalwareFamilySummary[];
}

export interface TrendPoint {
  ts: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TrendResponse {
  enabled: boolean;
  points: TrendPoint[];
}

export interface SourceHistoryResponse {
  enabled: boolean;
  points: SourceHealthHistoryPoint[];
}

export interface SourceConfigStatus {
  source: ThreatSource;
  label: string;
  configured: boolean;
  credentialed: boolean;
  requiredEnv: string[];
  status: SourceHealthStatus;
  count: number;
  lastError: string | null;
  lastFetched: string | null;
}

export interface ProviderConfigStatus {
  provider: EnrichmentProvider;
  configured: boolean;
  requiredEnv: string[];
}

export interface EnrichmentResult {
  provider: EnrichmentProvider;
  ok: boolean;
  error: string | null;
  summary: Record<string, unknown> | null;
  reference?: string;
}

export interface EnrichmentResponse {
  indicator: string;
  indicatorType: IndicatorType;
  results: EnrichmentResult[];
}

export interface IntegrationTestResult {
  kind: IntegrationKind;
  id: ThreatSource | EnrichmentProvider;
  label: string;
  status: IntegrationTestStatus;
  configured: boolean;
  requiredEnv: string[];
  testedAt: string;
  latencyMs: number | null;
  message: string;
  sampleCount?: number;
}

export interface NotifyStatus {
  enabled: boolean;
  channels: { dingtalk: boolean; telegram: boolean; slack: boolean; webhook: boolean };
  minSeverity: Severity;
  intervalMs: number;
  sources: string[] | null;
  maxItems: number;
  seenCount: number;
  lastRunAt: string | null;
  lastSentCount: number;
  lastResult: Record<string, string> | null;
}

export interface ConfigStatusResponse {
  sources: SourceConfigStatus[];
  enrichmentProviders: ProviderConfigStatus[];
  notify: NotifyStatus;
  persistence: { enabled: boolean };
}

export interface NotifyTestResponse {
  sent: number;
  result: Record<string, string>;
}

export type StrideCategory =
  | 'Spoofing'
  | 'Tampering'
  | 'Repudiation'
  | 'Information Disclosure'
  | 'Denial of Service'
  | 'Elevation of Privilege';

export interface ThreatModelScenario {
  id: string;
  title: string;
  stride: StrideCategory;
  severity: Severity;
  confidence: number;
  evidence: string[];
  recommendations: string[];
}

export interface IocInvestigation {
  indicator: string;
  indicatorType: IndicatorType;
  exactMatches: ThreatIndicator[];
  relatedIndicators: ThreatIndicator[];
  sourceSummary: Array<{ source: ThreatSource; count: number }>;
  model: {
    posture: 'matched' | 'related_only' | 'no_match';
    highestSeverity: Severity | null;
    confidence: number;
    scenarios: ThreatModelScenario[];
    nextSteps: string[];
  };
}

export interface InvestigationHistoryEntry {
  id: string;
  ts: number;
  indicator: string;
  indicatorType: IndicatorType;
  posture: IocInvestigation['model']['posture'];
  exactCount: number;
  relatedCount: number;
  highestSeverity: Severity | null;
  confidence: number;
}

export interface ThreatModelAsset {
  id: string;
  name: string;
  kind: 'user' | 'service' | 'data_store' | 'external_source' | 'secret' | 'integration';
  trustZone: string;
  criticality: Severity;
  data: string[];
}

export interface ThreatModelDataFlow {
  id: string;
  from: string;
  to: string;
  name: string;
  protocol: string;
  crossesTrustBoundary: boolean;
  data: string[];
}

export interface TrustBoundary {
  id: string;
  name: string;
  description: string;
  assets: string[];
}

export interface ArchitectureThreatModel {
  scope: string;
  generatedAt: string;
  assets: ThreatModelAsset[];
  dataFlows: ThreatModelDataFlow[];
  trustBoundaries: TrustBoundary[];
  scenarios: ThreatModelScenario[];
  assumptions: string[];
  nextSteps: string[];
}
