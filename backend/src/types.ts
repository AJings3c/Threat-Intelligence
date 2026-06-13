// Unified threat-intelligence data model.
// Normalized across all sources (CISA KEV, abuse.ch feeds, phishing feeds, NVD).

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
export type ApiRole = 'viewer' | 'analyst' | 'admin';
export type Language = 'en' | 'zh';

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
  // All sources reporting this indicator (>=2 means cross-source corroboration).
  sources?: ThreatSource[];
  // Derived 0-100 confidence: more independent sources + higher severity => higher.
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

export interface FetchResult<T> {
  items: T[];
  fetchedAt: number;
  error: string | null;
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

export type StrideCategory =
  | 'Spoofing'
  | 'Tampering'
  | 'Repudiation'
  | 'Information Disclosure'
  | 'Denial of Service'
  | 'Elevation of Privilege';

export type ThreatModelLayer = 'system' | 'application' | 'service' | 'code';
export type ThreatTreatmentStatus = 'implemented' | 'planned' | 'accepted' | 'transferred';

export interface ThreatModelReference {
  title: string;
  url: string;
}

export interface ThreatModelMethodology {
  framework: 'STRIDE';
  scoring: 'DREAD';
  process: string[];
  reviewTriggers: string[];
  references: ThreatModelReference[];
}

export interface DreadScore {
  damage: number;
  reproducibility: number;
  exploitability: number;
  affectedUsers: number;
  discoverability: number;
  total: number;
  average: number;
  risk: Severity;
  rationale: string[];
}

export interface ThreatModelScenario {
  id: string;
  title: string;
  stride: StrideCategory;
  severity: Severity;
  confidence: number;
  evidence: string[];
  recommendations: string[];
  assetIds?: string[];
  dataFlowIds?: string[];
  threat?: string;
  impact?: string;
  dread?: DreadScore;
  controls?: string[];
  treatment?: ThreatTreatmentStatus;
  verification?: string[];
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
  owner?: string;
  securityObjectives?: Array<'confidentiality' | 'integrity' | 'availability' | 'accountability'>;
}

export interface ThreatModelDataFlow {
  id: string;
  from: string;
  to: string;
  name: string;
  protocol: string;
  crossesTrustBoundary: boolean;
  data: string[];
  trustBoundary?: string;
  threatSurface?: string[];
}

export interface TrustBoundary {
  id: string;
  name: string;
  description: string;
  assets: string[];
}

export interface ThreatModelLayerView {
  layer: ThreatModelLayer;
  description: string;
  assets: string[];
  trustBoundaries: string[];
  entryPoints: string[];
}

export interface ThreatModelMatrixRow {
  elementId: string;
  elementType: 'asset' | 'data_flow' | 'trust_boundary';
  elementName: string;
  stride: Partial<Record<StrideCategory, string[]>>;
  priority: Severity;
}

export interface ThreatModelAttackPath {
  id: string;
  actor: string;
  objective: string;
  entryPoint: string;
  path: string[];
  impactedAssets: string[];
  stride: StrideCategory[];
  severity: Severity;
  mitigations: string[];
}

export interface ThreatModelControl {
  id: string;
  name: string;
  status: ThreatTreatmentStatus;
  owner: string;
  scenarios: string[];
  verification: string[];
}

export interface ArchitectureThreatModel {
  scope: string;
  generatedAt: string;
  methodology: ThreatModelMethodology;
  layers: ThreatModelLayerView[];
  assets: ThreatModelAsset[];
  dataFlows: ThreatModelDataFlow[];
  trustBoundaries: TrustBoundary[];
  threatMatrix: ThreatModelMatrixRow[];
  scenarios: ThreatModelScenario[];
  attackPaths: ThreatModelAttackPath[];
  controls: ThreatModelControl[];
  assumptions: string[];
  nextSteps: string[];
}

export interface AuditEvent {
  ts: string;
  role: ApiRole;
  action: string;
  path: string;
  ok: boolean;
  detail: string;
}

// Phase 1: Platform Upgrade Types

export type CaseStatus = 'open' | 'investigating' | 'resolved' | 'closed';

export interface Case {
  id: string;
  title: string;
  status: CaseStatus;
  severity: Severity;
  assignee?: string;
  iocIds: string[];
  comments: CaseComment[];
  createdAt: number;
  updatedAt: number;
}

export interface CaseComment {
  id: string;
  caseId: string;
  author: string;
  content: string;
  createdAt: number;
}

export type RuleTriggerType = 'ioc_match' | 'threshold' | 'schedule';
export type RuleActionType = 'webhook' | 'ticket' | 'block' | 'enrich';

export interface RuleAction {
  type: RuleActionType;
  config: Record<string, unknown>;
}

export interface Rule {
  id: string;
  name: string;
  triggerType: RuleTriggerType;
  triggerConfig: Record<string, unknown>;
  actions: RuleAction[];
  enabled: boolean;
  createdAt: number;
}

export interface RuleExecution {
  id: string;
  ruleId: string;
  triggeredAt: number;
  actionsTaken: RuleAction[];
  success: boolean;
}

export interface EnrichmentCache {
  iocValue: string;
  provider: string;
  result: Record<string, unknown>;
  cachedAt: number;
}

export interface FalsePositive {
  iocValue: string;
  markedBy: string;
  reason?: string;
  markedAt: number;
}

export interface HuntQuery {
  iocs: string[];
  timeRange: { start: number; end: number };
  sources?: ThreatSource[];
}

export interface HuntResult {
  ioc: string;
  matches: ThreatIndicator[];
  firstSeen?: string;
  lastSeen?: string;
  confidence: number;
}

export interface HuntHistory {
  id: string;
  query: string;
  resultsCount: number;
  initiatedBy: string;
  createdAt: number;
}

