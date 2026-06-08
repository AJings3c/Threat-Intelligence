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
  provider: 'virustotal' | 'shodan' | 'censys';
  configured: boolean;
  requiredEnv: string[];
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
