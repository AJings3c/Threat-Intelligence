export type ThreatSource = 'cisa_kev' | 'feodo' | 'urlhaus' | 'nvd';
export type ThreatType =
  | 'c2_server'
  | 'malware_host'
  | 'malicious_url'
  | 'exploited_vuln'
  | 'vulnerability';
export type IndicatorType = 'ip' | 'domain' | 'url' | 'cve';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

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
}

export interface CveItem {
  id: string;
  source: ThreatSource;
  title: string;
  description: string;
  severity: Severity;
  cvssScore?: number;
  cvssVector?: string;
  published?: string;
  lastModified?: string;
  reference: string;
  knownExploited: boolean;
}

export interface SourceHealth {
  source: ThreatSource;
  label: string;
  ok: boolean;
  count: number;
  lastFetched: string | null;
  lastError: string | null;
  ageMs: number | null;
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
