import type { Severity, ThreatSource, ThreatType } from './types';

export const SOURCE_LABELS: Record<ThreatSource, string> = {
  cisa_kev: 'CISA KEV',
  feodo: 'Feodo Tracker',
  urlhaus: 'URLhaus',
  nvd: 'NVD CVE',
  x: 'X Security Intel',
  facebook: 'Facebook Security Intel',
};

export const TYPE_LABELS: Record<ThreatType, string> = {
  c2_server: 'C2 Server',
  malware_host: 'Malware Host',
  malicious_url: 'Malicious URL',
  exploited_vuln: 'Exploited Vuln',
  vulnerability: 'Vulnerability',
  social_intel: 'Social Intel',
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#38bdf8',
};

export const SEVERITY_BADGE: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-red-300 border-red-500/40',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  medium: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40',
  low: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
};
