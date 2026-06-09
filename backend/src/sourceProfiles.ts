import type { SourceReliability, ThreatSource, Tlp } from './types.js';

export interface SourceProfile {
  reliability: SourceReliability;
  tlp: Tlp;
  confidenceWeight: number;
  credentialed?: boolean;
  requiredEnv?: string[];
  deprecated?: {
    since: string;
    message: string;
    replacement?: string;
  };
}

export const SOURCE_PROFILES: Record<ThreatSource, SourceProfile> = {
  cisa_kev: { reliability: 'A', tlp: 'clear', confidenceWeight: 25 },
  feodo: { reliability: 'A', tlp: 'clear', confidenceWeight: 22 },
  urlhaus: { reliability: 'A', tlp: 'clear', confidenceWeight: 22 },
  nvd: { reliability: 'A', tlp: 'clear', confidenceWeight: 18 },
  x: { reliability: 'C', tlp: 'clear', confidenceWeight: 4, credentialed: true, requiredEnv: ['X_BEARER_TOKEN'] },
  facebook: {
    reliability: 'C',
    tlp: 'clear',
    confidenceWeight: 4,
    credentialed: true,
    requiredEnv: ['FACEBOOK_ACCESS_TOKEN', 'FACEBOOK_PAGE_IDS'],
  },
  openphish: { reliability: 'B', tlp: 'clear', confidenceWeight: 14 },
  threatfox: { reliability: 'B', tlp: 'clear', confidenceWeight: 18 },
  malwarebazaar: { reliability: 'B', tlp: 'clear', confidenceWeight: 18 },
  spamhaus_drop: { reliability: 'A', tlp: 'clear', confidenceWeight: 20 },
  dshield: { reliability: 'B', tlp: 'clear', confidenceWeight: 12 },
  phishtank: {
    reliability: 'B',
    tlp: 'clear',
    confidenceWeight: 14,
    credentialed: true,
    requiredEnv: ['PHISHTANK_APP_KEY'],
  },
  abuseipdb: {
    reliability: 'B',
    tlp: 'clear',
    confidenceWeight: 14,
    credentialed: true,
    requiredEnv: ['ABUSEIPDB_API_KEY'],
  },
  otx: { reliability: 'B', tlp: 'clear', confidenceWeight: 16, credentialed: true, requiredEnv: ['OTX_API_KEY'] },
  taxii_import: {
    reliability: 'C',
    tlp: 'clear',
    confidenceWeight: 10,
    credentialed: true,
    requiredEnv: ['TAXII_IMPORT_OBJECTS_URL'],
  },
};

export function sourceProfile(source: ThreatSource): SourceProfile {
  return SOURCE_PROFILES[source];
}

export function sourceRequiredEnv(source: ThreatSource): string[] {
  return sourceProfile(source).requiredEnv ?? [];
}

export function isSourceConfigured(source: ThreatSource, env: NodeJS.ProcessEnv = process.env): boolean {
  const required = sourceRequiredEnv(source);
  return required.length === 0 || required.every((name) => Boolean(env[name]?.trim()));
}
