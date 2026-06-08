import type { SourceReliability, ThreatSource, Tlp } from './types.js';

export interface SourceProfile {
  reliability: SourceReliability;
  tlp: Tlp;
  confidenceWeight: number;
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
  x: { reliability: 'C', tlp: 'clear', confidenceWeight: 4 },
  facebook: { reliability: 'C', tlp: 'clear', confidenceWeight: 4 },
  openphish: { reliability: 'B', tlp: 'clear', confidenceWeight: 14 },
  threatfox: { reliability: 'B', tlp: 'clear', confidenceWeight: 18 },
  malwarebazaar: { reliability: 'B', tlp: 'clear', confidenceWeight: 18 },
  spamhaus_drop: { reliability: 'A', tlp: 'clear', confidenceWeight: 20 },
  dshield: { reliability: 'B', tlp: 'clear', confidenceWeight: 12 },
  phishtank: { reliability: 'B', tlp: 'clear', confidenceWeight: 14 },
  abuseipdb: { reliability: 'B', tlp: 'clear', confidenceWeight: 14 },
  otx: { reliability: 'B', tlp: 'clear', confidenceWeight: 16 },
  taxii_import: { reliability: 'C', tlp: 'clear', confidenceWeight: 10 },
};

export function sourceProfile(source: ThreatSource): SourceProfile {
  return SOURCE_PROFILES[source];
}
