import crypto from 'node:crypto';
import type { ThreatIndicator, CveItem } from './types.js';

// Minimal STIX 2.1 export so indicators/CVEs can be shared with MISP / OpenCTI / SIEMs.
// We emit `indicator` SDOs (with STIX patterns) for network IOCs and `vulnerability`
// SDOs for CVEs, wrapped in a bundle.

export interface StixObject {
  type: string;
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  [key: string]: unknown;
}

export interface StixBundle {
  type: 'bundle';
  id: string;
  objects: StixObject[];
}

function patternFor(t: ThreatIndicator): string | null {
  const v = t.indicator.replace(/'/g, "\\'");
  switch (t.indicatorType) {
    case 'ip':
      return `[ipv4-addr:value = '${v}']`;
    case 'domain':
      return `[domain-name:value = '${v}']`;
    case 'url':
      return `[url:value = '${v}']`;
    case 'cidr':
      return `[ipv4-addr:value = '${v}']`;
    case 'hash':
      if (/^[a-f0-9]{64}$/i.test(t.indicator)) return `[file:hashes.'SHA-256' = '${v}']`;
      if (/^[a-f0-9]{40}$/i.test(t.indicator)) return `[file:hashes.'SHA-1' = '${v}']`;
      if (/^[a-f0-9]{32}$/i.test(t.indicator)) return `[file:hashes.MD5 = '${v}']`;
      return null;
    default:
      return null; // 'cve' is exported as a vulnerability SDO instead
  }
}

function vulnerability(id: string, created: string, name?: string, description?: string): StixObject {
  return {
    type: 'vulnerability',
    spec_version: '2.1',
    id: `vulnerability--${crypto.randomUUID()}`,
    created,
    modified: created,
    name: name ?? id,
    description,
    external_references: [{ source_name: 'cve', external_id: id }],
  };
}

export function buildStixBundle(
  indicators: ThreatIndicator[],
  cves: CveItem[],
  now = new Date(),
): StixBundle {
  const created = now.toISOString();
  const objects: StixObject[] = [];
  const seenVuln = new Set<string>();

  for (const t of indicators) {
    if (t.indicatorType === 'cve') {
      if (seenVuln.has(t.indicator)) continue;
      seenVuln.add(t.indicator);
      objects.push(vulnerability(t.indicator, created, t.title, t.description));
      continue;
    }
    const pattern = patternFor(t);
    if (!pattern) continue;
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${crypto.randomUUID()}`,
      created,
      modified: created,
      name: t.title ?? t.indicator,
      description: t.description,
      indicator_types: ['malicious-activity'],
      pattern,
      pattern_type: 'stix',
      valid_from: t.firstSeen ?? created,
      labels: t.tags.length > 0 ? t.tags : undefined,
      confidence: t.confidence,
      x_threat_intel_source_reliability: t.sourceReliability,
      x_threat_intel_tlp: t.tlp,
      external_references: t.reference ? [{ source_name: t.source, url: t.reference }] : undefined,
    });
  }

  for (const c of cves) {
    if (seenVuln.has(c.id)) continue;
    seenVuln.add(c.id);
    objects.push(vulnerability(c.id, created, c.title, c.description));
  }

  return { type: 'bundle', id: `bundle--${crypto.randomUUID()}`, objects };
}
