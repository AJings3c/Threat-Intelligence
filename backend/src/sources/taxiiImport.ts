import type { FetchResult, IndicatorType, ThreatIndicator, ThreatType } from '../types.js';
import { errorMessage, fetchWithTimeout } from '../util.js';
import { STIX_MEDIA_TYPE, TAXII_MEDIA_TYPE } from '../taxii.js';

interface ExternalReference {
  source_name?: string;
  external_id?: string;
  url?: string;
}

interface ImportedStixObject {
  type?: string;
  id?: string;
  name?: string;
  description?: string;
  pattern?: string;
  labels?: string[];
  valid_from?: string;
  created?: string;
  modified?: string;
  confidence?: number;
  external_references?: ExternalReference[];
}

interface TaxiiEnvelope {
  objects?: ImportedStixObject[];
  more?: boolean;
  next?: string;
}

function envInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

function pageUrl(objectsUrl: string, next: string | null, addedAfter: string | null, limit: number): string {
  const url = new URL(objectsUrl);
  if (addedAfter && !next) url.searchParams.set('added_after', addedAfter);
  if (next) url.searchParams.set('next', next);
  url.searchParams.set('limit', String(limit));
  return url.toString();
}

function parseTime(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function extractQuoted(pattern: string, property: string): string | null {
  const escaped = property.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`${escaped}\\s*(?:=|ISSUBSET)\\s*'([^']+)'`, 'i');
  return pattern.match(re)?.[1] ?? null;
}

function observableFromPattern(pattern: string | undefined): {
  value: string;
  indicatorType: IndicatorType;
} | null {
  if (!pattern) return null;
  const ip = extractQuoted(pattern, 'ipv4-addr:value');
  if (ip) return { value: ip, indicatorType: ip.includes('/') ? 'cidr' : 'ip' };
  const domain = extractQuoted(pattern, 'domain-name:value');
  if (domain) return { value: domain.toLowerCase(), indicatorType: 'domain' };
  const url = extractQuoted(pattern, 'url:value');
  if (url) return { value: url, indicatorType: 'url' };
  const sha256 = extractQuoted(pattern, "file:hashes.'SHA-256'") ?? extractQuoted(pattern, 'file:hashes.SHA-256');
  if (sha256) return { value: sha256.toLowerCase(), indicatorType: 'hash' };
  const sha1 = extractQuoted(pattern, "file:hashes.'SHA-1'") ?? extractQuoted(pattern, 'file:hashes.SHA-1');
  if (sha1) return { value: sha1.toLowerCase(), indicatorType: 'hash' };
  const md5 = extractQuoted(pattern, 'file:hashes.MD5');
  if (md5) return { value: md5.toLowerCase(), indicatorType: 'hash' };
  return null;
}

function cveId(object: ImportedStixObject): string | null {
  if (object.name?.startsWith('CVE-')) return object.name;
  for (const ref of object.external_references ?? []) {
    if (ref.external_id?.startsWith('CVE-')) return ref.external_id;
  }
  return null;
}

function threatTypeFor(indicatorType: IndicatorType): ThreatType {
  switch (indicatorType) {
    case 'url':
      return 'malicious_url';
    case 'hash':
      return 'malicious_hash';
    case 'cidr':
      return 'malicious_network';
    case 'cve':
      return 'vulnerability';
    default:
      return 'malware_host';
  }
}

export function parseTaxiiObjects(data: TaxiiEnvelope, limit = 1000): ThreatIndicator[] {
  const items: ThreatIndicator[] = [];
  const seen = new Set<string>();

  for (const object of data.objects ?? []) {
    let observable: { value: string; indicatorType: IndicatorType } | null = null;
    if (object.type === 'indicator') observable = observableFromPattern(object.pattern);
    if (object.type === 'vulnerability') {
      const cve = cveId(object);
      if (cve) observable = { value: cve, indicatorType: 'cve' };
    }
    if (!observable) continue;
    const key = `${observable.indicatorType}:${observable.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);

    items.push({
      id: `taxii_import:${object.id ?? items.length}`,
      source: 'taxii_import',
      type: threatTypeFor(observable.indicatorType),
      indicator: observable.value,
      indicatorType: observable.indicatorType,
      severity: object.confidence !== undefined && object.confidence >= 80 ? 'high' : 'medium',
      title: object.name ?? 'Imported TAXII indicator',
      description: object.description,
      tags: ['taxii', ...(object.labels ?? [])],
      reference: object.external_references?.find((ref) => ref.url)?.url,
      firstSeen: parseTime(object.valid_from ?? object.created),
      lastSeen: parseTime(object.modified),
      confidence: object.confidence,
    });
    if (items.length >= limit) break;
  }

  return items;
}

export async function fetchTaxiiImport(limit = 1000): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  const objectsUrl = process.env.TAXII_IMPORT_OBJECTS_URL?.trim();
  if (!objectsUrl) return { items: [], fetchedAt, error: null };

  try {
    const headers: Record<string, string> = {
      Accept: `${TAXII_MEDIA_TYPE}, ${STIX_MEDIA_TYPE}, application/json`,
    };
    const bearer = process.env.TAXII_IMPORT_BEARER_TOKEN?.trim();
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const username = process.env.TAXII_IMPORT_USERNAME?.trim();
    const password = process.env.TAXII_IMPORT_PASSWORD?.trim();
    if (!bearer && username && password) {
      headers.Authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
    }
    const pageLimit = envInt(process.env.TAXII_IMPORT_PAGE_LIMIT, Math.min(limit, 500), 1, 1000);
    const maxPages = envInt(process.env.TAXII_IMPORT_MAX_PAGES, 5, 1, 100);
    const addedAfter = process.env.TAXII_IMPORT_ADDED_AFTER?.trim() || null;
    const objects: ImportedStixObject[] = [];
    let next: string | null = null;
    for (let page = 0; page < maxPages && objects.length < limit; page += 1) {
      const res = await fetchWithTimeout(pageUrl(objectsUrl, next, addedAfter, pageLimit), { headers }, 60_000);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as TaxiiEnvelope;
      objects.push(...(data.objects ?? []));
      if (!data.more || !data.next) break;
      next = data.next;
    }
    return { items: parseTaxiiObjects({ objects }, limit), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
