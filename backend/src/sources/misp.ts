import type {
  DetectionArtifact,
  DetectionArtifactFormat,
  FetchResult,
  IndicatorType,
  ThreatIndicator,
  ThreatType,
} from '../types.js';
import { getConnectorState, persistDetectionArtifacts, setConnectorState } from '../persist.js';
import { errorMessage, fetchWithRetry } from '../util.js';

interface MispTag {
  name?: string;
}

interface MispAttribute {
  id?: string;
  event_id?: string;
  type?: string;
  category?: string;
  value?: string;
  comment?: string;
  timestamp?: string;
  to_ids?: boolean;
  Tag?: MispTag[];
}

interface MispEvent {
  Event?: { Attribute?: MispAttribute[] };
  Attribute?: MispAttribute[];
}

interface MispResponse {
  response?: { Attribute?: MispAttribute[] } | MispEvent[];
  Attribute?: MispAttribute[];
}

function envInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

function attributesOf(data: MispResponse): MispAttribute[] {
  if (Array.isArray(data.Attribute)) return data.Attribute;
  if (Array.isArray(data.response)) {
    return data.response.flatMap((entry) => entry.Attribute ?? entry.Event?.Attribute ?? []);
  }
  return data.response?.Attribute ?? [];
}

function timeOf(timestamp: string | undefined): string | undefined {
  if (!timestamp) return undefined;
  const seconds = Number(timestamp);
  if (Number.isFinite(seconds)) return new Date(seconds * 1000).toISOString();
  const parsed = new Date(timestamp);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function observables(attribute: MispAttribute): Array<{ value: string; indicatorType: IndicatorType }> {
  const value = attribute.value?.trim();
  if (!value) return [];
  switch (attribute.type?.toLowerCase()) {
    case 'ip-src':
    case 'ip-dst':
      return [{ value, indicatorType: 'ip' }];
    case 'ip-src|port':
    case 'ip-dst|port':
      return [{ value: value.split('|')[0], indicatorType: 'ip' }];
    case 'domain':
    case 'hostname':
      return [{ value: value.toLowerCase(), indicatorType: 'domain' }];
    case 'domain|ip': {
      const [domain, ip] = value.split('|');
      return [
        ...(domain ? [{ value: domain.toLowerCase(), indicatorType: 'domain' as const }] : []),
        ...(ip ? [{ value: ip, indicatorType: 'ip' as const }] : []),
      ];
    }
    case 'url':
    case 'uri':
      return [{ value, indicatorType: 'url' }];
    case 'md5':
    case 'sha1':
    case 'sha256':
    case 'sha512':
      return [{ value: value.toLowerCase(), indicatorType: 'hash' }];
    case 'snort':
    case 'yara':
    case 'sigma':
      return [];
    default:
      return [];
  }
}

function threatType(indicatorType: IndicatorType, tags: string[]): ThreatType {
  if (indicatorType === 'url') return tags.some((tag) => tag.includes('phish')) ? 'phishing_url' : 'malicious_url';
  if (indicatorType === 'hash') return 'malicious_hash';
  return 'malware_host';
}

export function parseMispAttributes(
  data: MispResponse,
  baseUrl = 'https://misp.invalid',
  limit = 1000,
): ThreatIndicator[] {
  const items: ThreatIndicator[] = [];
  const seen = new Set<string>();
  for (const attribute of attributesOf(data)) {
    const tags = (attribute.Tag ?? []).map((tag) => tag.name?.trim()).filter((tag): tag is string => Boolean(tag));
    for (const observable of observables(attribute)) {
      const key = `${observable.indicatorType}:${observable.value.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const observedAt = timeOf(attribute.timestamp);
      items.push({
        id: `misp:${attribute.id ?? items.length}:${observable.indicatorType}`,
        source: 'misp',
        type: threatType(observable.indicatorType, tags),
        indicator: observable.value,
        indicatorType: observable.indicatorType,
        severity: attribute.to_ids === false ? 'low' : 'medium',
        title: attribute.category ? `MISP ${attribute.category}` : 'MISP attribute',
        description: attribute.comment || undefined,
        tags: ['misp', attribute.type ?? 'attribute', ...tags],
        reference: attribute.event_id ? new URL(`/events/view/${attribute.event_id}`, baseUrl).toString() : baseUrl,
        firstSeen: observedAt,
        lastSeen: observedAt,
      });
      if (items.length >= limit) return items;
    }
  }
  return items;
}

export function parseMispDetectionArtifacts(
  data: MispResponse,
  baseUrl = 'https://misp.invalid',
): DetectionArtifact[] {
  const artifacts: DetectionArtifact[] = [];
  for (const attribute of attributesOf(data)) {
    const format = attribute.type?.toLowerCase() as DetectionArtifactFormat | undefined;
    if (format !== 'sigma' && format !== 'yara' && format !== 'snort') continue;
    const content = attribute.value?.trim();
    if (!content) continue;
    const observedAt = timeOf(attribute.timestamp);
    artifacts.push({
      id: `misp:${attribute.id ?? artifacts.length}:${format}`,
      source: 'misp',
      format,
      content,
      title: attribute.category ? `MISP ${attribute.category} ${format.toUpperCase()}` : `MISP ${format.toUpperCase()}`,
      description: attribute.comment || undefined,
      tags: ['misp', format, ...(attribute.Tag ?? []).map((tag) => tag.name ?? '').filter(Boolean)],
      reference: attribute.event_id ? new URL(`/events/view/${attribute.event_id}`, baseUrl).toString() : baseUrl,
      firstSeen: observedAt,
      lastSeen: observedAt,
    });
  }
  return artifacts;
}

export async function fetchMisp(limit = 1000): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  const baseUrl = process.env.MISP_BASE_URL?.trim();
  const apiKey = process.env.MISP_API_KEY?.trim();
  if (!baseUrl || !apiKey) return { items: [], fetchedAt, error: null };

  try {
    const parsedBase = new URL(baseUrl);
    if (parsedBase.protocol !== 'https:') throw new Error('MISP_BASE_URL must use HTTPS');
    const endpoint = new URL('/attributes/restSearch', parsedBase).toString();
    const pageLimit = envInt(process.env.MISP_PAGE_LIMIT, Math.min(limit, 500), 1, 5000);
    const maxPages = envInt(process.env.MISP_MAX_PAGES, 5, 1, 100);
    const configuredTimestamp = process.env.MISP_IMPORT_TIMESTAMP?.trim();
    const state = getConnectorState('misp');
    const timestamp = configuredTimestamp || (typeof state.timestamp === 'string' ? state.timestamp : undefined);
    const attributes: MispAttribute[] = [];
    let complete = false;
    for (let page = 1; page <= maxPages && attributes.length < limit; page += 1) {
      const res = await fetchWithRetry(
        endpoint,
        {
          method: 'POST',
          headers: {
            Authorization: apiKey,
            Accept: 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            returnFormat: 'json',
            published: true,
            to_ids: true,
            limit: pageLimit,
            page,
            ...(timestamp ? { timestamp } : {}),
          }),
        },
        60_000,
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const pageAttributes = attributesOf((await res.json()) as MispResponse);
      attributes.push(...pageAttributes);
      if (pageAttributes.length < pageLimit) {
        complete = true;
        break;
      }
    }
    if (!configuredTimestamp && complete) {
      setConnectorState('misp', { timestamp: String(Math.floor(fetchedAt / 1000)) }, fetchedAt);
    }
    persistDetectionArtifacts(parseMispDetectionArtifacts({ Attribute: attributes }, parsedBase.toString()), fetchedAt);
    return { items: parseMispAttributes({ Attribute: attributes }, parsedBase.toString(), limit), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
