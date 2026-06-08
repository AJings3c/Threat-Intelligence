import type {
  FetchResult,
  IndicatorType,
  Severity,
  ThreatIndicator,
  ThreatType,
} from '../types.js';
import { fetchWithTimeout, errorMessage } from '../util.js';

const THREATFOX_RECENT_URL = 'https://threatfox.abuse.ch/export/json/recent/';

interface ThreatFoxEntry {
  ioc_value: string;
  ioc_type: string;
  threat_type?: string;
  malware?: string | null;
  malware_alias?: string | null;
  malware_printable?: string | null;
  first_seen_utc?: string | null;
  last_seen_utc?: string | null;
  confidence_level?: number | string | null;
  is_compromised?: boolean | string | null;
  reference?: string | null;
  tags?: string | string[] | null;
  reporter?: string | null;
}

type ThreatFoxResponse = Record<string, ThreatFoxEntry[]>;

function dateTimeUtc(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value.replace(' ', 'T').replace(/Z?$/, 'Z'));
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function severityFromConfidence(value: ThreatFoxEntry['confidence_level']): Severity {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) return 'medium';
  if (n >= 90) return 'critical';
  if (n >= 70) return 'high';
  if (n >= 40) return 'medium';
  return 'low';
}

function splitTags(value: ThreatFoxEntry['tags']): string[] {
  if (Array.isArray(value)) return value.map((tag) => tag.trim()).filter(Boolean);
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((tag) => tag.trim())
      .filter(Boolean);
  }
  return [];
}

function observable(entry: ThreatFoxEntry): { value: string; type: IndicatorType; extraTags: string[] } | null {
  const raw = entry.ioc_value.trim();
  const iocType = entry.ioc_type.toLowerCase();

  if (iocType === 'ip:port') {
    const match = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
    if (!match) return null;
    return { value: match[1], type: 'ip', extraTags: [`port:${match[2]}`] };
  }
  if (iocType === 'ip' || iocType === 'ipv4') {
    return { value: raw, type: 'ip', extraTags: [] };
  }
  if (iocType === 'domain') {
    return { value: raw.toLowerCase(), type: 'domain', extraTags: [] };
  }
  if (iocType === 'url') {
    try {
      new URL(raw);
      return { value: raw, type: 'url', extraTags: [] };
    } catch {
      return null;
    }
  }
  if (iocType.endsWith('_hash') || iocType === 'hash') {
    return { value: raw.toLowerCase(), type: 'hash', extraTags: [iocType.replace('_hash', '')] };
  }

  return null;
}

function threatTypeFor(entry: ThreatFoxEntry, indicatorType: IndicatorType): ThreatType {
  const threat = (entry.threat_type ?? '').toLowerCase();
  if (threat === 'botnet_cc') return 'c2_server';
  if (indicatorType === 'hash') return 'malicious_hash';
  if (indicatorType === 'url') return 'malicious_url';
  return 'malware_host';
}

function titleFor(entry: ThreatFoxEntry, type: ThreatType): string {
  const malware = entry.malware_printable || entry.malware_alias || entry.malware;
  const label = type === 'c2_server' ? 'C2 IOC' : type.replace(/_/g, ' ');
  return malware ? `${malware} ${label}` : label;
}

export function parseThreatFoxResponse(
  data: ThreatFoxResponse,
  fetchedAt = Date.now(),
  limit = 1000,
): ThreatIndicator[] {
  const entries = Object.entries(data)
    .map(([id, arr]) => ({ id, entry: arr?.[0] }))
    .filter((item): item is { id: string; entry: ThreatFoxEntry } => Boolean(item.entry))
    .sort((a, b) =>
      (b.entry.first_seen_utc ?? '').localeCompare(a.entry.first_seen_utc ?? ''),
    );
  const fetchedIso = new Date(fetchedAt).toISOString();
  const items: ThreatIndicator[] = [];

  for (const { id, entry } of entries) {
    const obs = observable(entry);
    if (!obs) continue;
    const type = threatTypeFor(entry, obs.type);
    const tags = Array.from(
      new Set(
        [
          entry.threat_type,
          entry.malware,
          entry.malware_alias,
          entry.malware_printable,
          entry.reporter,
          ...splitTags(entry.tags),
          ...obs.extraTags,
        ].filter((tag): tag is string => Boolean(tag)),
      ),
    );
    const port = obs.extraTags.find((tag) => tag.startsWith('port:'))?.slice(5);

    items.push({
      id: `threatfox:${id}`,
      source: 'threatfox',
      type,
      indicator: obs.value,
      indicatorType: obs.type,
      severity: severityFromConfidence(entry.confidence_level),
      title: titleFor(entry, type),
      description: [
        entry.threat_type ? `Threat: ${entry.threat_type}` : null,
        entry.malware_printable ? `Malware: ${entry.malware_printable}` : null,
        port ? `Port: ${port}` : null,
        entry.confidence_level ? `Confidence: ${entry.confidence_level}` : null,
      ]
        .filter(Boolean)
        .join(' · '),
      malwareFamily: entry.malware_printable || entry.malware || undefined,
      tags,
      reference: entry.reference || `https://threatfox.abuse.ch/ioc/${id}/`,
      firstSeen: dateTimeUtc(entry.first_seen_utc),
      lastSeen: dateTimeUtc(entry.last_seen_utc) ?? fetchedIso,
    });
    if (items.length >= limit) break;
  }

  return items;
}

export async function fetchThreatFox(limit = 1000): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  try {
    const res = await fetchWithTimeout(THREATFOX_RECENT_URL, {}, 30_000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as ThreatFoxResponse;
    return { items: parseThreatFoxResponse(data, fetchedAt, limit), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
