import type { FetchResult, IndicatorType, Severity, ThreatIndicator, ThreatType } from '../types.js';
import { errorMessage, fetchWithTimeout } from '../util.js';

const OTX_SUBSCRIBED_PULSES_URL = 'https://otx.alienvault.com/api/v1/pulses/subscribed';

interface OtxIndicator {
  indicator?: string;
  type?: string;
  created?: string;
  description?: string | null;
}

interface OtxPulse {
  id?: string;
  name?: string;
  description?: string;
  created?: string;
  modified?: string;
  tags?: string[];
  indicators?: OtxIndicator[];
}

interface OtxResponse {
  results?: OtxPulse[];
}

function envInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

function parseTime(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function indicatorKind(type: string | undefined, value: string): IndicatorType | null {
  const t = (type ?? '').toLowerCase();
  if (t === 'ipv4' || t === 'ip') return 'ip';
  if (t === 'domain' || t === 'hostname') return 'domain';
  if (t === 'url' || t === 'uri') return 'url';
  if (t.includes('filehash') || t.includes('hash') || /^[a-f0-9]{32,64}$/i.test(value)) return 'hash';
  if (t === 'cve') return 'cve';
  return null;
}

function threatTypeFor(indicatorType: IndicatorType): ThreatType {
  switch (indicatorType) {
    case 'url':
      return 'malicious_url';
    case 'hash':
      return 'malicious_hash';
    case 'cve':
      return 'vulnerability';
    default:
      return 'malware_host';
  }
}

function severityFor(tags: string[] | undefined, indicatorType: IndicatorType): Severity {
  const joined = (tags ?? []).join(' ').toLowerCase();
  if (joined.includes('ransomware') || joined.includes('apt')) return 'critical';
  if (indicatorType === 'cve' || indicatorType === 'hash') return 'high';
  return 'medium';
}

export function parseOtxPulses(data: OtxResponse, limit = 1000): ThreatIndicator[] {
  const items: ThreatIndicator[] = [];
  const seen = new Set<string>();

  for (const pulse of data.results ?? []) {
    const pulseId = pulse.id ?? 'unknown';
    for (const raw of pulse.indicators ?? []) {
      const value = raw.indicator?.trim();
      if (!value) continue;
      const indicatorType = indicatorKind(raw.type, value);
      if (!indicatorType) continue;
      const key = `${indicatorType}:${value.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);

      items.push({
        id: `otx:${pulseId}:${items.length}`,
        source: 'otx',
        type: threatTypeFor(indicatorType),
        indicator: indicatorType === 'domain' || indicatorType === 'hash' ? value.toLowerCase() : value,
        indicatorType,
        severity: severityFor(pulse.tags, indicatorType),
        title: pulse.name ?? 'AlienVault OTX indicator',
        description: raw.description ?? pulse.description,
        tags: ['otx', raw.type, ...(pulse.tags ?? [])].filter((tag): tag is string => Boolean(tag)),
        reference: pulse.id ? `https://otx.alienvault.com/pulse/${pulse.id}` : 'https://otx.alienvault.com/',
        firstSeen: parseTime(raw.created ?? pulse.created),
        lastSeen: parseTime(pulse.modified),
      });
      if (items.length >= limit) return items;
    }
  }

  return items;
}

export async function fetchOtx(limit = 1000): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  const apiKey = process.env.OTX_API_KEY?.trim();
  if (!apiKey) return { items: [], fetchedAt, error: null };

  try {
    const apiBase = (process.env.OTX_API_BASE?.trim() || OTX_SUBSCRIBED_PULSES_URL).replace(
      /\/+$/,
      '',
    );
    const requestedLimit = envInt(process.env.OTX_LIMIT, limit, 1, 10_000);
    const params = new URLSearchParams({ limit: String(Math.min(requestedLimit, 100)) });
    const res = await fetchWithTimeout(
      `${apiBase}?${params.toString()}`,
      { headers: { 'X-OTX-API-KEY': apiKey } },
      45_000,
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as OtxResponse;
    return { items: parseOtxPulses(data, Math.min(limit, requestedLimit)), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
