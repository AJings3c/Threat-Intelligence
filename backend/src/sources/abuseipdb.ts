import type { FetchResult, Severity, ThreatIndicator } from '../types.js';
import { errorMessage, fetchWithTimeout } from '../util.js';

const ABUSEIPDB_BLACKLIST_URL = 'https://api.abuseipdb.com/api/v2/blacklist';

interface AbuseIpDbEntry {
  ipAddress?: string;
  abuseConfidenceScore?: number;
  countryCode?: string;
  usageType?: string;
  isp?: string;
  domain?: string;
  lastReportedAt?: string;
}

interface AbuseIpDbResponse {
  data?: AbuseIpDbEntry[];
}

function clampEnvInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

function severityFromScore(score: number | undefined): Severity {
  if (score === undefined) return 'medium';
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

function parseTime(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

export function parseAbuseIpDbBlacklist(data: AbuseIpDbResponse, limit = 1000): ThreatIndicator[] {
  const seen = new Set<string>();
  const items: ThreatIndicator[] = [];

  for (const entry of data.data ?? []) {
    const ip = entry.ipAddress?.trim();
    if (!ip || seen.has(ip)) continue;
    seen.add(ip);
    const score = entry.abuseConfidenceScore;
    items.push({
      id: `abuseipdb:${ip}`,
      source: 'abuseipdb',
      type: 'malware_host',
      indicator: ip,
      indicatorType: 'ip',
      severity: severityFromScore(score),
      title: 'AbuseIPDB reported IP',
      description: [
        score !== undefined ? `Abuse confidence: ${score}` : null,
        entry.isp ? `ISP: ${entry.isp}` : null,
        entry.usageType ? `Usage: ${entry.usageType}` : null,
      ]
        .filter(Boolean)
        .join(' · '),
      country: entry.countryCode,
      tags: ['abuseipdb', entry.usageType, entry.isp, entry.domain].filter((tag): tag is string =>
        Boolean(tag),
      ),
      reference: `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`,
      lastSeen: parseTime(entry.lastReportedAt),
    });
    if (items.length >= limit) break;
  }

  return items;
}

export async function fetchAbuseIpDb(limit = 1000): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  const apiKey = process.env.ABUSEIPDB_API_KEY?.trim();
  if (!apiKey) return { items: [], fetchedAt, error: null };

  try {
    const apiBase = (process.env.ABUSEIPDB_API_BASE?.trim() || ABUSEIPDB_BLACKLIST_URL).replace(
      /\/+$/,
      '',
    );
    const confidenceMinimum = clampEnvInt(process.env.ABUSEIPDB_CONFIDENCE_MINIMUM, 90, 0, 100);
    const requestedLimit = clampEnvInt(process.env.ABUSEIPDB_LIMIT, limit, 1, 10_000);
    const params = new URLSearchParams({
      confidenceMinimum: String(confidenceMinimum),
      limit: String(Math.min(limit, requestedLimit)),
      ipVersion: '4',
    });
    const res = await fetchWithTimeout(
      `${apiBase}?${params.toString()}`,
      { headers: { Key: apiKey, Accept: 'application/json' } },
      45_000,
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as AbuseIpDbResponse;
    return { items: parseAbuseIpDbBlacklist(data, Math.min(limit, requestedLimit)), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
