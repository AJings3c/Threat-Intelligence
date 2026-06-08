import type { IndicatorType } from './types.js';
import { errorMessage, fetchWithTimeout } from './util.js';

export interface EnrichmentResult {
  provider: 'virustotal' | 'shodan' | 'censys';
  ok: boolean;
  error: string | null;
  summary: Record<string, unknown> | null;
  reference?: string;
}

export interface EnrichmentResponse {
  indicator: string;
  indicatorType: IndicatorType;
  results: EnrichmentResult[];
}

function urlSafeBase64(value: string): string {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function numberRecord(value: unknown): Record<string, number> | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const out: Record<string, number> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw === 'number') out[key] = raw;
  }
  return out;
}

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

function vtPath(indicator: string, type: IndicatorType): string | null {
  switch (type) {
    case 'hash':
      return `/files/${encodeURIComponent(indicator)}`;
    case 'ip':
      return `/ip_addresses/${encodeURIComponent(indicator)}`;
    case 'domain':
      return `/domains/${encodeURIComponent(indicator)}`;
    case 'url':
      return `/urls/${urlSafeBase64(indicator)}`;
    default:
      return null;
  }
}

export async function enrichVirusTotal(
  indicator: string,
  type: IndicatorType,
): Promise<EnrichmentResult | null> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  const path = vtPath(indicator, type);
  if (!apiKey || !path) return null;
  try {
    const base = (process.env.VIRUSTOTAL_API_BASE?.trim() || 'https://www.virustotal.com/api/v3').replace(
      /\/+$/,
      '',
    );
    const res = await fetchWithTimeout(`${base}${path}`, { headers: { 'x-apikey': apiKey } }, 30_000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = (await res.json()) as Record<string, unknown>;
    const data = objectRecord(json.data);
    const attrs = objectRecord(data.attributes);
    return {
      provider: 'virustotal',
      ok: true,
      error: null,
      summary: {
        reputation: attrs.reputation,
        lastAnalysisStats: numberRecord(attrs.last_analysis_stats),
        categories: attrs.categories,
      },
      reference: `https://www.virustotal.com/gui/${type === 'ip' ? 'ip-address' : type}/${encodeURIComponent(
        indicator,
      )}`,
    };
  } catch (err) {
    return { provider: 'virustotal', ok: false, error: errorMessage(err), summary: null };
  }
}

export async function enrichShodan(indicator: string, type: IndicatorType): Promise<EnrichmentResult | null> {
  const apiKey = process.env.SHODAN_API_KEY?.trim();
  if (!apiKey || type !== 'ip') return null;
  try {
    const base = (process.env.SHODAN_API_BASE?.trim() || 'https://api.shodan.io/shodan/host').replace(/\/+$/, '');
    const params = new URLSearchParams({ key: apiKey });
    const res = await fetchWithTimeout(`${base}/${encodeURIComponent(indicator)}?${params.toString()}`, {}, 30_000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return {
      provider: 'shodan',
      ok: true,
      error: null,
      summary: {
        ports: Array.isArray(data.ports) ? data.ports : undefined,
        hostnames: Array.isArray(data.hostnames) ? data.hostnames : undefined,
        org: data.org,
        isp: data.isp,
        vulns: data.vulns && typeof data.vulns === 'object' ? Object.keys(data.vulns) : undefined,
      },
      reference: `https://www.shodan.io/host/${encodeURIComponent(indicator)}`,
    };
  } catch (err) {
    return { provider: 'shodan', ok: false, error: errorMessage(err), summary: null };
  }
}

export async function enrichCensys(indicator: string, type: IndicatorType): Promise<EnrichmentResult | null> {
  const apiId = process.env.CENSYS_API_ID?.trim();
  const apiSecret = process.env.CENSYS_API_SECRET?.trim();
  if (!apiId || !apiSecret || type !== 'ip') return null;
  try {
    const base = (process.env.CENSYS_API_BASE?.trim() || 'https://search.censys.io/api/v2/hosts').replace(
      /\/+$/,
      '',
    );
    const auth = Buffer.from(`${apiId}:${apiSecret}`).toString('base64');
    const res = await fetchWithTimeout(
      `${base}/${encodeURIComponent(indicator)}`,
      { headers: { Authorization: `Basic ${auth}` } },
      30_000,
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    const result = objectRecord(data.result);
    const location = objectRecord(result.location);
    const autonomousSystem = objectRecord(result.autonomous_system);
    return {
      provider: 'censys',
      ok: true,
      error: null,
      summary: {
        serviceCount: result.service_count,
        services: Array.isArray(result.services)
          ? result.services.slice(0, 20).map((service) => {
              const s = objectRecord(service);
              return { port: s.port, service_name: s.service_name, transport_protocol: s.transport_protocol };
            })
          : undefined,
        country: location.country,
        asn: autonomousSystem.asn,
        asName: autonomousSystem.name,
      },
      reference: `https://search.censys.io/hosts/${encodeURIComponent(indicator)}`,
    };
  } catch (err) {
    return { provider: 'censys', ok: false, error: errorMessage(err), summary: null };
  }
}

export async function enrichIndicator(
  indicator: string,
  indicatorType: IndicatorType,
): Promise<EnrichmentResponse> {
  const results = await Promise.all([
    enrichVirusTotal(indicator, indicatorType),
    enrichShodan(indicator, indicatorType),
    enrichCensys(indicator, indicatorType),
  ]);
  return {
    indicator,
    indicatorType,
    results: results.filter((result): result is EnrichmentResult => Boolean(result)),
  };
}

export function parseIndicatorType(value: string | undefined): IndicatorType | null {
  if (
    value === 'ip' ||
    value === 'domain' ||
    value === 'url' ||
    value === 'hash' ||
    value === 'cidr' ||
    value === 'cve'
  ) {
    return value;
  }
  return null;
}
