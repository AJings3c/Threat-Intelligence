import type {
  EnrichmentProvider,
  EnrichmentResponse,
  EnrichmentResult,
  IndicatorType,
  ProviderConfigStatus,
} from './types.js';
import { errorMessage, fetchWithRetry, fetchWithTimeout } from './util.js';

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
    const res = await fetchWithRetry(`${base}${path}`, { headers: { 'x-apikey': apiKey } }, 30_000);
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
    const res = await fetchWithRetry(`${base}/${encodeURIComponent(indicator)}?${params.toString()}`, {}, 30_000);
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
    const res = await fetchWithRetry(
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

export async function enrichGreyNoise(indicator: string, type: IndicatorType): Promise<EnrichmentResult | null> {
  const apiKey = process.env.GREYNOISE_API_KEY?.trim();
  if (!apiKey || type !== 'ip') return null;
  try {
    const base = (process.env.GREYNOISE_API_BASE?.trim() || 'https://api.greynoise.io/v3/community').replace(
      /\/+$/,
      '',
    );
    const res = await fetchWithRetry(
      `${base}/${encodeURIComponent(indicator)}`,
      { headers: { key: apiKey } },
      30_000,
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as Record<string, unknown>;
    return {
      provider: 'greynoise',
      ok: true,
      error: null,
      summary: {
        noise: data.noise,
        riot: data.riot,
        classification: data.classification,
        name: data.name,
        link: data.link,
        lastSeen: data.last_seen,
      },
      reference: `https://viz.greynoise.io/ip/${encodeURIComponent(indicator)}`,
    };
  } catch (err) {
    return { provider: 'greynoise', ok: false, error: errorMessage(err), summary: null };
  }
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function enrichURLScan(indicator: string, type: IndicatorType): Promise<EnrichmentResult | null> {
  const apiKey = process.env.URLSCAN_API_KEY?.trim();
  if (!apiKey || type !== 'url') return null;
  try {
    const base = (process.env.URLSCAN_API_BASE?.trim() || 'https://urlscan.io/api/v1').replace(/\/+$/, '');

    const submitRes = await fetchWithTimeout(
      `${base}/scan/`,
      {
        method: 'POST',
        headers: {
          'API-Key': apiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: indicator, visibility: 'private' }),
      },
      30_000,
    );

    if (!submitRes.ok) throw new Error(`HTTP ${submitRes.status}`);
    const submitData = (await submitRes.json()) as Record<string, unknown>;
    const uuid = submitData.uuid as string;
    const apiUrl = submitData.api as string;

    let resultData: Record<string, unknown> | null = null;
    for (let i = 0; i < 6; i++) {
      await sleep(5000);
      const resultRes = await fetchWithRetry(apiUrl, {}, 30_000);
      if (resultRes.status === 200) {
        resultData = (await resultRes.json()) as Record<string, unknown>;
        break;
      }
    }

    if (!resultData) {
      return { provider: 'urlscan', ok: false, error: 'Scan timeout after 30 seconds', summary: null };
    }

    const task = objectRecord(resultData.task);
    const page = objectRecord(resultData.page);
    const verdicts = objectRecord(resultData.verdicts);
    const lists = objectRecord(resultData.lists);

    return {
      provider: 'urlscan',
      ok: true,
      error: null,
      summary: {
        screenshot: task.screenshotURL,
        verdict: verdicts.overall,
        malicious: verdicts.malicious,
        ip: page.ip,
        asn: page.asn,
        country: page.country,
        domain: page.domain,
        urls: Array.isArray(lists.urls) ? lists.urls.slice(0, 10) : undefined,
        certificates: Array.isArray(lists.certificates) ? lists.certificates.slice(0, 5) : undefined,
      },
      reference: `https://urlscan.io/result/${uuid}/`,
    };
  } catch (err) {
    return { provider: 'urlscan', ok: false, error: errorMessage(err), summary: null };
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
    enrichGreyNoise(indicator, indicatorType),
    enrichURLScan(indicator, indicatorType),
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

export function enrichmentConfigStatus(env: NodeJS.ProcessEnv = process.env): ProviderConfigStatus[] {
  return [
    {
      provider: 'virustotal',
      configured: Boolean(env.VIRUSTOTAL_API_KEY?.trim()),
      requiredEnv: ['VIRUSTOTAL_API_KEY'],
    },
    {
      provider: 'shodan',
      configured: Boolean(env.SHODAN_API_KEY?.trim()),
      requiredEnv: ['SHODAN_API_KEY'],
    },
    {
      provider: 'censys',
      configured: Boolean(env.CENSYS_API_ID?.trim() && env.CENSYS_API_SECRET?.trim()),
      requiredEnv: ['CENSYS_API_ID', 'CENSYS_API_SECRET'],
    },
    {
      provider: 'greynoise',
      configured: Boolean(env.GREYNOISE_API_KEY?.trim()),
      requiredEnv: ['GREYNOISE_API_KEY'],
    },
    {
      provider: 'urlscan',
      configured: Boolean(env.URLSCAN_API_KEY?.trim()),
      requiredEnv: ['URLSCAN_API_KEY'],
    },
  ];
}

export function providerRequiredEnv(provider: EnrichmentProvider): string[] {
  return enrichmentConfigStatus().find((item) => item.provider === provider)?.requiredEnv ?? [];
}

export function isProviderConfigured(
  provider: EnrichmentProvider,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return enrichmentConfigStatus(env).some((item) => item.provider === provider && item.configured);
}
