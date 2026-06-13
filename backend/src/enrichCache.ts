import { getEnrichmentCache, setEnrichmentCache, cleanExpiredCache } from './persist.js';
import { enrichVirusTotal, enrichShodan, enrichCensys } from './enrich.js';
import type { EnrichmentResult, EnrichmentResponse, IndicatorType } from './types.js';

const CACHE_TTL_MS = 3600 * 1000; // 1 hour

export async function enrichWithCache(
  indicator: string,
  indicatorType: IndicatorType,
): Promise<EnrichmentResponse> {
  const providers = ['virustotal', 'shodan', 'censys'] as const;
  const results: EnrichmentResult[] = [];

  for (const provider of providers) {
    const cached = getEnrichmentCache(indicator, provider);

    if (cached) {
      const row = cached as { result: string; cached_at: number };
      try {
        const result = JSON.parse(row.result) as EnrichmentResult;
        results.push(result);
        continue;
      } catch {
        // Invalid cache, fetch fresh
      }
    }

    let result: EnrichmentResult | null = null;

    switch (provider) {
      case 'virustotal':
        result = await enrichVirusTotal(indicator, indicatorType);
        break;
      case 'shodan':
        result = await enrichShodan(indicator, indicatorType);
        break;
      case 'censys':
        result = await enrichCensys(indicator, indicatorType);
        break;
    }

    if (result) {
      results.push(result);
      setEnrichmentCache(indicator, provider, JSON.stringify(result), Date.now());
    }
  }

  return {
    indicator,
    indicatorType,
    results,
  };
}

export async function enrichGreyNoise(indicator: string, type: IndicatorType): Promise<EnrichmentResult | null> {
  const apiKey = process.env.GREYNOISE_API_KEY?.trim();
  if (!apiKey || type !== 'ip') return null;

  try {
    const response = await fetch(`https://api.greynoise.io/v3/community/${encodeURIComponent(indicator)}`, {
      headers: { key: apiKey },
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = (await response.json()) as Record<string, unknown>;

    return {
      provider: 'greynoise' as any,
      ok: true,
      error: null,
      summary: {
        noise: data.noise,
        riot: data.riot,
        classification: data.classification,
        name: data.name,
        lastSeen: data.last_seen,
      },
      reference: `https://viz.greynoise.io/ip/${encodeURIComponent(indicator)}`,
    };
  } catch (err) {
    return {
      provider: 'greynoise' as any,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      summary: null,
    };
  }
}

export async function enrichURLScan(indicator: string, type: IndicatorType): Promise<EnrichmentResult | null> {
  const apiKey = process.env.URLSCAN_API_KEY?.trim();
  if (!apiKey || type !== 'url') return null;

  try {
    const submitResponse = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'API-Key': apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: indicator, visibility: 'unlisted' }),
    });

    if (!submitResponse.ok) throw new Error(`HTTP ${submitResponse.status}`);
    const submitData = (await submitResponse.json()) as Record<string, unknown>;
    const uuid = submitData.uuid as string;

    await new Promise((resolve) => setTimeout(resolve, 10000));

    const resultResponse = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
    if (!resultResponse.ok) throw new Error(`Result not ready yet`);
    const resultData = (await resultResponse.json()) as Record<string, unknown>;

    const task = resultData.task as Record<string, unknown> | undefined;
    const page = resultData.page as Record<string, unknown> | undefined;

    return {
      provider: 'urlscan' as any,
      ok: true,
      error: null,
      summary: {
        screenshotUrl: task?.screenshotURL,
        verdict: page?.verdict,
        status: page?.status,
        server: page?.server,
      },
      reference: `https://urlscan.io/result/${uuid}/`,
    };
  } catch (err) {
    return {
      provider: 'urlscan' as any,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      summary: null,
    };
  }
}

export function startCacheCleanupTask(): void {
  const cleanupInterval = 3600 * 1000;

  setInterval(() => {
    try {
      cleanExpiredCache(CACHE_TTL_MS);
      console.log('[enrichCache] expired cache entries cleaned');
    } catch (err) {
      console.error(`[enrichCache] cleanup failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }, cleanupInterval);
}
