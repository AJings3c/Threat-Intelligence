import { getEnrichmentCache, setEnrichmentCache, cleanExpiredCache } from './persist.js';
import { enrichCensys, enrichGreyNoise, enrichShodan, enrichURLScan, enrichVirusTotal } from './enrich.js';
import type { EnrichmentProvider, EnrichmentResult, EnrichmentResponse, IndicatorType } from './types.js';
import { ProviderCircuitBreaker } from './providerCircuit.js';

const CACHE_TTL_MS = 3600 * 1000; // 1 hour
const ENRICHMENT_PROVIDERS: EnrichmentProvider[] = ['virustotal', 'shodan', 'censys', 'greynoise', 'urlscan'];
const circuit = new ProviderCircuitBreaker(
  Math.max(1, Number(process.env.ENRICH_CIRCUIT_FAILURE_THRESHOLD ?? 3)),
  Math.max(1000, Number(process.env.ENRICH_CIRCUIT_COOLDOWN_MS ?? 60_000)),
);

async function callProvider(
  provider: EnrichmentProvider,
  indicator: string,
  indicatorType: IndicatorType,
): Promise<EnrichmentResult | null> {
  switch (provider) {
    case 'virustotal':
      return enrichVirusTotal(indicator, indicatorType);
    case 'shodan':
      return enrichShodan(indicator, indicatorType);
    case 'censys':
      return enrichCensys(indicator, indicatorType);
    case 'greynoise':
      return enrichGreyNoise(indicator, indicatorType);
    case 'urlscan':
      return enrichURLScan(indicator, indicatorType);
  }
}

async function enrichOne(
  provider: EnrichmentProvider,
  indicator: string,
  indicatorType: IndicatorType,
): Promise<EnrichmentResult | null> {
  const cached = getEnrichmentCache(indicator, provider);
  if (cached) {
    const row = cached as { result: string };
    try {
      return JSON.parse(row.result) as EnrichmentResult;
    } catch {
      // Invalid cache: fetch a fresh result.
    }
  }

  const openUntil = circuit.openUntil(provider);
  if (openUntil) {
    return {
      provider,
      ok: false,
      error: `provider circuit open until ${new Date(openUntil).toISOString()}`,
      summary: null,
    };
  }
  const result = await callProvider(provider, indicator, indicatorType);
  if (!result) return null;
  circuit.record(provider, result.ok);
  if (result.ok) setEnrichmentCache(indicator, provider, JSON.stringify(result), Date.now());
  return result;
}

export async function enrichWithCache(
  indicator: string,
  indicatorType: IndicatorType,
): Promise<EnrichmentResponse> {
  const results = (await Promise.all(
    ENRICHMENT_PROVIDERS.map((provider) => enrichOne(provider, indicator, indicatorType)),
  )).filter((result): result is EnrichmentResult => result !== null);

  return {
    indicator,
    indicatorType,
    results,
  };
}

export function startCacheCleanupTask(): () => void {
  const cleanupInterval = 3600 * 1000;

  const timer = setInterval(() => {
    try {
      cleanExpiredCache(CACHE_TTL_MS);
      console.log('[enrichCache] expired cache entries cleaned');
    } catch (err) {
      console.error(`[enrichCache] cleanup failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }, cleanupInterval);
  return () => clearInterval(timer);
}
