import type {
  EnrichmentProvider,
  FetchResult,
  IntegrationKind,
  IntegrationTestResult,
  ThreatIndicator,
  ThreatSource,
} from './types.js';
import { enrichCensys, enrichShodan, enrichVirusTotal, isProviderConfigured, providerRequiredEnv } from './enrich.js';
import { SOURCE_LABELS } from './store.js';
import { isSourceConfigured, sourceRequiredEnv } from './sourceProfiles.js';
import { fetchCisaKev } from './sources/cisaKev.js';
import { fetchFeodo } from './sources/feodo.js';
import { fetchUrlhaus } from './sources/urlhaus.js';
import { fetchNvd } from './sources/nvd.js';
import { fetchXRecentSearch } from './sources/x.js';
import { fetchFacebookPages } from './sources/facebook.js';
import { fetchOpenPhish } from './sources/openphish.js';
import { fetchThreatFox } from './sources/threatfox.js';
import { fetchMalwareBazaar } from './sources/malwarebazaar.js';
import { fetchSpamhausDrop } from './sources/spamhausDrop.js';
import { fetchDShield } from './sources/dshield.js';
import { fetchPhishTank } from './sources/phishtank.js';
import { fetchAbuseIpDb } from './sources/abuseipdb.js';
import { fetchOtx } from './sources/otx.js';
import { fetchTaxiiImport } from './sources/taxiiImport.js';
import { errorMessage } from './util.js';

type SourceFetcher = () => Promise<FetchResult<ThreatIndicator> | FetchResult<unknown>>;

const SOURCE_TESTERS: Record<ThreatSource, SourceFetcher> = {
  cisa_kev: () => fetchCisaKev(),
  feodo: () => fetchFeodo(),
  urlhaus: () => fetchUrlhaus(),
  nvd: () => fetchNvd(5, 7),
  x: () => fetchXRecentSearch(),
  facebook: () => fetchFacebookPages(),
  openphish: () => fetchOpenPhish(),
  threatfox: () => fetchThreatFox(),
  malwarebazaar: () => fetchMalwareBazaar(),
  spamhaus_drop: () => fetchSpamhausDrop(),
  dshield: () => fetchDShield(),
  phishtank: () => fetchPhishTank(20),
  abuseipdb: () => fetchAbuseIpDb(20),
  otx: () => fetchOtx(20),
  taxii_import: () => fetchTaxiiImport(20),
};

function resultBase(
  kind: IntegrationKind,
  id: ThreatSource | EnrichmentProvider,
  label: string,
  configured: boolean,
  requiredEnv: string[],
  started: number,
): Pick<IntegrationTestResult, 'kind' | 'id' | 'label' | 'configured' | 'requiredEnv' | 'testedAt' | 'latencyMs'> {
  return {
    kind,
    id,
    label,
    configured,
    requiredEnv,
    testedAt: new Date().toISOString(),
    latencyMs: Date.now() - started,
  };
}

export async function testThreatSource(source: ThreatSource): Promise<IntegrationTestResult> {
  const started = Date.now();
  const requiredEnv = sourceRequiredEnv(source);
  const configured = isSourceConfigured(source);
  const base = resultBase('source', source, SOURCE_LABELS[source], configured, requiredEnv, started);
  if (!configured) {
    return {
      ...base,
      status: 'missing_config',
      latencyMs: null,
      message: `Missing ${requiredEnv.join(', ')}`,
    };
  }
  try {
    const result = await SOURCE_TESTERS[source]();
    if (result.error) {
      return { ...base, status: 'failed', message: result.error, sampleCount: result.items.length };
    }
    return {
      ...base,
      status: 'ok',
      message: result.items.length > 0 ? 'Connection succeeded and returned sample data' : 'Connection succeeded',
      sampleCount: result.items.length,
    };
  } catch (err) {
    return { ...base, status: 'failed', message: errorMessage(err) };
  }
}

export async function testEnrichmentProvider(provider: EnrichmentProvider): Promise<IntegrationTestResult> {
  const started = Date.now();
  const requiredEnv = providerRequiredEnv(provider);
  const configured = isProviderConfigured(provider);
  const base = resultBase('provider', provider, provider, configured, requiredEnv, started);
  if (!configured) {
    return {
      ...base,
      status: 'missing_config',
      latencyMs: null,
      message: `Missing ${requiredEnv.join(', ')}`,
    };
  }

  const sampleIndicator = provider === 'virustotal' ? 'example.com' : '1.1.1.1';
  const sampleType = provider === 'virustotal' ? 'domain' : 'ip';
  try {
    const result =
      provider === 'virustotal'
        ? await enrichVirusTotal(sampleIndicator, sampleType)
        : provider === 'shodan'
          ? await enrichShodan(sampleIndicator, sampleType)
          : await enrichCensys(sampleIndicator, sampleType);
    if (!result) return { ...base, status: 'unsupported', message: 'Provider is not available for the sample type' };
    if (!result.ok) return { ...base, status: 'failed', message: result.error ?? 'Connection failed' };
    return { ...base, status: 'ok', message: 'Connection succeeded', sampleCount: 1 };
  } catch (err) {
    return { ...base, status: 'failed', message: errorMessage(err) };
  }
}

export async function testIntegration(
  kind: IntegrationKind,
  id: ThreatSource | EnrichmentProvider,
): Promise<IntegrationTestResult> {
  if (kind === 'source') return testThreatSource(id as ThreatSource);
  return testEnrichmentProvider(id as EnrichmentProvider);
}
