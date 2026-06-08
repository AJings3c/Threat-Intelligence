import type { CveItem, FetchResult } from '../types.js';
import { fetchWithTimeout, errorMessage, cvssToSeverity } from '../util.js';
import { fetchEpssScores } from './epss.js';
import { sourceProfile } from '../sourceProfiles.js';

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

interface CvssData {
  baseScore?: number;
  baseSeverity?: string;
  vectorString?: string;
}

interface CvssMetric {
  cvssData?: CvssData;
}

interface NvdCve {
  id: string;
  published?: string;
  lastModified?: string;
  descriptions?: { lang: string; value: string }[];
  references?: { url: string }[];
  metrics?: {
    cvssMetricV31?: CvssMetric[];
    cvssMetricV30?: CvssMetric[];
    cvssMetricV2?: CvssMetric[];
  };
}

interface NvdResponse {
  vulnerabilities?: { cve: NvdCve }[];
}

function pickCvss(cve: NvdCve): CvssData | undefined {
  const m = cve.metrics;
  if (!m) return undefined;
  return (
    m.cvssMetricV31?.[0]?.cvssData ??
    m.cvssMetricV30?.[0]?.cvssData ??
    m.cvssMetricV2?.[0]?.cvssData
  );
}

function isoDate(d: Date): string {
  // NVD expects e.g. 2026-06-01T00:00:00.000
  return d.toISOString().replace('Z', '');
}

export async function fetchNvd(limit = 60, days = 14): Promise<FetchResult<CveItem>> {
  const fetchedAt = Date.now();
  try {
    const end = new Date();
    const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);
    const params = new URLSearchParams({
      pubStartDate: isoDate(start),
      pubEndDate: isoDate(end),
      resultsPerPage: String(Math.min(limit, 200)),
    });
    // An NVD API key raises the rate limit from 5 to 50 requests / 30s.
    const apiKey = process.env.NVD_API_KEY?.trim();
    const res = await fetchWithTimeout(
      `${NVD_URL}?${params.toString()}`,
      apiKey ? { headers: { apiKey } } : {},
      30_000,
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as NvdResponse;
    const vulns = data.vulnerabilities ?? [];

    const items: CveItem[] = vulns.map(({ cve }) => {
      const cvss = pickCvss(cve);
      const score = cvss?.baseScore;
      const profile = sourceProfile('nvd');
      const description =
        cve.descriptions?.find((d) => d.lang === 'en')?.value ??
        cve.descriptions?.[0]?.value ??
        'No description available.';
      return {
        id: cve.id,
        source: 'nvd',
        title: cve.id,
        description,
        severity: cvssToSeverity(score),
        cvssScore: score,
        cvssVector: cvss?.vectorString,
        sourceReliability: profile.reliability,
        tlp: profile.tlp,
        published: cve.published,
        lastModified: cve.lastModified,
        reference: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        knownExploited: false,
      };
    });

    // Newest first.
    items.sort((a, b) => (b.published ?? '').localeCompare(a.published ?? ''));

    try {
      const epss = await fetchEpssScores(items.map((item) => item.id));
      for (const item of items) {
        const score = epss.get(item.id.toUpperCase());
        if (!score) continue;
        item.epssScore = score.epssScore;
        item.epssPercentile = score.epssPercentile;
        item.epssDate = score.epssDate;
      }
    } catch {
      // EPSS is enrichment only; NVD CVEs should still be served if it is down.
    }

    return { items: items.slice(0, limit), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
