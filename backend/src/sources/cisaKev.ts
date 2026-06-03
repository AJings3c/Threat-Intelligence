import type { ThreatIndicator, FetchResult } from '../types.js';
import { fetchWithTimeout, errorMessage } from '../util.js';

const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

interface KevVuln {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  knownRansomwareCampaignUse?: string;
  dueDate?: string;
}

interface KevResponse {
  vulnerabilities: KevVuln[];
}

export async function fetchCisaKev(limit = 400): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  try {
    const res = await fetchWithTimeout(KEV_URL);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as KevResponse;

    // Most-recently-added first.
    const sorted = [...data.vulnerabilities].sort((a, b) =>
      (b.dateAdded ?? '').localeCompare(a.dateAdded ?? ''),
    );

    const items: ThreatIndicator[] = sorted.slice(0, limit).map((v) => {
      const ransomware = (v.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known';
      return {
        id: `kev:${v.cveID}`,
        source: 'cisa_kev',
        type: 'exploited_vuln',
        indicator: v.cveID,
        indicatorType: 'cve',
        severity: ransomware ? 'critical' : 'high',
        title: v.vulnerabilityName,
        description: v.shortDescription,
        tags: [
          v.vendorProject,
          v.product,
          ...(ransomware ? ['ransomware'] : []),
        ].filter(Boolean),
        reference: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
        firstSeen: v.dateAdded ? new Date(v.dateAdded).toISOString() : undefined,
      };
    });

    return { items, fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
