import { fetchWithTimeout } from '../util.js';

const EPSS_URL = 'https://api.first.org/data/v1/epss';
const CHUNK_SIZE = 80;

interface EpssApiItem {
  cve: string;
  epss: string;
  percentile: string;
  date: string;
}

interface EpssApiResponse {
  status?: string;
  data?: EpssApiItem[];
}

export interface EpssScore {
  epssScore: number;
  epssPercentile: number;
  epssDate: string;
}

function chunks<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

export async function fetchEpssScores(cves: string[]): Promise<Map<string, EpssScore>> {
  const unique = Array.from(new Set(cves.map((cve) => cve.trim().toUpperCase()).filter(Boolean)));
  const scores = new Map<string, EpssScore>();
  if (unique.length === 0) return scores;

  for (const batch of chunks(unique, CHUNK_SIZE)) {
    const params = new URLSearchParams({ cve: batch.join(',') });
    const res = await fetchWithTimeout(`${EPSS_URL}?${params.toString()}`, {}, 20_000);
    if (!res.ok) throw new Error(`EPSS HTTP ${res.status}`);
    const data = (await res.json()) as EpssApiResponse;
    for (const item of data.data ?? []) {
      const epssScore = Number(item.epss);
      const epssPercentile = Number(item.percentile);
      if (!Number.isFinite(epssScore) || !Number.isFinite(epssPercentile)) continue;
      scores.set(item.cve.toUpperCase(), {
        epssScore,
        epssPercentile,
        epssDate: item.date,
      });
    }
  }

  return scores;
}
