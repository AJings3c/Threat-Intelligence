import type { ThreatIndicator, FetchResult } from '../types.js';
import { fetchWithTimeout, errorMessage } from '../util.js';

const URLHAUS_URL = 'https://urlhaus.abuse.ch/downloads/json_recent/';

interface UrlhausEntry {
  url: string;
  url_status?: string;
  host?: string;
  dateadded?: string;
  last_online?: string;
  threat?: string;
  tags?: string[] | null;
  urlhaus_link?: string;
  reporter?: string;
}

type UrlhausResponse = Record<string, UrlhausEntry[]>;

export async function fetchUrlhaus(limit = 1500): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  try {
    const res = await fetchWithTimeout(URLHAUS_URL);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as UrlhausResponse;

    const items: ThreatIndicator[] = [];
    for (const id of Object.keys(data)) {
      const entry = data[id]?.[0];
      if (!entry) continue;
      const online = (entry.url_status ?? '').toLowerCase() === 'online';
      items.push({
        id: `urlhaus:${id}`,
        source: 'urlhaus',
        type: 'malicious_url',
        indicator: entry.url,
        indicatorType: 'url',
        severity: online ? 'high' : 'medium',
        title: entry.threat ? entry.threat.replace(/_/g, ' ') : 'Malicious URL',
        description: `${online ? 'Online' : 'Offline'} malware URL reported by ${
          entry.reporter ?? 'unknown'
        }`,
        tags: [entry.threat, entry.url_status, ...(entry.tags ?? [])].filter(
          (t): t is string => Boolean(t),
        ),
        reference: entry.urlhaus_link,
        firstSeen: entry.dateadded
          ? new Date(entry.dateadded.replace(' UTC', 'Z').replace(' ', 'T')).toISOString()
          : undefined,
        lastSeen: entry.last_online
          ? new Date(entry.last_online.replace(' UTC', 'Z').replace(' ', 'T')).toISOString()
          : undefined,
      });
      if (items.length >= limit) break;
    }

    return { items, fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
