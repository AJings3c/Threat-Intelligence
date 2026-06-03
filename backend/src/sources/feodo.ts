import type { ThreatIndicator, FetchResult } from '../types.js';
import { fetchWithTimeout, errorMessage } from '../util.js';

const FEODO_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';

interface FeodoEntry {
  ip_address: string;
  port?: number;
  status?: string;
  hostname?: string | null;
  as_number?: number;
  as_name?: string;
  country?: string;
  first_seen?: string;
  last_online?: string;
  malware?: string;
}

export async function fetchFeodo(limit = 1000): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  try {
    const res = await fetchWithTimeout(FEODO_URL);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as FeodoEntry[];

    const items: ThreatIndicator[] = data.slice(0, limit).map((e) => ({
      id: `feodo:${e.ip_address}:${e.port ?? 0}`,
      source: 'feodo',
      type: 'c2_server',
      indicator: e.ip_address,
      indicatorType: 'ip',
      severity: 'high',
      title: e.malware ? `${e.malware} C2 server` : 'Botnet C2 server',
      description: [
        e.malware ? `Malware: ${e.malware}` : null,
        e.port ? `Port: ${e.port}` : null,
        e.as_name ? `ASN: ${e.as_name}` : null,
      ]
        .filter(Boolean)
        .join(' · '),
      malwareFamily: e.malware,
      country: e.country,
      tags: [e.malware, e.status, e.as_name].filter((t): t is string => Boolean(t)),
      reference: 'https://feodotracker.abuse.ch/browse/',
      firstSeen: e.first_seen ? new Date(e.first_seen).toISOString() : undefined,
      lastSeen: e.last_online ? new Date(e.last_online).toISOString() : undefined,
    }));

    return { items, fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
