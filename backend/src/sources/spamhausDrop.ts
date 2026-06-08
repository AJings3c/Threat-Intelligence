import type { FetchResult, ThreatIndicator } from '../types.js';
import { fetchWithTimeout, errorMessage } from '../util.js';

const SPAMHAUS_DROP_V4_URL = 'https://www.spamhaus.org/drop/drop_v4.json';
const CIDR_RE = /^(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[12][0-9]|3[0-2])$/;

interface SpamhausDropEntry {
  cidr: string;
  sblid?: string;
  rir?: string;
}

export function parseSpamhausDropFeed(text: string, limit = 1000): ThreatIndicator[] {
  const seen = new Set<string>();
  const items: ThreatIndicator[] = [];

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    let entry: SpamhausDropEntry;
    try {
      entry = JSON.parse(line) as SpamhausDropEntry;
    } catch {
      continue;
    }
    const cidr = entry.cidr?.trim();
    if (!cidr || seen.has(cidr) || !CIDR_RE.test(cidr)) continue;
    seen.add(cidr);

    items.push({
      id: `spamhaus_drop:${cidr}`,
      source: 'spamhaus_drop',
      type: 'malicious_network',
      indicator: cidr,
      indicatorType: 'cidr',
      severity: 'high',
      title: 'Spamhaus DROP network',
      description: [
        entry.sblid ? `SBL: ${entry.sblid}` : null,
        entry.rir ? `RIR: ${entry.rir}` : null,
      ]
        .filter(Boolean)
        .join(' · '),
      tags: ['drop', 'spamhaus', entry.sblid, entry.rir].filter((tag): tag is string =>
        Boolean(tag),
      ),
      reference: entry.sblid ? `https://check.spamhaus.org/listed/?searchterm=${entry.sblid}` : 'https://www.spamhaus.org/drop/',
    });
    if (items.length >= limit) break;
  }

  return items;
}

export async function fetchSpamhausDrop(limit = 1000): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  try {
    const res = await fetchWithTimeout(SPAMHAUS_DROP_V4_URL, {}, 25_000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    return { items: parseSpamhausDropFeed(text, limit), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
