import crypto from 'node:crypto';
import type { ThreatIndicator, FetchResult } from '../types.js';
import { fetchWithTimeout, errorMessage } from '../util.js';

const OPENPHISH_URL = 'https://openphish.com/feed.txt';

function shortHash(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
}

export function parseOpenPhishFeed(text: string, fetchedAt = Date.now(), limit = 1000): ThreatIndicator[] {
  const seen = new Set<string>();
  const items: ThreatIndicator[] = [];
  const seenIso = new Date(fetchedAt).toISOString();

  for (const raw of text.split(/\r?\n/)) {
    const url = raw.trim();
    if (!url || url.startsWith('#') || seen.has(url)) continue;
    try {
      new URL(url);
    } catch {
      continue;
    }
    seen.add(url);
    items.push({
      id: `openphish:${shortHash(url)}`,
      source: 'openphish',
      type: 'phishing_url',
      indicator: url,
      indicatorType: 'url',
      severity: 'high',
      title: 'Phishing URL',
      description: 'Phishing URL reported by OpenPhish Community Feed',
      tags: ['phishing', 'openphish'],
      reference: 'https://openphish.com/',
      lastSeen: seenIso,
    });
    if (items.length >= limit) break;
  }

  return items;
}

export async function fetchOpenPhish(limit = 1000): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  try {
    const res = await fetchWithTimeout(
      OPENPHISH_URL,
      { headers: { Accept: 'text/plain' } },
      25_000,
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    return { items: parseOpenPhishFeed(text, fetchedAt, limit), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
