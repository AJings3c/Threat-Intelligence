import crypto from 'node:crypto';
import type { FetchResult, ThreatIndicator } from '../types.js';
import { errorMessage, fetchWithTimeout } from '../util.js';

const PHISHTANK_FEED_URL = 'https://data.phishtank.com/data/{appKey}/online-valid.json';

interface PhishTankEntry {
  phish_id?: string | number;
  url?: string;
  phish_detail_url?: string;
  submission_time?: string;
  verified?: string;
  verification_time?: string;
  online?: string;
  target?: string;
}

function shortHash(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
}

function parseTime(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value.replace(' ', 'T').replace(/Z?$/, 'Z'));
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function feedUrl(appKey: string): string {
  const configured = process.env.PHISHTANK_FEED_URL?.trim();
  if (configured) return configured.replace('{appKey}', encodeURIComponent(appKey));
  return PHISHTANK_FEED_URL.replace('{appKey}', encodeURIComponent(appKey));
}

export function parsePhishTankFeed(
  data: unknown,
  fetchedAt = Date.now(),
  limit = 1000,
): ThreatIndicator[] {
  if (!Array.isArray(data)) return [];
  const seen = new Set<string>();
  const fetchedIso = new Date(fetchedAt).toISOString();
  const items: ThreatIndicator[] = [];

  for (const raw of data) {
    const entry = raw as PhishTankEntry;
    const url = entry.url?.trim();
    if (!url || seen.has(url)) continue;
    try {
      new URL(url);
    } catch {
      continue;
    }
    const verified = (entry.verified ?? '').toLowerCase() === 'yes';
    const online = (entry.online ?? '').toLowerCase() === 'yes';
    if (!verified || !online) continue;
    seen.add(url);

    const id = entry.phish_id ? String(entry.phish_id) : shortHash(url);
    const target = entry.target?.trim();
    items.push({
      id: `phishtank:${id}`,
      source: 'phishtank',
      type: 'phishing_url',
      indicator: url,
      indicatorType: 'url',
      severity: 'high',
      title: target ? `Phishing URL targeting ${target}` : 'Phishing URL',
      description: 'Verified online phishing URL reported by PhishTank',
      tags: ['phishing', 'phishtank', target].filter((tag): tag is string => Boolean(tag)),
      reference: entry.phish_detail_url || 'https://phishtank.org/',
      firstSeen: parseTime(entry.submission_time),
      lastSeen: parseTime(entry.verification_time) ?? fetchedIso,
    });
    if (items.length >= limit) break;
  }

  return items;
}

export async function fetchPhishTank(limit = 1000): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  const appKey = process.env.PHISHTANK_APP_KEY?.trim();
  if (!appKey) return { items: [], fetchedAt, error: null };

  try {
    const res = await fetchWithTimeout(
      feedUrl(appKey),
      { headers: { Accept: 'application/json' } },
      60_000,
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as unknown;
    return { items: parsePhishTankFeed(data, fetchedAt, limit), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
