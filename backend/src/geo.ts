import { fetchWithTimeout, errorMessage } from './util.js';

export interface GeoInfo {
  country?: string;
  countryCode?: string;
  lat?: number;
  lon?: number;
}

// Persistent in-memory cache so we don't re-query the same IP.
const geoCache = new Map<string, GeoInfo>();

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

export function isIpv4(value: string): boolean {
  return IPV4_RE.test(value);
}

// ip-api.com free batch endpoint: up to 100 IPs/request, ~15 requests/min.
// We resolve a bounded number of uncached IPs per refresh to stay well under limits.
const BATCH_SIZE = 100;
const MAX_BATCHES = 3;

// When ip-api rate-limits us (HTTP 429), it returns an X-Ttl header (seconds until
// the window resets). We back off until then instead of hammering the endpoint.
let rateLimitedUntil = 0;

export function geoRateLimitedUntil(): number {
  return rateLimitedUntil;
}

interface IpApiEntry {
  query: string;
  status: string;
  country?: string;
  countryCode?: string;
  lat?: number;
  lon?: number;
}

export async function geolocate(ips: string[]): Promise<Map<string, GeoInfo>> {
  const result = new Map<string, GeoInfo>();
  const unique = Array.from(new Set(ips.filter(isIpv4)));
  const uncached: string[] = [];

  for (const ip of unique) {
    const cached = geoCache.get(ip);
    if (cached) {
      result.set(ip, cached);
    } else {
      uncached.push(ip);
    }
  }

  // Respect an active rate-limit backoff window: serve only cached results.
  if (Date.now() < rateLimitedUntil) return result;

  const toQuery = uncached.slice(0, BATCH_SIZE * MAX_BATCHES);
  for (let i = 0; i < toQuery.length; i += BATCH_SIZE) {
    const batch = toQuery.slice(i, i + BATCH_SIZE);
    try {
      const res = await fetchWithTimeout(
        'http://ip-api.com/batch?fields=query,status,country,countryCode,lat,lon',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(batch),
        },
        20_000,
        { retries: 0 },
      );
      if (res.status === 429) {
        // Honor ip-api's reset hint (seconds); default to 60s if absent.
        const ttl = Number(res.headers.get('X-Ttl') ?? '60');
        rateLimitedUntil = Date.now() + (Number.isFinite(ttl) ? ttl : 60) * 1000;
        console.warn(`[geo] rate-limited; backing off ${ttl}s`);
        break;
      }
      if (!res.ok) break;
      const data = (await res.json()) as IpApiEntry[];
      for (const entry of data) {
        if (entry.status !== 'success') continue;
        const info: GeoInfo = {
          country: entry.country,
          countryCode: entry.countryCode,
          lat: entry.lat,
          lon: entry.lon,
        };
        geoCache.set(entry.query, info);
        result.set(entry.query, info);
      }
    } catch (err) {
      // Best-effort geolocation: log and continue with whatever we have.
      console.warn(`[geo] batch failed: ${errorMessage(err)}`);
      break;
    }
  }

  return result;
}
