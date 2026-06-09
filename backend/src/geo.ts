import fs from 'node:fs';
import { createRequire } from 'node:module';
import { fetchWithTimeout, errorMessage } from './util.js';
import { loadGeoCache, saveGeo } from './persist.js';

export interface GeoInfo {
  country?: string;
  countryCode?: string;
  lat?: number;
  lon?: number;
}

// In-memory cache so we don't re-query the same IP. Hydrated lazily from persistence
// (if enabled) on first use so a restart doesn't re-query everything.
const geoCache = new Map<string, GeoInfo>();
let hydrated = false;

function ensureHydrated(): void {
  if (hydrated) return;
  hydrated = true;
  for (const [ip, info] of loadGeoCache()) geoCache.set(ip, info);
}

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

export function isIpv4(value: string): boolean {
  if (!IPV4_RE.test(value)) return false;
  return value.split('.').every((part) => {
    const n = Number(part);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

// ip-api.com free batch endpoint: up to 100 IPs/request, ~15 requests/min.
// We resolve a bounded number of uncached IPs per refresh to stay well under limits.
// A persistent cache means coverage accumulates across refreshes.
const BATCH_SIZE = 100;
const MAX_BATCHES = 5;

// --- Optional offline GeoLite2 lookup (no rate limit, no plaintext HTTP) ---
// Enabled when GEOLITE2_DB points to a MaxMind .mmdb file. Falls back to ip-api otherwise.
interface MmdbCity {
  country?: { iso_code?: string; names?: { en?: string } };
  location?: { latitude?: number; longitude?: number };
}
interface MmdbReader {
  get(ip: string): MmdbCity | null;
}

let offlineReady = false;
let offlineReader: MmdbReader | null = null;

async function getOfflineReader(): Promise<MmdbReader | null> {
  if (offlineReady) return offlineReader;
  offlineReady = true;
  const dbPath = process.env.GEOLITE2_DB?.trim();
  if (!dbPath) return null;
  try {
    if (!fs.existsSync(dbPath)) {
      console.warn(`[geo] GEOLITE2_DB not found at ${dbPath}; using online lookup`);
      return null;
    }
    const require = createRequire(import.meta.url);
    const maxmind = require('maxmind') as { open(path: string): Promise<unknown> };
    offlineReader = (await maxmind.open(dbPath)) as MmdbReader;
    console.log(`[geo] offline GeoLite2 lookup enabled (${dbPath})`);
  } catch (err) {
    console.warn(`[geo] failed to open GEOLITE2_DB: ${errorMessage(err)}`);
    offlineReader = null;
  }
  return offlineReader;
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
  ensureHydrated();
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

  // Prefer offline GeoLite2 when configured: no rate limit, resolves every uncached IP.
  const reader = await getOfflineReader();
  if (reader) {
    for (const ip of uncached) {
      let r: MmdbCity | null = null;
      try {
        r = reader.get(ip);
      } catch {
        r = null;
      }
      if (!r) continue;
      const info: GeoInfo = {
        country: r.country?.names?.en,
        countryCode: r.country?.iso_code,
        lat: r.location?.latitude,
        lon: r.location?.longitude,
      };
      geoCache.set(ip, info);
      saveGeo(ip, info);
      result.set(ip, info);
    }
    return result;
  }

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
      );
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
        saveGeo(entry.query, info);
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
