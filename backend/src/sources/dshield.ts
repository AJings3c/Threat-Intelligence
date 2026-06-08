import type { FetchResult, Severity, ThreatIndicator } from '../types.js';
import { fetchWithTimeout, errorMessage } from '../util.js';

const DSHIELD_BLOCK_URL = 'https://isc.sans.edu/block.txt';
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function severityFromAttacks(attacks: number): Severity {
  if (attacks >= 1000) return 'critical';
  if (attacks >= 250) return 'high';
  if (attacks >= 50) return 'medium';
  return 'low';
}

export function parseDShieldBlockFeed(text: string, limit = 200): ThreatIndicator[] {
  const seen = new Set<string>();
  const items: ThreatIndicator[] = [];

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const [start, , bitsRaw, attacksRaw, networkName, country, abuseContact] = line.split(/\t+/);
    const bits = Number(bitsRaw);
    const attacks = Number(attacksRaw);
    if (!IPV4_RE.test(start) || !Number.isInteger(bits) || bits < 0 || bits > 32) continue;
    if (!Number.isFinite(attacks)) continue;

    const cidr = `${start}/${bits}`;
    if (seen.has(cidr)) continue;
    seen.add(cidr);
    const cleanNetwork = networkName && networkName !== '-' ? networkName : undefined;
    const cleanCountry = country && country !== '-' ? country : undefined;
    const cleanContact =
      abuseContact && abuseContact !== '-' && abuseContact !== 'None' ? abuseContact : undefined;

    items.push({
      id: `dshield:${cidr}`,
      source: 'dshield',
      type: 'scanner_network',
      indicator: cidr,
      indicatorType: 'cidr',
      severity: severityFromAttacks(attacks),
      title: 'DShield top attacking subnet',
      description: [
        `Attacks: ${attacks}`,
        cleanNetwork ? `Network: ${cleanNetwork}` : null,
        cleanContact ? `Abuse: ${cleanContact}` : null,
      ]
        .filter(Boolean)
        .join(' · '),
      country: cleanCountry,
      tags: ['dshield', 'scanner', `attacks:${attacks}`, cleanNetwork, cleanCountry].filter(
        (tag): tag is string => Boolean(tag),
      ),
      reference: 'https://isc.sans.edu/block.txt',
    });
    if (items.length >= limit) break;
  }

  return items;
}

export async function fetchDShield(limit = 200): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  try {
    const res = await fetchWithTimeout(
      DSHIELD_BLOCK_URL,
      { headers: { Accept: 'text/plain' } },
      25_000,
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    return { items: parseDShieldBlockFeed(text, limit), fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
