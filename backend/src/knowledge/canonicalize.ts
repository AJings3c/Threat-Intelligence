import type { KnowledgeExternalReference } from './types.js';

const UNSAFE_UNICODE = /[\p{Cc}\p{Cf}\p{Cs}]/gu;
const WHITESPACE = /\s+/gu;

/**
 * Produces a safe display value without discarding meaningful punctuation.
 * Keeping punctuation makes alias matching conservative and avoids accidental
 * merges such as `APT-29` and `APT29`.
 */
export function normalizeKnowledgeName(value: string): string {
  return value.normalize('NFKC').replace(UNSAFE_UNICODE, ' ').replace(WHITESPACE, ' ').trim();
}

/** Stable, locale-independent key used for exact name and alias matching. */
export function canonicalizeKnowledgeName(value: string): string {
  return normalizeKnowledgeName(value).toLowerCase();
}

/**
 * Cleans and deduplicates aliases while preserving the first display spelling.
 * The primary name is omitted because it is already searchable on the entity.
 */
export function normalizeKnowledgeAliases(primaryName: string, aliases: readonly string[]): string[] {
  const primaryKey = canonicalizeKnowledgeName(primaryName);
  const seen = new Set<string>();
  if (primaryKey) seen.add(primaryKey);

  const normalized: string[] = [];
  for (const alias of aliases) {
    const display = normalizeKnowledgeName(alias);
    const key = canonicalizeKnowledgeName(display);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    normalized.push(display);
  }
  return normalized;
}

function canonicalizeHttpUrl(value: string): string | null {
  try {
    const url = new URL(normalizeKnowledgeName(value));
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    url.username = '';
    url.password = '';
    url.hash = '';
    url.searchParams.sort();
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * Builds a collision-resistant key from a structured external reference.
 * External IDs take precedence over URLs because they are usually the most
 * stable identifier (for example MITRE `G0016` or `CVE-2025-0001`).
 */
export function externalReferenceKey(reference: KnowledgeExternalReference): string | null {
  const sourceName = canonicalizeKnowledgeName(reference.sourceName);
  if (!sourceName) return null;

  const externalId = reference.externalId ? canonicalizeKnowledgeName(reference.externalId) : '';
  if (externalId) {
    return `external-id:${encodeURIComponent(sourceName)}:${encodeURIComponent(externalId)}`;
  }

  const url = reference.url ? canonicalizeHttpUrl(reference.url) : null;
  if (!url) return null;
  return `external-url:${encodeURIComponent(sourceName)}:${encodeURIComponent(url)}`;
}
