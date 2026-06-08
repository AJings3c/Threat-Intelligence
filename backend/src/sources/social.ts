import type { Severity } from '../types.js';

const KEYWORD_WEIGHTS: Record<string, number> = {
  '0day': 8,
  'zero-day': 8,
  exploit: 7,
  exploited: 7,
  rce: 7,
  cve: 6,
  poc: 5,
  ransomware: 5,
  apt: 4,
  ioc: 4,
  breach: 4,
  kev: 4,
  phishing: 3,
  malware: 3,
  vulnerability: 3,
};

export function headline(text: string, length = 96): string {
  const compact = text.replace(/\s+/g, ' ').trim();
  return compact.length <= length ? compact : `${compact.slice(0, length - 1)}...`;
}

export function parseIsoTime(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const time = Date.parse(value);
  return Number.isNaN(time) ? undefined : new Date(time).toISOString();
}

export function scoreSocialText(text: string, bonus = 0): { severity: Severity; tags: string[] } {
  const lower = text.toLowerCase();
  let score = bonus;
  const tags: string[] = ['social'];
  for (const [keyword, weight] of Object.entries(KEYWORD_WEIGHTS)) {
    if (!lower.includes(keyword)) continue;
    score += weight;
    tags.push(keyword);
  }

  const uniqueTags = Array.from(new Set(tags));
  if (score >= 22) return { severity: 'critical', tags: uniqueTags };
  if (score >= 12) return { severity: 'high', tags: uniqueTags };
  if (score >= 5) return { severity: 'medium', tags: uniqueTags };
  return { severity: 'low', tags: uniqueTags };
}

export function clampLimit(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}
