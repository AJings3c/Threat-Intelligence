import type { IndicatorType } from './types.js';

export interface ExtractedIoc {
  value: string;
  indicatorType: IndicatorType;
}

function refang(value: string): string {
  return value
    .replace(/\[:\]|\(:\)/g, ':')
    .replace(/\bhxxps:/gi, 'https:')
    .replace(/\bhxxp:/gi, 'http:')
    .replace(/\[(?:\.|dot)\]|\((?:\.|dot)\)/gi, '.');
}

function isIpv4(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

export function extractIocs(input: string, limit = 1000): ExtractedIoc[] {
  const text = refang(input);
  const results: ExtractedIoc[] = [];
  const seen = new Set<string>();
  const add = (value: string, indicatorType: IndicatorType): void => {
    const normalized = indicatorType === 'domain' || indicatorType === 'hash' ? value.toLowerCase() : value;
    const key = `${indicatorType}:${normalized}`;
    if (!seen.has(key) && results.length < limit) {
      seen.add(key);
      results.push({ value: normalized, indicatorType });
    }
  };

  for (const match of text.matchAll(/\b(?:https?):\/\/[^\s<>"']+/gi)) {
    const value = match[0].replace(/[),.;]+$/, '');
    try {
      const url = new URL(value);
      if (url.protocol === 'http:' || url.protocol === 'https:') add(url.toString(), 'url');
    } catch {
      // Skip malformed URL candidates.
    }
  }
  for (const match of text.matchAll(/\bCVE-\d{4}-\d{4,19}\b/gi)) add(match[0].toUpperCase(), 'cve');
  for (const match of text.matchAll(/\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi)) add(match[0], 'hash');
  for (const match of text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
    if (isIpv4(match[0])) add(match[0], 'ip');
  }
  for (const match of text.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi)) {
    const value = match[0].toLowerCase();
    if (!isIpv4(value)) add(value, 'domain');
  }
  return results;
}
