import type { Language } from './types.js';

export function parseLanguage(value: unknown): Language {
  return value === 'zh' ? 'zh' : 'en';
}
