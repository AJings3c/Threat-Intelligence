import type { Severity } from '../types.js';

export interface AlertItem {
  id: string;
  sourceLabel: string;
  severity: Severity;
  title: string;
  indicator: string;
  reference?: string;
  country?: string;
}

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🟢',
};

export interface DigestContent {
  title: string;
  /** Markdown body shared by DingTalk markdown and Telegram (Markdown parse mode). */
  markdown: string;
  /** Plain-text fallback (used for DingTalk text + logging). */
  text: string;
}

function escapeMd(value: string): string {
  // Conservative escaping that is safe for both DingTalk and Telegram Markdown.
  return value.replace(/([_*[\]()`])/g, '\\$1');
}

export function buildDigest(items: AlertItem[], generatedAt = new Date()): DigestContent {
  const ts = generatedAt.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  const title = `Threat Intel Alert · ${items.length} new indicator(s)`;

  const mdLines: string[] = [`#### 🛰️ ${title}`, `> ${ts}`, ''];
  const txtLines: string[] = [`${title} (${ts})`, ''];

  items.forEach((item, idx) => {
    const emoji = SEVERITY_EMOJI[item.severity];
    const n = idx + 1;
    const loc = item.country ? ` · ${item.country}` : '';
    const head = `${emoji} **[${item.severity.toUpperCase()}]** ${escapeMd(item.title)}`;
    const body = `\`${escapeMd(item.indicator)}\` — ${item.sourceLabel}${loc}`;
    if (item.reference) {
      mdLines.push(`${n}. ${head}`, `   ${body} · [details](${item.reference})`, '');
    } else {
      mdLines.push(`${n}. ${head}`, `   ${body}`, '');
    }
    txtLines.push(
      `${n}. [${item.severity.toUpperCase()}] ${item.title} | ${item.indicator} | ${item.sourceLabel}${loc}${
        item.reference ? ` | ${item.reference}` : ''
      }`,
    );
  });

  return { title, markdown: mdLines.join('\n'), text: txtLines.join('\n') };
}

// A digest describing a source health transition (feed went down / recovered).
export function buildSourceAlert(
  kind: 'down' | 'recovered',
  source: { label: string; lastError: string | null; count: number },
  generatedAt = new Date(),
): DigestContent {
  const ts = generatedAt.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  if (kind === 'down') {
    const title = `Source health · ${source.label} is failing`;
    const reason = source.lastError ?? 'unknown error';
    return {
      title,
      markdown: `#### ⚠️ ${title}\n> ${ts}\n\nLast error: \`${escapeMd(reason)}\`\nServing ${source.count} cached indicator(s).`,
      text: `${title} (${ts})\nLast error: ${reason}\nServing ${source.count} cached indicator(s).`,
    };
  }
  const title = `Source health · ${source.label} recovered`;
  return {
    title,
    markdown: `#### ✅ ${title}\n> ${ts}\n\nNow serving ${source.count} indicator(s).`,
    text: `${title} (${ts})\nNow serving ${source.count} indicator(s).`,
  };
}
