import type { Severity, ThreatSource } from '../types.js';

export type NotifyChannel = 'dingtalk' | 'telegram' | 'slack' | 'webhook';

export interface NotifyConfig {
  enabled: boolean;
  intervalMs: number;
  minSeverity: Severity;
  sources: ThreatSource[] | null;
  maxItems: number;
  // Upper bound on the de-dup "seen" set so a long-running process can't grow unbounded.
  seenMax: number;
  dingtalk: { webhook: string; secret: string | null } | null;
  telegram: { botToken: string; chatId: string } | null;
  slack: { webhook: string } | null;
  webhook: { url: string } | null;
}

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function severityRank(sev: Severity): number {
  return SEVERITY_RANK[sev];
}

function parseSeverity(value: string | undefined): Severity {
  const v = (value ?? '').toLowerCase();
  if (v === 'low' || v === 'medium' || v === 'high' || v === 'critical') return v;
  return 'critical';
}

function parseSources(value: string | undefined): ThreatSource[] | null {
  if (!value) return null;
  const valid: ThreatSource[] = ['cisa_kev', 'feodo', 'urlhaus', 'nvd'];
  const parsed = value
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s): s is ThreatSource => (valid as string[]).includes(s));
  return parsed.length > 0 ? parsed : null;
}

// DingTalk accepts either a full webhook URL or just the access_token.
function normalizeDingtalkWebhook(value: string): string {
  if (value.startsWith('http://') || value.startsWith('https://')) return value;
  return `https://oapi.dingtalk.com/robot/send?access_token=${value}`;
}

export function loadNotifyConfig(env: NodeJS.ProcessEnv = process.env): NotifyConfig {
  const dingtalkRaw = env.DINGTALK_WEBHOOK?.trim();
  const telegramToken = env.TELEGRAM_BOT_TOKEN?.trim();
  const telegramChat = env.TELEGRAM_CHAT_ID?.trim();

  const dingtalk = dingtalkRaw
    ? { webhook: normalizeDingtalkWebhook(dingtalkRaw), secret: env.DINGTALK_SECRET?.trim() || null }
    : null;
  const telegram =
    telegramToken && telegramChat ? { botToken: telegramToken, chatId: telegramChat } : null;

  const slackRaw = env.SLACK_WEBHOOK?.trim();
  const slack = slackRaw ? { webhook: slackRaw } : null;
  const webhookRaw = env.WEBHOOK_URL?.trim();
  const webhook = webhookRaw ? { url: webhookRaw } : null;

  // The feature is "on" only when explicitly enabled AND at least one channel is configured.
  const flagEnabled = (env.NOTIFY_ENABLED ?? '').toLowerCase() === 'true';

  return {
    enabled: flagEnabled && Boolean(dingtalk || telegram || slack || webhook),
    intervalMs: Number(env.NOTIFY_INTERVAL_MS ?? 60 * 60 * 1000),
    minSeverity: parseSeverity(env.NOTIFY_MIN_SEVERITY),
    sources: parseSources(env.NOTIFY_SOURCES),
    maxItems: Number(env.NOTIFY_MAX_ITEMS ?? 10),
    seenMax: Math.max(1000, Number(env.NOTIFY_SEEN_MAX ?? 50_000)),
    dingtalk,
    telegram,
    slack,
    webhook,
  };
}
