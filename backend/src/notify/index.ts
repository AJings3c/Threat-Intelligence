import type { Severity } from '../types.js';
import { store, SOURCE_LABELS } from '../store.js';
import { loadNotifyConfig, severityRank, type NotifyConfig } from './config.js';
import { collectNewAlerts } from './collect.js';
import { buildDigest, type AlertItem } from './format.js';
import { sendDingtalk } from './dingtalk.js';
import { sendTelegram } from './telegram.js';
import { errorMessage } from '../util.js';

export interface NotifierStatus {
  enabled: boolean;
  channels: { dingtalk: boolean; telegram: boolean };
  minSeverity: Severity;
  intervalMs: number;
  sources: string[] | null;
  maxItems: number;
  seenCount: number;
  lastRunAt: string | null;
  lastSentCount: number;
  lastResult: Record<string, string> | null;
}

class Notifier {
  private config: NotifyConfig = loadNotifyConfig();
  // Track indicator IDs we have already alerted on, so digests only contain new threats.
  private seen = new Set<string>();
  private primed = false;
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastRunAt = 0;
  private lastSentCount = 0;
  private lastResult: Record<string, string> | null = null;

  get isEnabled(): boolean {
    return this.config.enabled;
  }

  // Collect indicators that meet the severity/source filters and have not been alerted yet.
  private collectNew(): AlertItem[] {
    return collectNewAlerts({
      indicators: store.getIndicators(),
      cves: store.getAllCves(),
      seen: this.seen,
      minSeverity: this.config.minSeverity,
      sources: this.config.sources,
    });
  }

  private markSeen(items: AlertItem[]): void {
    for (const item of items) this.seen.add(item.id);
  }

  /** Run one digest cycle. Returns the items that were sent (empty if none/dry). */
  async runOnce(force = false): Promise<AlertItem[]> {
    if (!this.config.enabled && !force) return [];

    const candidates = this.collectNew();

    // First run after boot: prime the baseline without spamming historical data.
    if (!this.primed && !force) {
      this.markSeen(candidates);
      this.primed = true;
      this.lastRunAt = Date.now();
      return [];
    }

    if (candidates.length === 0) {
      this.lastRunAt = Date.now();
      return [];
    }

    const toSend = candidates.slice(0, this.config.maxItems);
    const digest = buildDigest(toSend);
    const result: Record<string, string> = {};

    if (this.config.dingtalk) {
      const r = await sendDingtalk(this.config.dingtalk, digest);
      result.dingtalk = r.ok ? 'ok' : `error: ${r.error}`;
    }
    if (this.config.telegram) {
      const r = await sendTelegram(this.config.telegram, digest);
      result.telegram = r.ok ? 'ok' : `error: ${r.error}`;
    }

    // Mark all candidates seen (not just the truncated batch) so the next digest moves forward.
    this.markSeen(candidates);
    this.primed = true;
    this.lastRunAt = Date.now();
    this.lastSentCount = toSend.length;
    this.lastResult = result;
    return toSend;
  }

  /** Send a digest of the current top threats immediately, ignoring the "seen" set. */
  async sendTest(): Promise<{ sent: number; result: Record<string, string> }> {
    const minRank = severityRank(this.config.minSeverity);
    const allow = this.config.sources;
    const items: AlertItem[] = [];
    for (const t of store.getIndicators()) {
      if (severityRank(t.severity) < minRank) continue;
      if (allow && !allow.includes(t.source)) continue;
      items.push({
        id: t.id,
        sourceLabel: SOURCE_LABELS[t.source],
        severity: t.severity,
        title: t.title ?? t.type,
        indicator: t.indicator,
        reference: t.reference,
        country: t.country,
      });
      if (items.length >= this.config.maxItems) break;
    }
    const digest = buildDigest(
      items.length > 0
        ? items
        : [
            {
              id: 'test',
              sourceLabel: 'threat-intel-platform',
              severity: 'low',
              title: 'Test notification — no threats matched current filters',
              indicator: 'n/a',
            },
          ],
    );
    const result: Record<string, string> = {};
    if (this.config.dingtalk) {
      const r = await sendDingtalk(this.config.dingtalk, digest);
      result.dingtalk = r.ok ? 'ok' : `error: ${r.error}`;
    }
    if (this.config.telegram) {
      const r = await sendTelegram(this.config.telegram, digest);
      result.telegram = r.ok ? 'ok' : `error: ${r.error}`;
    }
    if (!this.config.dingtalk && !this.config.telegram) {
      result.none = 'no channel configured (set DINGTALK_WEBHOOK and/or TELEGRAM_BOT_TOKEN)';
    }
    this.lastResult = result;
    return { sent: items.length, result };
  }

  start(): void {
    if (!this.config.enabled) {
      console.log('[notify] disabled (set NOTIFY_ENABLED=true and configure a channel)');
      return;
    }
    const channels = [
      this.config.dingtalk ? 'dingtalk' : null,
      this.config.telegram ? 'telegram' : null,
    ].filter(Boolean);
    console.log(
      `[notify] enabled · channels=${channels.join(',')} · minSeverity=${this.config.minSeverity} · interval=${this.config.intervalMs}ms`,
    );
    this.timer = setInterval(() => {
      this.runOnce().catch((err) => console.error(`[notify] run failed: ${errorMessage(err)}`));
    }, this.config.intervalMs);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  status(): NotifierStatus {
    return {
      enabled: this.config.enabled,
      channels: { dingtalk: Boolean(this.config.dingtalk), telegram: Boolean(this.config.telegram) },
      minSeverity: this.config.minSeverity,
      intervalMs: this.config.intervalMs,
      sources: this.config.sources,
      maxItems: this.config.maxItems,
      seenCount: this.seen.size,
      lastRunAt: this.lastRunAt ? new Date(this.lastRunAt).toISOString() : null,
      lastSentCount: this.lastSentCount,
      lastResult: this.lastResult,
    };
  }
}

export const notifier = new Notifier();
