import { describe, it, expect } from 'vitest';
import { loadNotifyConfig, severityRank } from '../src/notify/config.js';

const base: NodeJS.ProcessEnv = {};

describe('severityRank', () => {
  it('orders severities low < medium < high < critical', () => {
    expect(severityRank('low')).toBeLessThan(severityRank('medium'));
    expect(severityRank('medium')).toBeLessThan(severityRank('high'));
    expect(severityRank('high')).toBeLessThan(severityRank('critical'));
  });
});

describe('loadNotifyConfig', () => {
  it('is disabled when no channel is configured even if the flag is on', () => {
    const cfg = loadNotifyConfig({ ...base, NOTIFY_ENABLED: 'true' });
    expect(cfg.enabled).toBe(false);
  });

  it('is disabled when a channel exists but the flag is off', () => {
    const cfg = loadNotifyConfig({ ...base, DINGTALK_WEBHOOK: 'token123' });
    expect(cfg.enabled).toBe(false);
    expect(cfg.dingtalk).not.toBeNull();
  });

  it('enables only when flag is on AND a channel is configured', () => {
    const cfg = loadNotifyConfig({
      ...base,
      NOTIFY_ENABLED: 'true',
      TELEGRAM_BOT_TOKEN: 'bot',
      TELEGRAM_CHAT_ID: '42',
    });
    expect(cfg.enabled).toBe(true);
    expect(cfg.telegram).toEqual({ botToken: 'bot', chatId: '42' });
  });

  it('normalizes a bare DingTalk access_token into a full webhook URL', () => {
    const cfg = loadNotifyConfig({ ...base, DINGTALK_WEBHOOK: 'abc' });
    expect(cfg.dingtalk?.webhook).toBe(
      'https://oapi.dingtalk.com/robot/send?access_token=abc',
    );
  });

  it('keeps a full webhook URL untouched', () => {
    const cfg = loadNotifyConfig({ ...base, DINGTALK_WEBHOOK: 'https://example.com/hook' });
    expect(cfg.dingtalk?.webhook).toBe('https://example.com/hook');
  });

  it('parses and filters the source allow-list', () => {
    const cfg = loadNotifyConfig({ ...base, NOTIFY_SOURCES: 'feodo, bogus ,nvd' });
    expect(cfg.sources).toEqual(['feodo', 'nvd']);
  });

  it('treats an all-invalid source list as null (all sources)', () => {
    const cfg = loadNotifyConfig({ ...base, NOTIFY_SOURCES: 'bogus,nope' });
    expect(cfg.sources).toBeNull();
  });

  it('defaults minSeverity to critical and clamps seenMax to a floor', () => {
    const cfg = loadNotifyConfig({ ...base, NOTIFY_SEEN_MAX: '10' });
    expect(cfg.minSeverity).toBe('critical');
    expect(cfg.seenMax).toBe(1000);
  });
});
