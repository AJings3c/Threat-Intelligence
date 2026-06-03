import { describe, it, expect } from 'vitest';
import { loadNotifyConfig, severityRank } from '../notify/config.js';

describe('severityRank', () => {
  it('orders severities ascending', () => {
    expect(severityRank('low')).toBeLessThan(severityRank('medium'));
    expect(severityRank('medium')).toBeLessThan(severityRank('high'));
    expect(severityRank('high')).toBeLessThan(severityRank('critical'));
  });
});

describe('loadNotifyConfig', () => {
  it('is disabled with no channels even when the flag is set', () => {
    const cfg = loadNotifyConfig({ NOTIFY_ENABLED: 'true' });
    expect(cfg.enabled).toBe(false);
    expect(cfg.dingtalk).toBeNull();
    expect(cfg.telegram).toBeNull();
  });

  it('enables only when the flag is set AND a channel is configured', () => {
    const base = { DINGTALK_WEBHOOK: 'token123' };
    expect(loadNotifyConfig(base).enabled).toBe(false);
    expect(loadNotifyConfig({ ...base, NOTIFY_ENABLED: 'true' }).enabled).toBe(true);
  });

  it('expands a bare DingTalk token into a full webhook URL', () => {
    const cfg = loadNotifyConfig({ DINGTALK_WEBHOOK: 'abc', DINGTALK_SECRET: 'sec' });
    expect(cfg.dingtalk?.webhook).toBe(
      'https://oapi.dingtalk.com/robot/send?access_token=abc',
    );
    expect(cfg.dingtalk?.secret).toBe('sec');
  });

  it('keeps a full webhook URL as-is', () => {
    const cfg = loadNotifyConfig({ DINGTALK_WEBHOOK: 'https://example.com/hook' });
    expect(cfg.dingtalk?.webhook).toBe('https://example.com/hook');
  });

  it('requires both token and chat id for telegram', () => {
    expect(loadNotifyConfig({ TELEGRAM_BOT_TOKEN: 't' }).telegram).toBeNull();
    const cfg = loadNotifyConfig({ TELEGRAM_BOT_TOKEN: 't', TELEGRAM_CHAT_ID: 'c' });
    expect(cfg.telegram).toEqual({ botToken: 't', chatId: 'c' });
  });

  it('defaults severity to critical and parses a valid override', () => {
    expect(loadNotifyConfig({}).minSeverity).toBe('critical');
    expect(loadNotifyConfig({ NOTIFY_MIN_SEVERITY: 'HIGH' }).minSeverity).toBe('high');
    expect(loadNotifyConfig({ NOTIFY_MIN_SEVERITY: 'bogus' }).minSeverity).toBe('critical');
  });

  it('parses and validates the source allow-list', () => {
    expect(loadNotifyConfig({}).sources).toBeNull();
    expect(loadNotifyConfig({ NOTIFY_SOURCES: 'feodo, nvd' }).sources).toEqual(['feodo', 'nvd']);
    expect(loadNotifyConfig({ NOTIFY_SOURCES: 'bogus' }).sources).toBeNull();
  });
});
