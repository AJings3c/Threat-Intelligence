import { afterEach, describe, expect, it, vi } from 'vitest';
import { enrichIndicator, parseIndicatorType } from '../src/enrich.js';

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.VIRUSTOTAL_API_KEY;
  delete process.env.VIRUSTOTAL_API_BASE;
  delete process.env.SHODAN_API_KEY;
  delete process.env.SHODAN_API_BASE;
  delete process.env.CENSYS_API_ID;
  delete process.env.CENSYS_API_SECRET;
  delete process.env.CENSYS_API_BASE;
});

describe('parseIndicatorType', () => {
  it('accepts known indicator types', () => {
    expect(parseIndicatorType('ip')).toBe('ip');
    expect(parseIndicatorType('hash')).toBe('hash');
    expect(parseIndicatorType('bogus')).toBeNull();
  });
});

describe('enrichIndicator', () => {
  it('returns no providers when no API keys are configured', async () => {
    await expect(enrichIndicator('1.2.3.4', 'ip')).resolves.toEqual({
      indicator: '1.2.3.4',
      indicatorType: 'ip',
      results: [],
    });
  });

  it('queries enabled providers and summarizes responses', async () => {
    process.env.VIRUSTOTAL_API_KEY = 'vt';
    process.env.VIRUSTOTAL_API_BASE = 'https://vt.example/api/v3';
    process.env.SHODAN_API_KEY = 'shodan';
    process.env.SHODAN_API_BASE = 'https://shodan.example/shodan/host';
    process.env.CENSYS_API_ID = 'id';
    process.env.CENSYS_API_SECRET = 'secret';
    process.env.CENSYS_API_BASE = 'https://censys.example/api/v2/hosts';

    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({
            data: {
              attributes: {
                reputation: -10,
                last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 20 },
              },
            },
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            ports: [22, 443],
            hostnames: ['example.net'],
            org: 'Example Org',
            isp: 'Example ISP',
            vulns: { 'CVE-2026-0001': {} },
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            result: {
              service_count: 2,
              services: [{ port: 443, service_name: 'HTTPS', transport_protocol: 'TCP' }],
              location: { country: 'United States' },
              autonomous_system: { asn: 64512, name: 'EXAMPLE' },
            },
          }),
        ),
    );

    const result = await enrichIndicator('198.51.100.10', 'ip');
    expect(result.results.map((r) => r.provider)).toEqual(['virustotal', 'shodan', 'censys']);
    expect(result.results[0].summary?.lastAnalysisStats).toEqual({
      malicious: 3,
      suspicious: 1,
      harmless: 20,
    });
    expect(result.results[1].summary?.ports).toEqual([22, 443]);
    expect(result.results[2].summary?.serviceCount).toBe(2);
  });
});
