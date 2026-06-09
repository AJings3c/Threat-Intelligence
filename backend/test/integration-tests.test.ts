import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/sources/otx.js', () => ({
  fetchOtx: vi.fn(),
}));

import { testEnrichmentProvider, testThreatSource } from '../src/integrationTests.js';

beforeEach(() => {
  delete process.env.OTX_API_KEY;
  delete process.env.VIRUSTOTAL_API_KEY;
});

describe('integration tests', () => {
  it('reports missing source credentials without calling the provider', async () => {
    const result = await testThreatSource('otx');

    expect(result).toMatchObject({
      kind: 'source',
      id: 'otx',
      status: 'missing_config',
      configured: false,
    });
    expect(result.requiredEnv).toContain('OTX_API_KEY');
  });

  it('reports missing enrichment credentials', async () => {
    const result = await testEnrichmentProvider('virustotal');

    expect(result).toMatchObject({
      kind: 'provider',
      id: 'virustotal',
      status: 'missing_config',
      configured: false,
    });
    expect(result.requiredEnv).toContain('VIRUSTOTAL_API_KEY');
  });
});
