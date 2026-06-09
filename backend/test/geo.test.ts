import { describe, expect, it } from 'vitest';
import { isIpv4 } from '../src/geo.js';

describe('isIpv4', () => {
  it('requires dotted quads with octets in range', () => {
    expect(isIpv4('203.0.113.42')).toBe(true);
    expect(isIpv4('999.0.0.1')).toBe(false);
    expect(isIpv4('203.0.113')).toBe(false);
    expect(isIpv4('example.com')).toBe(false);
  });
});
