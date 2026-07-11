import { describe, expect, it } from 'vitest';
import { ProviderCircuitBreaker } from '../src/providerCircuit.js';

describe('provider circuit breaker', () => {
  it('opens after consecutive failures, permits a half-open retry, and resets on success', () => {
    const circuit = new ProviderCircuitBreaker(2, 1000);
    circuit.record('virustotal', false, 100);
    expect(circuit.openUntil('virustotal', 100)).toBeNull();
    circuit.record('virustotal', false, 200);
    expect(circuit.openUntil('virustotal', 300)).toBe(1200);
    expect(circuit.openUntil('virustotal', 1200)).toBeNull();
    circuit.record('virustotal', true, 1200);
    expect(circuit.openUntil('virustotal', 1200)).toBeNull();
  });

  it('isolates failures by provider', () => {
    const circuit = new ProviderCircuitBreaker(1, 1000);
    circuit.record('shodan', false, 100);
    expect(circuit.openUntil('shodan', 200)).toBe(1100);
    expect(circuit.openUntil('censys', 200)).toBeNull();
  });
});
