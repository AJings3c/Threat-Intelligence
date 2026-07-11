import type { EnrichmentProvider } from './types.js';

interface CircuitState {
  failures: number;
  openUntil: number;
}

export class ProviderCircuitBreaker {
  private readonly states = new Map<EnrichmentProvider, CircuitState>();

  constructor(
    private readonly failureThreshold = 3,
    private readonly cooldownMs = 60_000,
  ) {}

  openUntil(provider: EnrichmentProvider, now = Date.now()): number | null {
    const state = this.states.get(provider);
    if (!state || state.openUntil <= now) return null;
    return state.openUntil;
  }

  record(provider: EnrichmentProvider, success: boolean, now = Date.now()): void {
    if (success) {
      this.states.delete(provider);
      return;
    }
    const previous = this.states.get(provider) ?? { failures: 0, openUntil: 0 };
    const failures = previous.failures + 1;
    this.states.set(provider, {
      failures,
      openUntil: failures >= this.failureThreshold ? now + this.cooldownMs : 0,
    });
  }

  reset(): void {
    this.states.clear();
  }
}
