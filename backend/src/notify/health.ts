// Pure source-health transition logic, decoupled from delivery so it can be tested
// without channels or timers.

export interface HealthAlertState {
  // Consecutive failed refreshes per source.
  failStreak: Record<string, number>;
  // Sources we've already sent a "down" alert for (awaiting recovery).
  downAlerted: Record<string, true>;
}

export interface HealthInput {
  source: string;
  lastError: string | null;
}

export type HealthFire = { source: string; kind: 'down' | 'recovered' };

export function emptyHealthState(): HealthAlertState {
  return { failStreak: {}, downAlerted: {} };
}

// Fold the latest health snapshot into the alert state, returning which sources should
// fire a down/recovered alert. A source fires "down" once its failure streak reaches the
// threshold, and "recovered" the first time it succeeds again after a down alert.
export function reduceHealth(
  state: HealthAlertState,
  health: HealthInput[],
  threshold: number,
): { state: HealthAlertState; fire: HealthFire[] } {
  const failStreak = { ...state.failStreak };
  const downAlerted = { ...state.downAlerted };
  const fire: HealthFire[] = [];

  for (const h of health) {
    if (h.lastError !== null) {
      const streak = (failStreak[h.source] ?? 0) + 1;
      failStreak[h.source] = streak;
      if (streak >= threshold && !downAlerted[h.source]) {
        downAlerted[h.source] = true;
        fire.push({ source: h.source, kind: 'down' });
      }
    } else {
      failStreak[h.source] = 0;
      if (downAlerted[h.source]) {
        delete downAlerted[h.source];
        fire.push({ source: h.source, kind: 'recovered' });
      }
    }
  }

  return { state: { failStreak, downAlerted }, fire };
}
