import { markFalsePositive as persistMarkFalsePositive, isFalsePositive, getFalsePositives } from './persist.js';
import type { ThreatIndicator } from './types.js';

export interface QualityScore {
  score: number;
  factors: {
    baseConfidence: number;
    timeDecay: number;
    falsePositivePenalty: number;
    sourceBonus: number;
  };
  grade: 'excellent' | 'high' | 'medium' | 'low' | 'unreliable';
}

const TIME_DECAY_DAYS = 30;
const TIME_DECAY_PENALTY = 10;
const FALSE_POSITIVE_PENALTY = 70;
const MAX_SCORE = 100;
const MIN_SCORE = 0;

export function calculateQualityScore(indicator: ThreatIndicator): QualityScore {
  const baseConfidence = indicator.confidence ?? 50;

  let timeDecayPenalty = 0;
  if (indicator.lastSeen) {
    const daysSinceLastSeen = (Date.now() - new Date(indicator.lastSeen).getTime()) / (1000 * 86400);
    timeDecayPenalty = Math.floor(daysSinceLastSeen / TIME_DECAY_DAYS) * TIME_DECAY_PENALTY;
  }

  const isFP = isFalsePositive(indicator.indicator);
  const falsePositivePenalty = isFP ? FALSE_POSITIVE_PENALTY : 0;

  const sourceCount = indicator.sources?.length ?? 1;
  const sourceBonus = Math.min(sourceCount * 5, 20);

  let score = baseConfidence - timeDecayPenalty - falsePositivePenalty + sourceBonus;
  score = Math.max(MIN_SCORE, Math.min(MAX_SCORE, score));

  const grade = getQualityGrade(score);

  return {
    score,
    factors: {
      baseConfidence,
      timeDecay: -timeDecayPenalty,
      falsePositivePenalty: -falsePositivePenalty,
      sourceBonus,
    },
    grade,
  };
}

function getQualityGrade(score: number): 'excellent' | 'high' | 'medium' | 'low' | 'unreliable' {
  if (score >= 81) return 'excellent';
  if (score >= 61) return 'high';
  if (score >= 41) return 'medium';
  if (score >= 21) return 'low';
  return 'unreliable';
}

export function enrichIndicatorsWithQuality(indicators: ThreatIndicator[]): Array<ThreatIndicator & { quality: QualityScore }> {
  return indicators.map((indicator) => ({
    ...indicator,
    quality: calculateQualityScore(indicator),
  }));
}

export function filterByQuality(
  indicators: ThreatIndicator[],
  minScore: number,
): ThreatIndicator[] {
  return indicators.filter((indicator) => {
    const quality = calculateQualityScore(indicator);
    return quality.score >= minScore;
  });
}

export function markAsFalsePositive(
  iocValue: string,
  markedBy: string,
  reason?: string,
): void {
  persistMarkFalsePositive(iocValue, markedBy, reason ?? null, Date.now());
}

export function listFalsePositives(): Array<{
  iocValue: string;
  markedBy: string;
  reason: string | null;
  markedAt: number;
}> {
  const rows = getFalsePositives() as Array<{
    ioc_value: string;
    marked_by: string;
    reason: string | null;
    marked_at: number;
  }>;

  return rows.map((row) => ({
    iocValue: row.ioc_value,
    markedBy: row.marked_by,
    reason: row.reason,
    markedAt: row.marked_at,
  }));
}

export interface QualityDistribution {
  excellent: number;
  high: number;
  medium: number;
  low: number;
  unreliable: number;
  total: number;
}

export function getQualityDistribution(indicators: ThreatIndicator[]): QualityDistribution {
  const distribution: QualityDistribution = {
    excellent: 0,
    high: 0,
    medium: 0,
    low: 0,
    unreliable: 0,
    total: indicators.length,
  };

  for (const indicator of indicators) {
    const quality = calculateQualityScore(indicator);
    distribution[quality.grade]++;
  }

  return distribution;
}

export function getQualityTrend(
  indicators: ThreatIndicator[],
  days: number,
): Array<{ date: string; averageScore: number; count: number }> {
  const now = Date.now();
  const oneDayMs = 24 * 60 * 60 * 1000;
  const trend: Array<{ date: string; averageScore: number; count: number }> = [];

  for (let i = days - 1; i >= 0; i--) {
    const dayStart = now - i * oneDayMs;
    const dayEnd = dayStart + oneDayMs;
    const dateStr = new Date(dayStart).toISOString().split('T')[0];

    const dayIndicators = indicators.filter((ind) => {
      const lastSeen = ind.lastSeen ? new Date(ind.lastSeen).getTime() : 0;
      return lastSeen >= dayStart && lastSeen < dayEnd;
    });

    if (dayIndicators.length > 0) {
      const totalScore = dayIndicators.reduce((sum, ind) => {
        return sum + calculateQualityScore(ind).score;
      }, 0);
      const averageScore = Math.round(totalScore / dayIndicators.length);

      trend.push({
        date: dateStr,
        averageScore,
        count: dayIndicators.length,
      });
    } else {
      trend.push({
        date: dateStr,
        averageScore: 0,
        count: 0,
      });
    }
  }

  return trend;
}
