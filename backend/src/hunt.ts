import { randomUUID } from 'node:crypto';
import { recordHuntHistory, getHuntHistory as persistGetHuntHistory } from './persist.js';
import type { HuntQuery, HuntResult, HuntHistory, ThreatIndicator } from './types.js';

export function batchHunt(
  query: HuntQuery,
  indicators: ThreatIndicator[],
  initiatedBy: string,
): { results: HuntResult[]; query: HuntQuery } {
  const { iocs, timeRange, sources } = query;
  const results: HuntResult[] = [];

  for (const ioc of iocs) {
    const matches = indicators.filter((indicator) => {
      const valueMatch =
        indicator.indicator.toLowerCase() === ioc.toLowerCase() ||
        indicator.indicator.toLowerCase().includes(ioc.toLowerCase());

      if (!valueMatch) return false;

      const timeMatch =
        (!timeRange.start || new Date(indicator.lastSeen ?? 0).getTime() >= timeRange.start) &&
        (!timeRange.end || new Date(indicator.firstSeen ?? 0).getTime() <= timeRange.end);

      if (!timeMatch) return false;

      const sourceMatch = !sources || sources.length === 0 || sources.includes(indicator.source);

      return sourceMatch;
    });

    if (matches.length > 0) {
      const allSources = matches.flatMap((m) => m.sources ?? [m.source]);
      const uniqueSources = [...new Set(allSources)];
      const avgConfidence =
        matches.reduce((sum, m) => sum + (m.confidence ?? 50), 0) / matches.length;

      results.push({
        ioc,
        matches,
        firstSeen: matches.reduce((earliest, m) => {
          const fs = m.firstSeen;
          if (!fs) return earliest;
          return !earliest || fs < earliest ? fs : earliest;
        }, '' as string),
        lastSeen: matches.reduce((latest, m) => {
          const ls = m.lastSeen;
          if (!ls) return latest;
          return !latest || ls > latest ? ls : latest;
        }, '' as string),
        confidence: Math.round(avgConfidence + uniqueSources.length * 5),
      });
    } else {
      results.push({
        ioc,
        matches: [],
        confidence: 0,
      });
    }
  }

  const history: HuntHistory = {
    id: randomUUID(),
    query: JSON.stringify({ iocs: iocs.slice(0, 10), timeRange, sources }),
    resultsCount: results.filter((r) => r.matches.length > 0).length,
    initiatedBy,
    createdAt: Date.now(),
  };

  recordHuntHistory(history);

  return { results, query };
}

export function getHuntHistory(limit = 50): HuntHistory[] {
  const rows = persistGetHuntHistory(limit) as Array<{
    id: string;
    query: string;
    results_count: number;
    initiated_by: string;
    created_at: number;
  }>;

  return rows.map((row) => ({
    id: row.id,
    query: row.query,
    resultsCount: row.results_count,
    initiatedBy: row.initiated_by,
    createdAt: row.created_at,
  }));
}
