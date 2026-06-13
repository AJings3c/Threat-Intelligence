import { useState, useEffect, useRef } from 'react';
import { Play, Pause, RotateCcw, ChevronLeft, ChevronRight } from 'lucide-react';
import type { Language, ThreatIndicator } from '../types';

interface TimelineEvent {
  id: string;
  timestamp: number;
  indicator: ThreatIndicator;
  technique?: string;
  tactic?: string;
}

interface AttackPhase {
  tactic: string;
  events: TimelineEvent[];
  color: string;
}

const TIMELINE_TEXT = {
  en: {
    title: 'Attack Timeline',
    subtitle: 'Chronological attack chain reconstruction',
    play: 'Play',
    pause: 'Pause',
    reset: 'Reset',
    speed: 'Speed',
    events: 'Events',
    noData: 'No timeline data available',
    currentEvent: 'Current Event',
    phase: 'Phase',
    technique: 'Technique',
    indicator: 'Indicator',
  },
  zh: {
    title: '攻击时间线',
    subtitle: '按时序重建攻击链',
    play: '播放',
    pause: '暂停',
    reset: '重置',
    speed: '速度',
    events: '事件',
    noData: '无时间线数据',
    currentEvent: '当前事件',
    phase: '阶段',
    technique: '技术',
    indicator: '指标',
  },
};

const MITRE_TACTICS = [
  { id: 'reconnaissance', name: 'Reconnaissance', color: '#3b82f6' },
  { id: 'initial-access', name: 'Initial Access', color: '#8b5cf6' },
  { id: 'execution', name: 'Execution', color: '#ec4899' },
  { id: 'persistence', name: 'Persistence', color: '#f59e0b' },
  { id: 'privilege-escalation', name: 'Privilege Escalation', color: '#ef4444' },
  { id: 'defense-evasion', name: 'Defense Evasion', color: '#10b981' },
  { id: 'credential-access', name: 'Credential Access', color: '#06b6d4' },
  { id: 'discovery', name: 'Discovery', color: '#84cc16' },
  { id: 'lateral-movement', name: 'Lateral Movement', color: '#f97316' },
  { id: 'collection', name: 'Collection', color: '#a855f7' },
  { id: 'exfiltration', name: 'Exfiltration', color: '#dc2626' },
  { id: 'impact', name: 'Impact', color: '#991b1b' },
];

function inferTactic(indicator: ThreatIndicator): string {
  if (indicator.type === 'phishing_url') return 'initial-access';
  if (indicator.type === 'c2_server') return 'command-and-control';
  if (indicator.type === 'malware_host') return 'execution';
  if (indicator.type === 'malicious_hash') return 'execution';
  return 'discovery';
}

export function AttackTimeline({ lang, indicators }: { lang: Language; indicators: ThreatIndicator[] }) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [speed, setSpeed] = useState(1);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  const t = TIMELINE_TEXT[lang];

  const events: TimelineEvent[] = indicators
    .filter((ind) => ind.firstSeen)
    .sort((a, b) => {
      const aTime = typeof a.firstSeen === 'string' ? new Date(a.firstSeen).getTime() : (a.firstSeen ?? 0);
      const bTime = typeof b.firstSeen === 'string' ? new Date(b.firstSeen).getTime() : (b.firstSeen ?? 0);
      return aTime - bTime;
    })
    .slice(0, 50)
    .map((ind) => {
      const timestamp = typeof ind.firstSeen === 'string' ? new Date(ind.firstSeen).getTime() : (ind.firstSeen ?? Date.now());
      return {
        id: ind.id,
        timestamp,
        indicator: ind,
        tactic: inferTactic(ind),
      };
    });

  const phases: AttackPhase[] = MITRE_TACTICS.map((tactic) => ({
    tactic: tactic.name,
    events: events.filter((e) => e.tactic === tactic.id),
    color: tactic.color,
  })).filter((phase) => phase.events.length > 0);

  useEffect(() => {
    if (isPlaying && currentIndex < events.length - 1) {
      intervalRef.current = setInterval(() => {
        setCurrentIndex((prev) => {
          if (prev >= events.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, 2000 / speed);
    } else if (!isPlaying && intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isPlaying, currentIndex, events.length, speed]);

  const handlePlayPause = () => {
    if (currentIndex >= events.length - 1) {
      setCurrentIndex(0);
    }
    setIsPlaying(!isPlaying);
  };

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentIndex(0);
  };

  const handlePrev = () => {
    setCurrentIndex((prev) => Math.max(0, prev - 1));
  };

  const handleNext = () => {
    setCurrentIndex((prev) => Math.min(events.length - 1, prev + 1));
  };

  if (events.length === 0) {
    return (
      <div className="surface flex h-96 items-center justify-center rounded-lg">
        <p className="text-sm text-slate-400">{t.noData}</p>
      </div>
    );
  }

  const currentEvent = events[currentIndex];
  const progress = events.length > 1 ? (currentIndex / (events.length - 1)) * 100 : 0;

  return (
    <div className="space-y-4">
      <div className="surface rounded-lg p-4">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handlePlayPause}
              className="control inline-flex items-center gap-2 px-3 py-2 text-sm font-bold"
            >
              {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              {isPlaying ? t.pause : t.play}
            </button>
            <button
              type="button"
              onClick={handleReset}
              className="control inline-flex items-center gap-2 px-3 py-2 text-sm"
            >
              <RotateCcw className="h-4 w-4" />
              {t.reset}
            </button>
            <button type="button" onClick={handlePrev} className="control px-3 py-2 text-sm">
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button type="button" onClick={handleNext} className="control px-3 py-2 text-sm">
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-400">{t.speed}</span>
            <div className="flex gap-1">
              {[0.5, 1, 2, 4].map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSpeed(s)}
                  className={`control px-2 py-1 text-xs ${speed === s ? 'bg-teal-300/15 text-teal-100' : 'text-slate-400'}`}
                >
                  {s}x
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="relative mb-4">
          <div className="h-2 rounded-full bg-slate-700">
            <div
              className="h-full rounded-full bg-teal-400 transition-all duration-200"
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="mt-2 flex justify-between text-xs text-slate-400">
            <span>
              {currentIndex + 1} / {events.length} {t.events}
            </span>
            <span>{new Date(currentEvent.timestamp).toLocaleString()}</span>
          </div>
        </div>

        {currentEvent && (
          <div className="surface-raised rounded-lg p-4">
            <h3 className="mb-3 text-sm font-bold text-slate-200">{t.currentEvent}</h3>
            <div className="grid gap-3 md:grid-cols-3">
              <div>
                <div className="mb-1 text-xs font-semibold text-slate-400">{t.phase}</div>
                <div
                  className="inline-block rounded px-2 py-1 text-xs font-bold"
                  style={{
                    backgroundColor: `${MITRE_TACTICS.find((tac) => tac.id === currentEvent.tactic)?.color}22`,
                    color: MITRE_TACTICS.find((tac) => tac.id === currentEvent.tactic)?.color,
                  }}
                >
                  {MITRE_TACTICS.find((tac) => tac.id === currentEvent.tactic)?.name}
                </div>
              </div>
              <div>
                <div className="mb-1 text-xs font-semibold text-slate-400">{t.indicator}</div>
                <div className="font-mono text-sm text-slate-200">{currentEvent.indicator.indicator}</div>
              </div>
              <div>
                <div className="mb-1 text-xs font-semibold text-slate-400">Type</div>
                <div className="inline-block rounded bg-slate-500/20 px-2 py-1 text-xs font-bold capitalize text-slate-300">
                  {currentEvent.indicator.indicatorType}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="surface rounded-lg p-4">
        <h3 className="mb-3 text-sm font-bold text-slate-200">Attack Chain Phases</h3>
        <div className="space-y-2">
          {phases.map((phase) => (
            <div key={phase.tactic} className="surface-raised rounded-lg p-3">
              <div className="mb-2 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="h-3 w-3 rounded-full" style={{ backgroundColor: phase.color }} />
                  <span className="text-sm font-semibold text-slate-200">{phase.tactic}</span>
                </div>
                <span className="rounded bg-slate-500/20 px-2 py-0.5 text-xs font-bold text-slate-400">
                  {phase.events.length}
                </span>
              </div>
              <div className="flex gap-1">
                {phase.events.map((event) => (
                  <button
                    key={event.id}
                    type="button"
                    onClick={() => setCurrentIndex(events.indexOf(event))}
                    className={`h-2 flex-1 rounded transition-all ${
                      events.indexOf(event) === currentIndex
                        ? 'bg-teal-400'
                        : events.indexOf(event) < currentIndex
                          ? 'bg-slate-500'
                          : 'bg-slate-700'
                    }`}
                    title={event.indicator.indicator}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
