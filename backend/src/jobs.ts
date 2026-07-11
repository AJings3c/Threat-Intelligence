import { randomUUID } from 'node:crypto';
import {
  claimBackgroundJob,
  completeBackgroundJob,
  deleteFinishedBackgroundJobs,
  enqueueBackgroundJob,
  failBackgroundJob,
  type BackgroundJob,
} from './persist.js';
import { errorMessage } from './util.js';

export type JobHandler = (job: BackgroundJob) => Promise<void>;

export interface DurableJobWorkerOptions {
  pollIntervalMs?: number;
  leaseMs?: number;
  maxJobsPerTick?: number;
  workerId?: string;
}

export class DurableJobWorker {
  private readonly workerId: string;
  private readonly pollIntervalMs: number;
  private readonly leaseMs: number;
  private readonly maxJobsPerTick: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(
    private readonly handlers: Record<string, JobHandler>,
    options: DurableJobWorkerOptions = {},
  ) {
    this.workerId = options.workerId ?? `worker-${process.pid}-${randomUUID()}`;
    this.pollIntervalMs = Math.max(250, options.pollIntervalMs ?? 1000);
    this.leaseMs = Math.max(5000, options.leaseMs ?? 10 * 60_000);
    this.maxJobsPerTick = Math.max(1, Math.min(options.maxJobsPerTick ?? 4, 50));
  }

  start(): void {
    if (this.timer) return;
    void this.runOnce();
    this.timer = setInterval(() => void this.runOnce(), this.pollIntervalMs);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async runOnce(): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    let processed = 0;
    try {
      while (processed < this.maxJobsPerTick) {
        const job = claimBackgroundJob(this.workerId, Date.now(), this.leaseMs);
        if (!job) break;
        processed += 1;
        const handler = this.handlers[job.type];
        if (!handler) {
          failBackgroundJob(job.id, this.workerId, `no handler registered for job type ${job.type}`, Date.now(), 0);
          continue;
        }
        try {
          await handler(job);
          completeBackgroundJob(job.id, this.workerId);
        } catch (err) {
          const retryDelay = Math.min(1000 * 2 ** Math.max(0, job.attempts - 1), 5 * 60_000);
          failBackgroundJob(job.id, this.workerId, errorMessage(err), Date.now(), retryDelay);
        }
      }
      if (processed > 0) deleteFinishedBackgroundJobs(Date.now() - 7 * 24 * 60 * 60_000);
      return processed;
    } finally {
      this.running = false;
    }
  }
}

export function enqueueDurableJob(
  type: string,
  payload: Record<string, unknown> = {},
  options: { dedupeKey?: string; maxAttempts?: number; availableAt?: number } = {},
): boolean {
  return enqueueBackgroundJob({
    id: randomUUID(),
    type,
    payload,
    dedupeKey: options.dedupeKey,
    maxAttempts: options.maxAttempts,
    availableAt: options.availableAt,
  });
}
