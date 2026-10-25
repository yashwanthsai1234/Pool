import type { Jobs } from '../../src/jobs.ts';

interface Pending {
  queue: string;
  data: object;
  attempts: number;
}

/** A job runner with pg-boss's contract: a handler that throws leaves the job queued for another attempt. */
export function memoryJobs(retryLimit = 40) {
  const handlers = new Map<string, (data: never) => Promise<void>>();
  const pending: Pending[] = [];
  const schedules: { queue: string; cron: string }[] = [];
  const failures: { queue: string; message: string }[] = [];
  const sent: { queue: string; data: object }[] = [];
  const jobs: Jobs = {
    async send(queue, data) {
      sent.push({ queue, data });
      pending.push({ queue, data, attempts: 0 });
    },
    async work(queue, handler) {
      handlers.set(queue, handler as never);
    },
    async schedule(queue, cron) {
      schedules.push({ queue, cron });
    },
  };
  return {
    jobs,
    schedules,
    failures,
    sent,
    get pending() {
      return pending.length;
    },
    /** One round: every queued job runs once, concurrently. Failed ones stay queued (until `retryLimit`). */
    async round(): Promise<void> {
      const batch = pending.splice(0, pending.length);
      await Promise.all(
        batch.map(async (job) => {
          try {
            await handlers.get(job.queue)?.(job.data as never);
          } catch (e) {
            failures.push({ queue: job.queue, message: (e as Error).message });
            if (job.attempts + 1 < retryLimit) pending.push({ ...job, attempts: job.attempts + 1 });
          }
        }),
      );
    },
    async drain(maxRounds = 10): Promise<void> {
      for (let i = 0; i < maxRounds && pending.length > 0; i++) await this.round();
    },
  };
}
