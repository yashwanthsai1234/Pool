// The job port. Anchoring and time-stamping are pg-boss jobs so that a crash or an unreachable authority only delays
// them: a handler that throws is retried with backoff, and the job state lives in Postgres.
// Source: https://timgit.github.io/pg-boss/ (queues, retryLimit, retryBackoff, schedule with cron, policy 'short')
import type { PgBoss } from 'pg-boss';

export const QUEUE_ANCHOR = 'legx.anchor';
export const QUEUE_TSA = 'legx.tsa';

export interface Jobs {
  send(queue: string, data: object): Promise<void>;
  /** The handler's throw is the retry signal; the queue decides how often and how late. */
  work<T extends object>(queue: string, handler: (data: T) => Promise<void>): Promise<void>;
  /** Cron, five fields, minute resolution. */
  schedule(queue: string, cron: string, data: object): Promise<void>;
}

/** Queue settings: anchors coalesce (policy `short`: one waiting job), time stamps retry for a month with backoff. */
export const QUEUE_OPTIONS = {
  [QUEUE_ANCHOR]: { policy: 'short', retryLimit: 5, retryDelay: 5, retryBackoff: true, retryDelayMax: 300 },
  [QUEUE_TSA]: {
    policy: 'standard',
    retryLimit: 40,
    retryDelay: 30,
    retryBackoff: true,
    retryDelayMax: 3600,
    retentionSeconds: 30 * 86_400,
  },
} as const;

/** `boss` must already be started. Creates the two queues if they are missing. */
export async function pgBossJobs(boss: PgBoss): Promise<Jobs> {
  for (const [name, options] of Object.entries(QUEUE_OPTIONS)) await boss.createQueue(name, options);
  return {
    async send(queue, data) {
      await boss.send(queue, data);
    },
    async work(queue, handler) {
      await boss.work(queue, { pollingIntervalSeconds: 1 }, async (jobs) => {
        for (const job of jobs) await handler(job.data as never);
      });
    },
    async schedule(queue, cron, data) {
      await boss.schedule(queue, cron, data);
    },
  };
}
