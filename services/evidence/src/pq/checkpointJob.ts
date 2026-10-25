// The hybrid checkpoint job: a pg-boss cron job that runs the evidence service's `checkpoint()` (over a log wrapped by
// `hybridCheckpointLog`), so every published checkpoint has both lines. A crash only repeats the step: the WORM copy
// of a tree size keeps its first note and the anchor insert is `ON CONFLICT DO NOTHING` (module `log`).
// Source: https://timgit.github.io/pg-boss/ (cron schedule, retries); IMPLEMENTATION 3.12
import type { Jobs } from '../jobs.ts';

export const QUEUE_CHECKPOINT = 'legx.checkpoint';
export const CHECKPOINT_CRON = '*/10 * * * *';

export const CHECKPOINT_QUEUE_OPTIONS = {
  policy: 'short', // one waiting job: a backlog of checkpoint jobs is worth nothing
  retryLimit: 5,
  retryDelay: 5,
  retryBackoff: true,
  retryDelayMax: 300,
} as const;

/** `checkpoint` is `createLogService(...).checkpoint`. A throw is the retry signal. */
export async function registerCheckpointJob(jobs: Jobs, checkpoint: () => Promise<unknown>): Promise<void> {
  await jobs.work(QUEUE_CHECKPOINT, async () => {
    await checkpoint();
  });
  await jobs.schedule(QUEUE_CHECKPOINT, CHECKPOINT_CRON, {});
}
