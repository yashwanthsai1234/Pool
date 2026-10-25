// pg-boss behind the `Jobs` port of the evidence service (same contract: a throw is a retry). Creates the renewal queue
// with its own retry settings; `boss` must already be started.
// Source: https://timgit.github.io/pg-boss/ (createQueue, work, schedule)
import type { Jobs } from '@legx/evidence/jobs';
import type { PgBoss } from 'pg-boss';
import { QUEUE_RENEWAL, RENEWAL_QUEUE_OPTIONS } from './job.ts';

export async function renewalJobs(boss: PgBoss, queueOptions: object = RENEWAL_QUEUE_OPTIONS): Promise<Jobs> {
  await boss.createQueue(QUEUE_RENEWAL, queueOptions);
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
