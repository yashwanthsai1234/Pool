// Resumable onboarding: the ledger phase (steps 0a, 0b, events) runs as a pg-boss job. The job holds only the operations
// account (no bar number, no salt), and the phase is idempotent, so a crash or a retry just runs it again.
// Source: https://github.com/timgit/pg-boss/blob/master/docs/api/jobs.md (send, work, retry options)
// Source: https://github.com/timgit/pg-boss/blob/master/docs/api/queues.md (createQueue, retryLimit, retryDelay)
import { PgBoss } from 'pg-boss';
import { VerifierError } from './errors.ts';
import type { Log, Verifier } from './service.ts';

const QUEUE = 'verifier-issue-credential';

export interface OnboardingJobs {
  /** Queues the ledger phase for an operations account that already has a fresh BarVerification. */
  enqueue(opsAccount: string): Promise<void>;
  stop(): Promise<void>;
}

export async function startOnboardingJobs(o: {
  readonly connectionString: string;
  readonly verifier: Pick<Verifier, 'issue'>;
  readonly schema?: string;
  readonly pollSeconds?: number;
  readonly retryLimit?: number;
  readonly retryDelaySeconds?: number;
  readonly log?: Log;
}): Promise<OnboardingJobs> {
  const boss = new PgBoss({ connectionString: o.connectionString, schema: o.schema ?? 'legx_verifier_jobs' });
  boss.on('error', (e) => o.log?.('pgboss.error', { message: e.message }));
  await boss.start();
  await boss.createQueue(QUEUE, {
    retryLimit: o.retryLimit ?? 20,
    retryDelay: o.retryDelaySeconds ?? 5,
    retryBackoff: true,
  });
  await boss.work<{ opsAccount: string }>(QUEUE, { pollingIntervalSeconds: o.pollSeconds ?? 2 }, async ([job]) => {
    if (!job) return;
    const r = await o.verifier.issue(job.data.opsAccount);
    // Not an error of ours, but the job is not done: throwing makes pg-boss retry later.
    if (r.state !== 'complete')
      throw new VerifierError('AWAITING_OPS_ACCEPT', `${job.data.opsAccount} must accept the credential`);
  });
  return {
    enqueue: async (opsAccount) => {
      await boss.send(QUEUE, { opsAccount });
    },
    stop: () => boss.stop({ graceful: true, timeout: 10_000 }),
  };
}
