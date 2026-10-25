// P3.12-06/07 on real pg-boss and Postgres (container legx-3.12-pg, port 5505): the cron-style job runs the handler, a
// handler that throws (authority down) is retried by pg-boss, and the end result is one verified record.
// Source: https://timgit.github.io/pg-boss/ (createQueue, send, work, retryLimit)
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyId } from '@legx/contracts/values';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { localObjectStore } from '@legx/storage/localStore';
import { PgBoss } from 'pg-boss';
import { expect, it } from 'vitest';
import { makeLocalTsa } from '../../evidence/test/helpers/localTsa.ts';
import { createRenewal, QUEUE_RENEWAL, registerRenewalJob, renewalJobs, verifyRenewals } from '../src/index.ts';

const URL = process.env.LEGX_PG_URL ?? 'postgres://postgres:pw@127.0.0.1:5505/postgres';

it('pg-boss retries a renewal that failed because the authority was down, and ends with one verified record', async () => {
  const boss = new PgBoss(URL);
  await boss.start();
  try {
    const local = await makeLocalTsa('boss');
    const signer = nodeSigner(generateNodeSignerKeys(KeyId.parse('b-ed'), KeyId.parse('b-pq')));
    const pub = await signer.publicKeys();
    let down = 2;
    const client = local.client();
    const svc = createRenewal({
      objects: localObjectStore({ dir: mkdtempSync(join(tmpdir(), 'legx-boss-')) }),
      retainDays: 1,
      signer,
      head: async () => `legx.test/log\n1\n${Buffer.alloc(32, 1).toString('base64')}\n\n`,
      tsa: {
        timestamp: async (h) => {
          if (down-- > 0) throw new Error('authority down');
          return client.timestamp(h);
        },
      },
    });
    const jobs = await renewalJobs(boss, { policy: 'standard', retryLimit: 5, retryDelay: 1 });
    await registerRenewalJob(jobs, svc, { periodOf: () => 'int' });
    await jobs.send(QUEUE_RENEWAL, {});
    const deadline = Date.now() + 60_000;
    while ((await svc.load()).length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 500));
    const records = await svc.load();
    expect(records).toHaveLength(1);
    expect(down).toBeLessThan(0);
    expect(
      await verifyRenewals(records, {
        trustedRoots: [local.rootDer],
        keys: (k) =>
          k === pub.keyIds.ed25519
            ? { alg: 'ed25519', publicKey: pub.ed25519 }
            : k === pub.keyIds.mlDsa65
              ? { alg: 'ml-dsa-65', publicKey: pub.mlDsa65 }
              : undefined,
      }),
    ).toMatchObject({ ok: true, count: 1 });
  } finally {
    await boss.stop({ graceful: false });
  }
});
