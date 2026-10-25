// The whole deal against the real standalone ledger (port 6103) and Postgres 18 (port 5502): setup, lock check, gate,
// release, a 4-of-4 exit on slot S, and the close. The coordinator reads every result back from validated ledgers.

import { verifyMultisigned } from '@legx/core/verify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { account } from '../test/support/lifecycle.ts';
import { makeWorld, newDeal, ROLES, type World } from '../test/support/world.ts';
import { freshPg, type RealLedger, realLedger } from './support/real.ts';
import { Scenario, STAGE_STATE } from './support/scenario.ts';

let real: RealLedger;
let w: World;
let opsA: Awaited<ReturnType<RealLedger['fund']>>;
let opsB: Awaited<ReturnType<RealLedger['fund']>>;
let payA: string;
let payB: string;

beforeAll(async () => {
  real = await realLedger();
  w = await makeWorld({ db: await freshPg(), ledger: real.port });
  opsA = await real.fund(200);
  opsB = await real.fund(200);
  payA = (await real.fund(100)).classicAddress;
  payB = (await real.fund(100)).classicAddress;
});
afterAll(async () => {
  await w.close();
  await real.stop();
});

describe('a full deal on the real ledger', () => {
  it('walks every state, then pays Bob 4-of-4 on slot S and closes the wallet', async () => {
    const s = new Scenario(w, real, opsA, opsB, payA, payB);
    await s.create((x) => newDeal(x, { amountDrops: '50000000' }));
    for (let i = 0; i < STAGE_STATE.length; i++) {
      await s.next();
      expect(await s.state()).toBe(STAGE_STATE[i]);
    }
    const v = (await w.app.inject({ method: 'GET', url: '/' })).statusCode; // no route: 404, the app is alive
    expect(v).toBe(404);
    const { req, last } = await s.exit('pay_bob');
    expect(last?.status).toBe(200);
    expect(last?.body.submitted).toBe(true);
    expect(await s.state()).toBe('PAID_OUT');
    const tx = await real.port.tx(
      (
        await w.db.repos.ledgerObservations.listForAccount(s.shell.classicAddress, 0)
      )[0]?.tx_hash.toUpperCase() as never,
    );
    expect(tx?.meta.delivered_amount).toBe('50000000');
    expect(tx?.tx.Sequence).toBe(req.unsignedTx.Sequence);
    expect(
      verifyMultisigned(
        await signedBlobOf(s, req.requestId),
        ROLES.map((r) => account(w, r)),
      ).ok,
    ).toBe(true);
    await real.close(260);
    const close = await s.exit('close');
    expect(close.last?.status).toBe(200);
    expect(await s.state()).toBe('CLOSED');
  });
});

async function signedBlobOf(_s: Scenario, requestId: string) {
  const { multisign } = await import('xrpl');
  return multisign((await w.db.repos.signatures.list(requestId)).map((x) => x.signer_blob));
}
