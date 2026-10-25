// T-A-28b (IMPLEMENTATION 2.6; DESIGN D4, D22, 6.17): another account submits the finish. The ledger answers
// tecNO_PERMISSION (DepositAuth with the one preauthorized account), and the release gate fails RELEASER_SEALED and only
// that, when its submitter is not the sealed releaser. Run once the preauth exists (the lock is not finished) and after
// the lock. The sealed releaser then finishes, so the refusal was not an artefact of the setup.
// Source: https://xrpl.org/docs/concepts/accounts/depositauth ; DESIGN 6.17 RELEASER_SEALED
import { checkRelease } from '@legx/core/releaseGate';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { newDeal, type Stage } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';
import { escrowsWith, outcome, stranger } from './util.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-A-28b another account submits the finish', () => {
  it.each<Stage>(['preauth', 'locked'])('phase %s', async (phase) => {
    const d = await newDeal(c, phase);
    // setup state: one preauth entry, for lawyer B's operations account
    const preauth = await d.objects('deposit_preauth');
    expect(preauth.map((o) => o.Authorize)).toEqual([d.lawyerB.ops.classicAddress]);
    if (phase === 'locked') expect(await d.lockOk()).toBe(true);

    const others = [d.lawyerA.ops, d.aliceBase.wallet, d.bobBase.wallet, await stranger(c)];
    for (const w of others) {
      const r = await c.attempt(w, d.finishTx({ from: w.classicAddress }));
      expect(outcome(r), w.classicAddress).toBe('validated:tecNO_PERMISSION');
    }
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(1);

    if (phase === 'locked') {
      // the gate, with each other account as the submitter: only RELEASER_SEALED fails
      const g = await d.gate();
      expect(g.failing).toEqual([]);
      for (const w of others) {
        const f = checkRelease({ ...g.input, submitter: w.classicAddress });
        expect(
          f.filter((x) => !x.ok).map((x) => x.code),
          w.classicAddress,
        ).toEqual(['RELEASER_SEALED']);
      }
    }
    // control: the sealed releaser finishes
    const ok = await c.attempt(d.lawyerB.ops, d.finishTx());
    expect(outcome(ok)).toBe('validated:tesSUCCESS');
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(0);
  });
});
