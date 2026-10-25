// A complete slot set-up through the relay: DKG, then the test signature of each of the three pairs (DESIGN 6.4 rule 4).

import type { FrostMsg } from '@legx/core/frost';
import { type DkgKey, dkgCompletedRecord, testSignCheck, testSignMessage } from '@legx/core/frostDkg';
import { dkgCompletedData } from '../../src/events.ts';
import type { World } from './world.ts';

export const PAIRS: [number, number][] = [
  [1, 2],
  [1, 3],
  [2, 3],
];

export async function slotSetup(w: World) {
  const sessionId = await w.relay.openSession({
    dealId: w.dealId,
    slot: w.slot,
    purpose: 'dkg',
    participants: w.participants(),
  });
  const runs = await Promise.all([1, 2, 3].map((i) => w.holder(i).dkg(sessionId)));
  const keys = runs.map((r) => r.key) as DkgKey[];
  const pub = (keys[0] as DkgKey).public;
  const ctx = (runs[0] as (typeof runs)[0]).ctx;
  const testSignatures: { pair: [number, number]; sig: Uint8Array }[] = [];
  for (const pair of PAIRS) {
    const ids = pair.map((i) => (w.members[i - 1] as { info: { identifier: string } }).info.identifier);
    const session = await w.relay.openSession({
      dealId: w.dealId,
      slot: w.slot,
      purpose: 'sign',
      participants: w.participants(),
      pair: ids as [string, string],
    });
    const msg = testSignMessage(ctx, pub, pair);
    const sigs = await Promise.all(
      pair.map((i) =>
        w.holder(i).sign(session, {
          msg,
          kind: 'tagged',
          share: (keys[i - 1] as DkgKey).secret,
          pub,
          pair,
          check: (m, l) => testSignCheck(ctx, pub, i)(m, l),
        }),
      ),
    );
    testSignatures.push({ pair, sig: sigs[0] as Uint8Array });
  }
  const r = runs[0] as (typeof runs)[0];
  const record = dkgCompletedRecord({ ctx, pub, round1: r.round1 as FrostMsg[], echoes: r.echoes, testSignatures });
  const data = dkgCompletedData(
    record,
    ctx,
    w.members.map((m) => m.info),
    pub,
  );
  return { sessionId, ctx, keys, pub, record, data, testSignatures };
}
