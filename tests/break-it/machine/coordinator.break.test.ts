// Break-it 5.7: the coordinator's events.append applies state transitions on ledger facts it does not fully bind to
// THIS deal, and accepts setup events in any state.
// Source: DESIGN 7.5 step 5 (only validated ledger facts of the deal count), DESIGN 5.1 (state machine), DESIGN 6.6
//         (the seal is fixed once the wallet is locked)
// Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowfinish (Owner + OfferSequence name the escrow)
import { afterAll, describe, expect, it } from 'vitest';
import {
  AMOUNT,
  account,
  CONDITION,
  gatePassed,
  identityOnboarded,
  joinAll,
  ok,
  toFunded,
  toVerified,
} from '../../../services/coordinator/test/support/lifecycle.ts';
import {
  addTx,
  makeWorld,
  newDeal,
  post,
  rndHex,
  type World,
} from '../../../services/coordinator/test/support/world.ts';

const worlds: World[] = [];
const fresh = async () => {
  const w = await makeWorld();
  worlds.push(w);
  return w;
};
afterAll(async () => {
  for (const w of worlds) await (w as { close?: () => Promise<void> }).close?.();
});
const OTHER = 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe'; // an unrelated account

describe('I-S-M1 release.performed accepts an EscrowFinish of another escrow', () => {
  it('an EscrowFinish by the releaser for a different Owner/OfferSequence does not move the deal to FUNDED', async () => {
    const w = await fresh();
    const id = await newDeal(w);
    await toVerified(w, id);
    const g = ok(await gatePassed(w, id)) as { leafHash: string };
    const finish = addTx(w, 'EscrowFinish', w.addr.opsB, { Owner: OTHER, OfferSequence: 99 });
    const r = await post(w, id, 'lawyerB', 'release.performed', {
      finish_tx_hash: finish,
      ledger_index: w.ledger.index,
      gate_leaf_hash: g.leafHash,
    });
    expect(r.status).toBe(422);
  });
});

describe('I-S-M2 escrow.created trusts the claimed amount, condition and CancelAfter instead of the transaction', () => {
  it('an EscrowCreate of 1 drop with another condition and CancelAfter is refused', async () => {
    const w = await fresh();
    const id = await newDeal(w);
    await joinAll(w, id);
    ok(
      await post(w, id, 'alice', 'shell.opened', {
        wallet_address: w.addr.shell,
        funding_tx_hash: addTx(w, 'Payment', account(w, 'alice'), { Destination: w.addr.shell }),
      }),
    );
    const tx = addTx(w, 'EscrowCreate', account(w, 'alice'), {
      Destination: w.addr.shell,
      Amount: '1',
      Condition: `A0258020${'DD'.repeat(32)}810120`,
      CancelAfter: w.ledger.closeTime + 10,
    });
    const r = await post(w, id, 'alice', 'escrow.created', {
      escrow: {
        owner: account(w, 'alice'),
        offer_sequence: 7,
        amount_drops: AMOUNT,
        condition: CONDITION,
        cancel_after: w.ledger.closeTime + 200_000,
      },
      tx_hash: tx,
    });
    expect(r.status).toBe(422);
  });
});

describe('I-S-M3 escrow.cancelled accepts an EscrowCancel of another escrow', () => {
  it('an unrelated EscrowCancel after CancelAfter does not expire this deal', async () => {
    const w = await fresh();
    const id = await newDeal(w);
    await toVerified(w, id);
    w.ledger.closeTime += 300_000;
    const r = await post(w, id, 'alice', 'escrow.cancelled', {
      tx_hash: addTx(w, 'EscrowCancel', OTHER, { Owner: OTHER, OfferSequence: 99 }),
    });
    expect(r.status).toBe(422);
  });
});

describe('I-S-M4 setup events are accepted after the seal is fixed', () => {
  it('a new key.bound for slot A after VERIFIED is refused (it would change the seal the gate recomputes)', async () => {
    const w = await fresh();
    const id = await newDeal(w);
    await toVerified(w, id);
    const r = await post(w, id, 'alice', 'key.bound', {
      slot: 'A',
      xrpl_pubkey: `ED${rndHex(32).toUpperCase()}`,
      commitment: rndHex(32),
      binding_sig: rndHex(64),
    });
    expect(r.status).toBeGreaterThanOrEqual(400);
  });

  it('a new identity.onboarded for side A after FUNDED is refused (it rewrites the identity method the seal names)', async () => {
    const w = await fresh();
    const id = await newDeal(w);
    await toFunded(w, id);
    const r = await identityOnboarded(w, id, 'A');
    expect(r.status).toBeGreaterThanOrEqual(400);
  });
});
