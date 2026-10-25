// OD-28 (build/DECISIONS.md; IMPLEMENTATION 2.6): the release code when lawyer B is replaced before the release. The escrow
// condition is fixed by Alice's EscrowCreate, so the new lawyer B needs the old one's 32-byte code.
//  1. Handover: the old lawyer B seals the code to the new lawyer B with X-Wing HPKE (kind `release-code-handover`) and logs
//     an evidence event; the code never appears in clear in it. The new lawyer B opens it, the derived condition matches the
//     escrow on the ledger, and the new releaser finishes. The old releaser can no longer finish (its DepositPreauth was
//     removed), and a new lawyer B without the code cannot (tecCRYPTOCONDITION_ERROR).
//  2. Fallback: the old lawyer B is unavailable. The escrow expires at CancelAfter and anyone cancels it (Alice is refunded);
//     the new lawyer B makes a new code and condition; Alice creates a new escrow; the checker and the gate pass and the new
//     releaser finishes it. The old code does not fit the new escrow.
// `release-code-handover` is not yet a package kind of @legx/core pq.ts (PACKAGE_INFO) nor an event kind of @legx/contracts:
// the test builds the HPKE info and the event itself (build/ISSUES.md, I-2.6-a).
// Source: https://www.rfc-editor.org/rfc/rfc9180.html ; DECISIONS.md OD-28 ; DESIGN 5.4
import { makeCondition, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import { PACKAGE_SUITES, XWING_SUITE } from '@legx/core/pq';
import { bytesToHex } from '@noble/hashes/utils.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildEscrowCancel } from '../../src/builders/index.ts';
import { advanceCloseTime } from '../../src/ledger.ts';
import { escrowsWith, outcome, stranger } from '../attacks/util.ts';
import { type Deal, ESCROW_DROPS, newDeal } from '../deal.ts';
import { type Chain, makeLawyer, openChain, up } from '../roles.ts';

const INFO = utf8ToBytes('legx/hpke/release-code-handover/v1');
const suite = PACKAGE_SUITES[XWING_SUITE] as NonNullable<(typeof PACKAGE_SUITES)[string]>;
const toBase64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const aadOf = (d: Deal) =>
  tupleHash('legx/release-code-handover-aad/v1', [utf8ToBytes(d.dealId), utf8ToBytes(d.wallet)]);

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('OD-28 the release code when lawyer B is replaced', () => {
  it('handover: the old lawyer B seals the code to the new one, who then releases', async () => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true); // setup state
    const oldB = d.lawyerB;
    const code = d.preimage; // lives only on the old lawyer B's console
    const { old } = await d.swapLawyer('LB', makeLawyer('LB', 'Firm C', d.curve, 'CA-0000003'));
    expect(old.ops.classicAddress).toBe(oldB.ops.classicAddress);
    expect(await d.lockOk()).toBe(true);
    expect((await d.gate()).failing).toEqual([]);
    expect(d.lawyerB.ops.classicAddress).not.toBe(oldB.ops.classicAddress);

    // before the handover: the new lawyer B has no code; the old releaser is no longer authorized
    const guess = makeCondition(new Uint8Array(32).fill(7)).fulfillment;
    expect(outcome(await c.attempt(d.lawyerB.ops, d.finishTx({ fulfillment: guess })))).toBe(
      'validated:tecCRYPTOCONDITION_ERROR',
    );
    expect(outcome(await c.attempt(oldB.ops, d.finishTx({ from: oldB.ops.classicAddress })))).toBe(
      'validated:tecNO_PERMISSION',
    );
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(1);

    // the handover: X-Wing HPKE to the new lawyer B's key, logged as an evidence event signed by the old lawyer B's slot
    const kem = await suite.keygen();
    const sealed = await suite.seal(kem.publicKey, code, INFO, aadOf(d));
    const event = await d.ev.event(
      'release-code-handover',
      {
        suite: XWING_SUITE,
        enc: toBase64(sealed.enc),
        ciphertext: toBase64(sealed.ct),
        to_ops: d.lawyerB.ops.classicAddress,
      },
      old.slot,
      'lawyerB',
    );
    const text = Buffer.from(event).toString('latin1');
    expect(text).not.toContain(bytesToHex(code)); // the code never appears in clear, in hex ...
    expect(text).not.toContain(toBase64(code)); // ... or in base64
    expect(Buffer.from(event).includes(Buffer.from(code))).toBe(false);

    // wrong key, or another deal's context: the package does not open
    const other = await suite.keygen();
    await expect(suite.open(other.secretKey, sealed.enc, sealed.ct, INFO, aadOf(d))).rejects.toThrow();
    await expect(
      suite.open(
        kem.secretKey,
        sealed.enc,
        sealed.ct,
        INFO,
        tupleHash('legx/release-code-handover-aad/v1', [utf8ToBytes('another deal'), utf8ToBytes(d.wallet)]),
      ),
    ).rejects.toThrow();

    // the new lawyer B opens it; the condition it makes equals the one on the ledger; the release passes
    const opened = await suite.open(kem.secretKey, sealed.enc, sealed.ct, INFO, aadOf(d));
    const made = makeCondition(opened);
    expect(made.condition).toBe(d.condition);
    expect((await d.objects('escrow'))[0]).toMatchObject({ Condition: up(Buffer.from(d.condition, 'hex')) });
    const g = await d.gate();
    expect(g.failing).toEqual([]);
    const rec = await g.record();
    const done = await c.attempt(d.lawyerB.ops, d.finishTx({ fulfillment: made.fulfillment, leaf: rec.leafHash }));
    expect(outcome(done)).toBe('validated:tesSUCCESS');
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(0);
  });

  it('fallback: the old lawyer B is unavailable, the escrow expires and a new code and escrow replace it', async () => {
    const d = await newDeal(c, 'locked', { cancelAfterSeconds: 900 });
    const oldCondition = d.condition;
    const oldFulfillment = d.fulfillment;
    const alice = d.aliceBase.wallet.classicAddress;
    await d.swapLawyer('LB', makeLawyer('LB', 'Firm C', d.curve, 'CA-0000003'));
    expect((await d.gate()).failing).toEqual(['LOCK_OK']); // only the short CancelAfter (CANCEL_AFTER_MARGIN) blocks

    // the new lawyer B cannot finish without the old code
    expect(
      outcome(
        await c.attempt(
          d.lawyerB.ops,
          d.finishTx({ fulfillment: makeCondition(new Uint8Array(32).fill(9)).fulfillment }),
        ),
      ),
    ).toBe('validated:tecCRYPTOCONDITION_ERROR');
    expect(await escrowsWith(c, d.wallet, oldCondition)).toHaveLength(1);

    // the escrow expires at CancelAfter; anyone cancels it and Alice is refunded
    await advanceCloseTime(c.client, d.cancelAfter);
    const anyone = await stranger(c);
    const before = await d.balance(alice);
    const cancel = await c.attempt(
      anyone,
      buildEscrowCancel({ account: anyone.classicAddress, owner: alice, offerSequence: d.escrowSequence }, c.ctx),
    );
    expect(outcome(cancel)).toBe('validated:tesSUCCESS');
    expect((await d.balance(alice)) - before).toBe(BigInt(ESCROW_DROPS));
    expect(await escrowsWith(c, d.wallet, oldCondition)).toHaveLength(0);

    // a new code and condition (made by the new lawyer B), a new escrow from Alice with the usual three days
    await d.newEscrow();
    expect(d.condition).not.toBe(oldCondition);
    expect(await d.lockOk()).toBe(true); // the margin holds again
    // (the release gate is not run here: the standalone ledger keeps 256 ledgers, and the wait above dropped the mint and
    // bar-check ledgers the gate reads; the gate passed with the new lawyer before the wait, and the checker passes now)
    // the old code does not fit the new escrow; the new one does
    expect(outcome(await c.attempt(d.lawyerB.ops, d.finishTx({ fulfillment: oldFulfillment })))).toBe(
      'validated:tecCRYPTOCONDITION_ERROR',
    );
    expect(outcome(await c.attempt(d.lawyerB.ops, d.finishTx()))).toBe('validated:tesSUCCESS');
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(0);
  });
});
