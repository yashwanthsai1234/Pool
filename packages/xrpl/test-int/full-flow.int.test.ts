// T-I-01 and T-I-10 (IMPLEMENTATION 2.5): the full flow, phases P0 to P8 of DESIGN 5.2 and 5.3, on a real standalone
// ledger, with scripted roles (roles.ts) and the staged deal (deal.ts, the same script the attack tests use). Every
// slot signs through FROST 2-of-3; there are no stubs.
//
// T-I-01: Ed25519 operations accounts. T-I-10: secp256k1 operations accounts, and lawyer B is replaced by a lawyer
// from another firm after the lock and before the release (DESIGN 5.4).
//
// Chip identity (identityPolicy "chip", profile "production"): the zero-knowledge path is T-I-12 (task 2.9); the
// recorded mock proofs are refused by the production profile (DEVMODE_REFUSED), so they cannot pass this gate.
// The P6 and P7 snapshots read by P2.5-01 were recorded once from this flow (core/test/fixtures/ledger/t-i-01-*.json).
// Source: IMPLEMENTATION.md 2.5; DESIGN.md 5.2, 5.3, 5.4, 7.3
import { readFileSync } from 'node:fs';
import { utf8ToBytes } from '@legx/core/dealcore';
import { allOk, checkLock } from '@legx/core/lockcheck';
import { checkRelease, gateMemo, type ReleaseInput } from '@legx/core/releaseGate';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import xrpl from 'xrpl';
import { deliveredAmount } from '../src/read.ts';
import { type Deal, newDeal } from './deal.ts';
import { type Chain, type Json, makeLawyer, openChain, plainKeyFields, up } from './roles.ts';

const FIXTURES = new URL('../../core/test/fixtures/ledger/', import.meta.url);

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

async function validatedTx(hash: string) {
  const r = await c.client.request({ command: 'tx', transaction: hash });
  expect(r.result.validated).toBe(true);
  return r.result as unknown as { tx_json: Json; meta: Json; validated: boolean; ledger_index: number };
}

/** P0 to P8 on a fresh deal. `replaceLawyerB` swaps lawyer B for one of another firm after the lock (T-I-10). */
async function runFlow(curve: 'ed25519' | 'secp256k1', replaceLawyerB: boolean) {
  const logStart = c.log.length;
  const d = await newDeal(c, 'locked', { curve });

  // the wiped setup key can no longer sign for the shell (DisableMaster)
  const refused = await c.step('P6 the wiped setup key can no longer sign for the shell', async () =>
    c.submitBlob(
      d.shell.sign(await c.client.autofill({ TransactionType: 'AccountSet', Account: d.wallet, Domain: '00' })).tx_blob,
    ),
  );

  let replaced: { oldSlot: Deal['lawyerB']['slot']; oldOps: string; oldMint: string } | undefined;
  if (replaceLawyerB) {
    const oldMint = d.minted.hash;
    const { old } = await c.step('R lawyer B is replaced by a lawyer of another firm', () =>
      d.swapLawyer('LB', makeLawyer('LB', 'Firm C', curve, 'CA-0000003')),
    );
    expect(await d.lockOk()).toBe(true);
    replaced = { oldSlot: old.slot, oldOps: old.ops.classicAddress, oldMint };
  }

  const gate = await c.step('P7 release gate on the real snapshot', () => d.gate());
  expect(gate.failing).toEqual([]);
  const gateRecord = await gate.record();
  const alice = d.alice.wallet.classicAddress;
  const shellBefore = await d.balance(d.wallet);
  const finish = await c.step('P7 step 7 EscrowFinish from the releaser with the gate memo', () =>
    c.send(d.lawyerB.ops, d.finishTx({ leaf: gateRecord.leafHash })),
  );
  const shellAfterFinish = await d.balance(d.wallet);
  const exit = await c.step('P8 step 8 Payment to Bob, 4-of-4 on slot S', () => d.exit('bob'));
  const aliceBefore = await d.balance(alice);
  const closeResult = await c.step('P8 step 9 AccountDelete to Alice, 4-of-4', () => d.closeShell());
  const aliceAfter = await d.balance(alice);
  return {
    d,
    log: c.log.slice(logStart),
    gate,
    gateRecord,
    finish,
    exit,
    closeResult,
    replaced,
    refused,
    balances: { shellBefore, shellAfterFinish, aliceBefore, aliceAfter },
  };
}
type Flow = Awaited<ReturnType<typeof runFlow>>;

/** The assertions both runs share: every step succeeded, both memos read back, the exit delivered the agreed amount. */
async function assertFlow(f: Flow, transactions: number) {
  const { d } = f;
  expect(f.log.length).toBe(transactions);
  expect(f.log.filter((l) => l.result !== 'tesSUCCESS')).toEqual([]);

  // the mint memo and URI read back from a validated ledger (DESIGN 7.3 step 1)
  const mintTx = await validatedTx(d.minted.hash);
  const memo = (mintTx.tx_json.Memos as { Memo: { MemoType: string; MemoData: string } }[])[0]?.Memo;
  expect(memo).toEqual({ MemoType: up(utf8ToBytes('legx/contract-sigs/v1')), MemoData: d.sc.memoHex });
  expect(mintTx.tx_json.URI).toBe(d.sc.uriHex);

  // P2.5-02: the NFT issuer, decoded locally from the NFTokenID of the mint metadata, is lawyerOpsA
  expect(xrpl.parseNFTokenID(String(mintTx.meta.nftoken_id)).Issuer).toBe(d.lawyerA.ops.classicAddress);
  expect(xrpl.parseNFTokenID(d.minted.nftokenId).Issuer).toBe(d.data.lawyerOpsA);

  // the gate memo read back from the validated EscrowFinish (DESIGN 7.3 step 7)
  const finishTx = await validatedTx(f.finish.hash);
  expect((finishTx.tx_json.Memos as unknown[])[0]).toEqual({ Memo: gateMemo(f.gateRecord.leafHash) });
  expect(finishTx.tx_json.Account).toBe(d.data.releaserAccount);
  expect(f.balances.shellAfterFinish - f.balances.shellBefore).toBe(BigInt(f.gate.input.deal.escrow.amountDrops));

  // the exit counts only on tesSUCCESS with delivered_amount equal to the agreed amount (DESIGN 7.5)
  const exitTx = await validatedTx(f.exit.hash);
  expect(deliveredAmount(exitTx.meta as never)).toBe(f.gate.input.deal.escrow.amountDrops);
  expect(f.exit.receiverAfter - f.exit.receiverBefore).toBe(BigInt(f.gate.input.deal.escrow.amountDrops));

  // the wallet is closed and its balance went to Alice
  await expect(
    c.client.request({ command: 'account_info', account: d.wallet, ledger_index: 'validated' }),
  ).rejects.toMatchObject({ data: { error: 'actNotFound' } });
  expect(f.balances.aliceAfter).toBeGreaterThan(f.balances.aliceBefore);
  expect((await validatedTx(f.closeResult.hash)).meta.TransactionResult).toBe('tesSUCCESS');

  // P2.5-03: no plain-key signer for any of the four slots
  for (const s of d.slots()) expect(plainKeyFields(s, s.name)).toEqual([]);
  expect(plainKeyFields({ wallet: d.alice.wallet }, 'canary')).toEqual(['canary.wallet']);

  expect(f.refused).toEqual({ status: 'rejected', result: 'tefMASTER_DISABLED' });
}

describe('T-I-01 full flow, Ed25519 operations accounts', () => {
  it('P0 to P8: every step tesSUCCESS, both memos read back, delivered_amount matches', async () => {
    const f = await runFlow('ed25519', false);
    await assertFlow(f, 27); // 5 funded accounts, 0a and 0b twice, mint, steps 2 and 3, 12 lock steps, 7, 8, 9
    expect(f.d.lawyerA.ops.publicKey.startsWith('ED')).toBe(true);
    expect(f.replaced).toBeUndefined();

    // P2.5-04: the same input with one frost.dkg.completed test signature removed fails SLOT_SETUP_OK (and what rests on it)
    const tampered = structuredClone(f.gate.input) as { records: ReleaseInput['records'] };
    const lb = f.d.lawyerB.slot;
    tampered.records.dkgCompleted.LB = await f.d.ev.event(
      'frost.dkg.completed',
      { ...lb.dkg, test_sigs: (lb.dkg.test_sigs as string[]).slice(0, 2) },
      lb,
      'lawyerB',
    );
    const failing = checkRelease(tampered as unknown as ReleaseInput).filter((x) => !x.ok);
    // The records signed by lawyer B's holders (Bob's passport and onboarding, OD-21) rest on that slot's DKG record, so
    // they fail with it; nothing about slots LA, A or B does.
    expect(failing.map((x) => x.code)).toEqual(['PASSPORT_B_OK', 'ONBOARDING_OK', 'SLOT_SETUP_OK']);
  });

  it('P2.5-01 the recorded snapshots are real and pass the lock checker offline', () => {
    for (const name of ['p6', 'p7']) {
      const file = JSON.parse(readFileSync(new URL(`t-i-01-${name}.json`, FIXTURES), 'utf8'));
      const findings = checkLock(file.account_info, file.account_objects, {
        ...file.expected,
        escrow: { ...file.expected.escrow, minCancelAfter: file.expected.minCancelAfter },
      });
      expect(allOk(findings)).toBe(true);
      expect(file.expected.domainHex).toBe(file.account_info.Domain);
    }
  });
});

describe('T-I-10 full flow, secp256k1 operations accounts and a replaced lawyer', () => {
  it('lawyer B is replaced before release: the checker passes again, the new group key signs the release', async () => {
    const f = await runFlow('secp256k1', true);
    await assertFlow(f, 35); // T-I-01's 27, plus lawyer C: fund, 0a, 0b, mint, and four 4-of-4 multisigned changes
    expect(f.d.lawyerA.ops.publicKey.startsWith('ED')).toBe(false);
    const old = f.replaced as NonNullable<Flow['replaced']>;
    expect(f.d.lawyerB.slot.pubHex).not.toBe(old.oldSlot.pubHex);
    expect(f.d.lawyerB.ops.classicAddress).not.toBe(old.oldOps);
    expect(f.d.minted.hash).not.toBe(old.oldMint);
    // the release record carries slot LB's new group key signature (the gate refuses any other key)
    expect(f.d.data.lawyerPubB).toBe(f.d.lawyerB.slot.pubHex);
    expect(f.d.data.releaserAccount).toBe(f.d.lawyerB.ops.classicAddress);
    expect(f.gate.findings.every((x) => x.ok)).toBe(true);
    // the old releaser can no longer be the submitter: the sealed releaserAccount changed
    const stale = checkRelease({ ...f.gate.input, submitter: old.oldOps }).filter((x) => !x.ok);
    expect(stale.map((x) => x.code)).toEqual(['RELEASER_SEALED']);
  });
});
