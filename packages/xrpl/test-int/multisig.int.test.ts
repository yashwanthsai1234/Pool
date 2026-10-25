// Task 2.4 against the standalone ledger, with FROST-signed slots (2 of 3 shares per slot, OD-4):
// P2.4-01..04, T-A-12, T-A-18, and a race test (4 signers, 2 exit candidates, random order).
import type { SubmitResult } from '@legx/contracts/ports';
import { checkLock } from '@legx/core/lockcheck';
import fc from 'fast-check';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client, SubmittableTransaction } from 'xrpl';
import xrpl from 'xrpl';
import { type BuildCtx, build5a, build5g, build8, buildTicketCreate } from '../src/builders/index.ts';
import { connect } from '../src/connect.ts';
import { standaloneEnv } from '../src/env.ts';
import { fundAccount } from '../src/fund.ts';
import { readFees } from '../src/ledger.ts';
import { combine, exitOutcome, nextSlot, prepareExit, ticketSlots } from '../src/multisig.ts';
import { prepare } from '../src/prepare.ts';
import { rpcOf } from '../src/read.ts';
import { submitReliable } from '../src/submit.ts';
import { type FrostSlot, makeSlots, slotSign } from './frostSlots.ts';
import { closer } from './support.ts';

const env = standaloneEnv();
const opts = { pollMs: 50, timeoutMs: 60_000 };
let client: Client;
let ticker: Client;
let stop: () => Promise<void>;
let slots: FrostSlot[];
let ctx: BuildCtx;
const addresses = () => slots.map((s) => s.address);

beforeAll(async () => {
  client = await connect(env);
  ticker = await connect(env);
  stop = closer(ticker);
  slots = await makeSlots();
  ctx = { network: 'standalone', baseFeeDrops: (await readFees(client)).baseFeeDrops };
});
afterAll(async () => {
  await stop();
  await ticker.disconnect();
  await client.disconnect();
});

const rpc = () => rpcOf(client);
const submit = (blob: string) => submitReliable(rpc(), blob, opts);

/** A deal wallet locked as in step 5: a 4-of-4 FROST signer list and the master key disabled. */
async function lockedWallet() {
  const shell = await fundAccount(env, client, 100);
  for (const tx of [
    build5a({ shell: shell.classicAddress, signers: addresses() }, ctx),
    build5g({ shell: shell.classicAddress }, ctx),
  ]) {
    const r = await submit(shell.sign(await client.autofill(tx)).tx_blob);
    expect(r).toMatchObject({ status: 'validated', result: 'tesSUCCESS' });
  }
  return shell;
}

/** All four slots sign the same prepared transaction. `n` limits how many sign. */
const collect = (tx: SubmittableTransaction, n = 4) => slots.slice(0, n).map((s) => slotSign(s, tx as never));
const exitTx = (
  shell: string,
  payout: string,
  slot: { sequence: number } | { ticketSequence: number },
  amount = '10000000',
) => prepareExit(build8({ shell, payout, amount, slot }, ctx), { client, signers: 4 });
const wallet = () => fundAccount(env, client, 20);

describe('combine and the multisigned exit', () => {
  it('P2.4-01 four FROST slots sign; combine sorts by AccountID; rippled accepts it', async () => {
    const [shell, bob] = [await lockedWallet(), await wallet()];
    const { sequence } = await nextSlot(rpc(), shell.classicAddress);
    const tx = await exitTx(shell.classicAddress, bob.classicAddress, { sequence });
    const blobs = collect(tx).reverse();
    const blob = combine(blobs, addresses());
    const ids = (xrpl.decode(blob).Signers as { Signer: { Account: string } }[]).map((s) =>
      Buffer.from(xrpl.decodeAccountID(s.Signer.Account)).toString('hex'),
    );
    expect(ids).toEqual([...ids].sort());
    expect(blob).toBe(xrpl.multisign(blobs)); // second implementation: xrpl.js
    expect(await submit(blob)).toMatchObject({ status: 'validated', result: 'tesSUCCESS' });
  });

  it('P2.4-02 three signatures are refused before submit; rippled refuses them too', async () => {
    const [shell, bob] = [await lockedWallet(), await wallet()];
    const { sequence } = await nextSlot(rpc(), shell.classicAddress);
    const tx = await exitTx(shell.classicAddress, bob.classicAddress, { sequence });
    const three = collect(tx, 3);
    expect(() => combine(three, addresses())).toThrow(/signer list/);
    expect(await submit(xrpl.multisign(three))).toMatchObject({ status: 'rejected', result: 'tefBAD_QUORUM' });
    expect((await nextSlot(rpc(), shell.classicAddress)).sequence).toBe(sequence);
  });

  it('refuses a transaction with no LastLedgerSequence, a mixed body and a wrong signer set', async () => {
    const [shell, bob] = [await lockedWallet(), await wallet()];
    const { sequence } = await nextSlot(rpc(), shell.classicAddress);
    const tx = await exitTx(shell.classicAddress, bob.classicAddress, { sequence });
    const { LastLedgerSequence: _l, ...open } = tx;
    expect(() => combine(collect(open as SubmittableTransaction), addresses())).toThrow(/LastLedgerSequence/);
    const other = await exitTx(shell.classicAddress, bob.classicAddress, { sequence }, '10000001');
    const mixed = [...collect(tx, 3), slotSign(slots[3] as FrostSlot, other as never)];
    expect(() => combine(mixed, addresses())).toThrow(/same transaction/);
    expect(() => combine(collect(tx), addresses().slice(1))).toThrow(/signer list/);
    expect(() => combine([], addresses())).toThrow(/no blobs/);
  });

  it('exits are signed with 5 to 10 times the fee (OD-11)', async () => {
    const shell = await lockedWallet();
    const bob = await wallet();
    const t = (m?: number) =>
      prepareExit(
        build8({ shell: shell.classicAddress, payout: bob.classicAddress, amount: '1', slot: { sequence: 9 } }, ctx),
        {
          client,
          signers: 4,
          ...(m === undefined ? {} : { feeMultiplier: m }),
        },
      );
    const base = (ctx.baseFeeDrops as number) * 5;
    expect(Number((await t()).Fee)).toBe(base * 5);
    expect(Number((await t(10)).Fee)).toBe(base * 10);
    await expect(t(4)).rejects.toThrow(/5 to 10/);
    await expect(t(11)).rejects.toThrow(/5 to 10/);
    expect((await t()).LastLedgerSequence).toBeGreaterThan(
      (await client.getLedgerIndex()) + 1000, // the collection window, not the 20-ledger one
    );
  });
});

describe('the exit slot', () => {
  it('T-A-12 pay Bob and refund Alice, both fully signed on slot S: exactly one validates, the other gets tefPAST_SEQ', async () => {
    const [shell, alice, bob] = [await lockedWallet(), await wallet(), await wallet()];
    const { sequence } = await nextSlot(rpc(), shell.classicAddress);
    const sign = async (to: string) =>
      combine(collect(await exitTx(shell.classicAddress, to, { sequence })), addresses());
    const [payBob, refund] = [await sign(bob.classicAddress), await sign(alice.classicAddress)];
    const results = await Promise.all([submit(payBob), submit(refund)]);
    const won = results.filter((r) => r.status === 'validated');
    const lost = results.filter((r) => r.status === 'rejected');
    expect(won).toHaveLength(1);
    expect(lost).toEqual([{ status: 'rejected', result: 'tefPAST_SEQ' }]);
    expect(await exitOutcome(rpc(), shell.classicAddress, { sequence }, results[1] as SubmitResult)).toMatchObject({
      done: results[1]?.status === 'validated',
    });
  });

  it('P2.4-03 a tec result spends slot S; the helper returns S+1', async () => {
    const [shell, bob] = [await lockedWallet(), await wallet()];
    const needTag = await submit(
      bob.sign(
        await client.autofill({
          TransactionType: 'AccountSet',
          Account: bob.classicAddress,
          SetFlag: xrpl.AccountSetAsfFlags.asfRequireDest,
        }),
      ).tx_blob,
    );
    expect(needTag).toMatchObject({ result: 'tesSUCCESS' });
    const { sequence } = await nextSlot(rpc(), shell.classicAddress);
    const tx = await exitTx(shell.classicAddress, bob.classicAddress, { sequence }); // no destination tag
    const r = await submit(combine(collect(tx), addresses()));
    expect(r).toMatchObject({ status: 'validated', result: 'tecDST_TAG_NEEDED' });
    expect(await exitOutcome(rpc(), shell.classicAddress, { sequence }, r)).toEqual({
      done: false,
      slotUsed: true,
      next: { sequence: sequence + 1 },
    });
    // The old candidates are void: replaying the same blob cannot pay.
    const again = await submit(combine(collect(tx), addresses()));
    expect(again.status === 'validated' ? again.result : again.status).toBe('tecDST_TAG_NEEDED');
    const retry = await exitTx(shell.classicAddress, `${bob.classicAddress}`, { sequence: sequence + 1 });
    expect(retry.Sequence).toBe(sequence + 1);
  });

  it('P2.4-04 a Ticket: 4-of-4 TicketCreate, then both candidates on that ticket; one validates', async () => {
    const [shell, alice, bob] = [await lockedWallet(), await wallet(), await wallet()];
    const { sequence } = await nextSlot(rpc(), shell.classicAddress);
    const create = await prepare(buildTicketCreate({ shell: shell.classicAddress, count: 1 }, ctx), {
      client,
      signers: 4,
    });
    expect(await submit(combine(collect(create), addresses()))).toMatchObject({ result: 'tesSUCCESS' });
    const tickets = await ticketSlots(rpc(), shell.classicAddress);
    expect(tickets).toEqual([{ ticketSequence: sequence + 1 }]);
    const snap = async () => {
      const [info, objs] = await Promise.all([
        client.request({ command: 'account_info', account: shell.classicAddress, ledger_index: 'validated' }),
        client.request({ command: 'account_objects', account: shell.classicAddress, ledger_index: 'validated' }),
      ]);
      return [info.result.account_data, objs.result.account_objects] as const;
    };
    const ticketFinding = async (allowed: number[]) => {
      const [acct, objs] = await snap();
      return checkLock(acct as never, objs as never, { deal: {}, allowedTicketSequences: allowed } as never).find(
        (f) => f.code === 'TICKET_ALLOWED',
      );
    };
    expect((await ticketFinding([]))?.ok).toBe(false); // before funding: no ticket is allowed
    expect((await ticketFinding([sequence + 1]))?.ok).toBe(true);
    const slot = { ticketSequence: sequence + 1 };
    const sign = async (to: string) => combine(collect(await exitTx(shell.classicAddress, to, slot)), addresses());
    const results = await Promise.all([
      submit(await sign(bob.classicAddress)),
      submit(await sign(alice.classicAddress)),
    ]);
    expect(results.filter((r) => r.status === 'validated')).toHaveLength(1);
    expect(results.filter((r) => r.status === 'rejected')).toEqual([{ status: 'rejected', result: 'tefNO_TICKET' }]);
    expect(await ticketSlots(rpc(), shell.classicAddress)).toEqual([]);
  });

  it('T-A-18 after the lock, a single-signed SignerListSet or SetRegularKey is rejected', async () => {
    const shell = await lockedWallet();
    const stranger = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const txs = [
      {
        TransactionType: 'SignerListSet',
        SignerQuorum: 1,
        SignerEntries: [{ SignerEntry: { Account: stranger.classicAddress, SignerWeight: 1 } }],
      },
      { TransactionType: 'SetRegularKey', RegularKey: stranger.classicAddress },
    ];
    const before = (await nextSlot(rpc(), shell.classicAddress)).sequence;
    for (const t of txs) {
      const filled = await client.autofill({ Account: shell.classicAddress, ...t } as SubmittableTransaction);
      // signed by the (disabled) master key, and by an unrelated key claiming the account
      const byMaster = await submit(shell.sign(filled).tx_blob);
      expect(byMaster).toEqual({ status: 'rejected', result: 'tefMASTER_DISABLED' });
      const byStranger = await submit(stranger.sign(filled).tx_blob);
      expect(byStranger.status).toBe('rejected');
    }
    expect((await nextSlot(rpc(), shell.classicAddress)).sequence).toBe(before);
  });
});

describe('race: 4 signers and 2 exit candidates arrive in random orders', () => {
  interface Model {
    signed: [Set<number>, Set<number>];
  }
  interface Real {
    txs: SubmittableTransaction[];
    blobs: [string[], string[]];
    results: { candidate: number; result: SubmitResult }[];
  }

  class Sign implements fc.AsyncCommand<Model, Real> {
    candidate: number;
    signer: number;
    constructor(candidate: number, signer: number) {
      this.candidate = candidate;
      this.signer = signer;
    }
    check = () => true;
    async run(m: Model, r: Real) {
      await Promise.resolve();
      (r.blobs[this.candidate] as string[]).push(
        slotSign(slots[this.signer] as FrostSlot, r.txs[this.candidate] as never),
      );
      (m.signed[this.candidate] as Set<number>).add(this.signer);
    }
    toString = () => `sign(c${this.candidate}, s${this.signer})`;
  }

  class Submit implements fc.AsyncCommand<Model, Real> {
    candidate: number;
    constructor(candidate: number) {
      this.candidate = candidate;
    }
    check = () => true;
    async run(m: Model, r: Real) {
      const have = r.blobs[this.candidate] as string[];
      if ((m.signed[this.candidate] as Set<number>).size < 4) {
        // fewer than 4 signatures: refused before anything is sent
        expect(() => combine(have, addresses())).toThrow();
        return;
      }
      const result = await submit(combine(have, addresses()));
      r.results.push({ candidate: this.candidate, result });
    }
    toString = () => `submit(c${this.candidate})`;
  }

  it('exactly one candidate validates, the other gets tefPAST_SEQ; an unsigned candidate never reaches the ledger', async () => {
    const [alice, bob] = [await wallet(), await wallet()];
    // Every signer for both candidates, plus submit attempts (each twice), in a random subset and order.
    const all = [0, 1].flatMap((c) => [...[0, 1, 2, 3].map((i) => new Sign(c, i)), new Submit(c), new Submit(c)]);
    const arbCommands = fc.shuffledSubarray(all, { minLength: 8 });
    await fc.assert(
      fc.asyncProperty(fc.scheduler(), arbCommands, async (s, cmds) => {
        const shell = await lockedWallet();
        const { sequence } = await nextSlot(rpc(), shell.classicAddress);
        const txs = await Promise.all(
          [alice, bob].map((w) => exitTx(shell.classicAddress, w.classicAddress, { sequence })),
        );
        const real: Real = { txs, blobs: [[], []], results: [] };
        const model: Model = { signed: [new Set(), new Set()] };
        await fc.scheduledModelRun(s, () => ({ model, real }), cmds);
        // Then the stragglers sign and both fully signed candidates are submitted together (T-A-12 in random company).
        for (const c of [0, 1])
          for (const i of [0, 1, 2, 3]) if (!model.signed[c]?.has(i)) await new Sign(c, i).run(model, real);
        const finals = await Promise.all([new Submit(0), new Submit(1)].map((x) => x.run(model, real)));
        expect(finals).toHaveLength(2);
        const won = new Set(real.results.filter((x) => x.result.status === 'validated').map((x) => x.candidate));
        expect(won.size).toBe(1);
        for (const { candidate, result } of real.results)
          if (!won.has(candidate)) expect(result).toEqual({ status: 'rejected', result: 'tefPAST_SEQ' });
        const used = (await nextSlot(rpc(), shell.classicAddress)).sequence > sequence;
        expect(used).toBe(true);
      }),
      { numRuns: 12 },
    );
  });
});
