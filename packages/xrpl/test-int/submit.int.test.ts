// Task 2.2 against the standalone ledger: reliable submission (P2.2-01..04, T-A-14, T-A-15), 20 accounts at once,
// and random WebSocket drops under a fast-check scheduler.
import fc from 'fast-check';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'xrpl';
import xrpl from 'xrpl';
import { connect } from '../src/connect.ts';
import { standaloneEnv } from '../src/env.ts';
import { fundAccount } from '../src/fund.ts';
import { type Rpc, rpcOf } from '../src/read.ts';
import { submitReliable } from '../src/submit.ts';
import { accountSequence, closer, disconnectQuietly, signed, startProxy, type TcpProxy } from './support.ts';

const env = standaloneEnv();
const opts = { pollMs: 50, timeoutMs: 60_000 };
let client: Client;
let ticker: Client;
let stop: () => Promise<void>;

beforeAll(async () => {
  client = await connect(env);
  ticker = await connect(env);
  stop = closer(ticker);
});
afterAll(async () => {
  await stop();
  await ticker.disconnect();
  await client.disconnect();
});

const validatedLedger = async () =>
  (await client.request({ command: 'ledger', ledger_index: 'validated' })).result.ledger_index;
const pay = (to: string, drops = '1000000') => ({ TransactionType: 'Payment', Destination: to, Amount: drops });

describe('submitReliable on the standalone ledger', () => {
  it('P2.2-01 a good transaction: validated tesSUCCESS with ledgerIndex, hash and meta that match tx', async () => {
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const s = await signed(client, a, pay(b.classicAddress));
    const r = await submitReliable(rpcOf(client), s.blob, opts);
    expect(r).toMatchObject({ status: 'validated', result: 'tesSUCCESS', hash: s.hash });
    const t = await client.request({ command: 'tx', transaction: s.hash });
    expect(t.result.validated).toBe(true);
    if (r.status !== 'validated') throw new Error('unreachable');
    expect(r.ledgerIndex).toBe(t.result.ledger_index);
    expect(r.meta).toEqual(t.result.meta);
  });

  it('P2.2-02 a tec result is final and validated; the sequence was used', async () => {
    const [a, b] = [await fundAccount(env, client, 30), await fundAccount(env, client)];
    const s = await signed(client, a, pay(b.classicAddress, '29000000')); // more than the spendable balance
    const r = await submitReliable(rpcOf(client), s.blob, opts);
    expect(r).toMatchObject({ status: 'validated', result: 'tecUNFUNDED_PAYMENT', hash: s.hash });
    expect(await accountSequence(client, a.classicAddress)).toBe((s.tx.Sequence ?? 0) + 1);
  });

  it('P2.2-03 tem: final, not applied, with the engine code', async () => {
    const a = await fundAccount(env, client);
    const s = await signed(client, a, pay(a.classicAddress)); // XRP to self
    expect(await submitReliable(rpcOf(client), s.blob, opts)).toEqual({ status: 'rejected', result: 'temREDUNDANT' });
    expect(await accountSequence(client, a.classicAddress)).toBe(s.tx.Sequence);
  });

  it('P2.2-03 tef: a key with no authority over the account is tefBAD_AUTH, final and not applied', async () => {
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const filled = await client.autofill({ ...pay(b.classicAddress), Account: a.classicAddress } as never);
    const blob = b.sign(filled).tx_blob; // b signs for a
    expect(await submitReliable(rpcOf(client), blob, opts)).toEqual({ status: 'rejected', result: 'tefBAD_AUTH' });
  });

  it('T-A-14 replaying a validated blob: the engine says tefPAST_SEQ, and the answer is the original validation', async () => {
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const s = await signed(client, a, pay(b.classicAddress));
    const first = await submitReliable(rpcOf(client), s.blob, opts);
    const balance = await client.getXrpBalance(b.classicAddress);
    const raw = await client.request({ command: 'submit', tx_blob: s.blob });
    expect(raw.result.engine_result).toBe('tefPAST_SEQ');
    expect(await submitReliable(rpcOf(client), s.blob, opts)).toEqual(first);
    expect(await client.getXrpBalance(b.classicAddress)).toBe(balance);
  });

  it('T-A-14 an old blob whose sequence another transaction used: rejected tefPAST_SEQ', async () => {
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const one = await signed(client, a, pay(b.classicAddress, '1000'));
    const two = a.sign({ ...one.tx, Amount: '2000' } as never); // the other exit on the same slot
    await submitReliable(rpcOf(client), one.blob, opts);
    expect(await submitReliable(rpcOf(client), two.tx_blob, opts)).toEqual({
      status: 'rejected',
      result: 'tefPAST_SEQ',
    });
  });

  it('T-A-15 LastLedgerSequence passed before submit: expired', async () => {
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const lls = (await validatedLedger()) - 1;
    const s = await signed(client, a, { ...pay(b.classicAddress), LastLedgerSequence: lls });
    const raw = await client.request({ command: 'submit', tx_blob: s.blob });
    expect(raw.result.engine_result).toBe('tefMAX_LEDGER');
    expect(await submitReliable(rpcOf(client), s.blob, opts)).toEqual({ status: 'expired', lastLedgerSequence: lls });
  });

  it('T-A-15 LastLedgerSequence passes while the transaction waits (a sequence gap): expired after the ledger passes', async () => {
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const seq = await accountSequence(client, a.classicAddress);
    const lls = (await validatedLedger()) + 5;
    const s = await signed(client, a, { ...pay(b.classicAddress), Sequence: seq + 1, LastLedgerSequence: lls });
    const r = await submitReliable(rpcOf(client), s.blob, opts);
    expect(r).toEqual({ status: 'expired', lastLedgerSequence: lls });
    expect(await validatedLedger()).toBeGreaterThan(lls);
    expect(await accountSequence(client, a.classicAddress)).toBe(seq);
  });

  it('P2.2-04 the network drops after submit, before the result: found by account and sequence after reconnect', async () => {
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const proxy = await startProxy(env.wsUrl);
    const c = new xrpl.Client(proxy.url, { timeout: 5_000 });
    await c.connect();
    try {
      const s = await signed(client, a, pay(b.classicAddress));
      const inner = rpcOf(c);
      let dropped = 0;
      const rpc: Rpc = {
        ...inner,
        request: async (req) => {
          const res = await inner.request(req);
          if (req.command === 'submit' && dropped++ === 0) {
            proxy.killAll(); // the server has the transaction; we never see its answer
            throw new xrpl.DisconnectedError('websocket was closed');
          }
          return res;
        },
      };
      const r = await submitReliable(rpc, s.blob, opts);
      expect(dropped).toBeGreaterThanOrEqual(1);
      expect(r).toMatchObject({ status: 'validated', result: 'tesSUCCESS', hash: s.hash });
      expect(await accountSequence(client, a.classicAddress)).toBe((s.tx.Sequence ?? 0) + 1);
    } finally {
      await disconnectQuietly(c);
      await proxy.close();
    }
  });

  it('concurrency: 20 accounts submit at once; each gets exactly one final result', async () => {
    const senders = [];
    for (let i = 0; i < 20; i++) senders.push(await fundAccount(env, client, 100));
    const dest = await fundAccount(env, client);
    const blobs = await Promise.all(senders.map((w) => signed(client, w, pay(dest.classicAddress))));
    const results = await Promise.all(blobs.map((s) => submitReliable(rpcOf(client), s.blob, opts)));
    expect(results.map((r) => r.status)).toEqual(Array(20).fill('validated'));
    expect(results.map((r) => (r.status === 'validated' ? r.hash : ''))).toEqual(blobs.map((s) => s.hash));
    for (const w of senders) expect(await accountSequence(client, w.classicAddress)).toBeGreaterThan(0);
  });
});

describe('fault: random WebSocket kills under a fast-check scheduler', () => {
  let proxy: TcpProxy;
  beforeAll(async () => {
    proxy = await startProxy(env.wsUrl);
  });
  afterAll(async () => {
    await proxy.close();
  });

  it('never a wrong final answer: validated means on the ledger, anything else means the slot is unused', async () => {
    const dest = await fundAccount(env, client);
    await fc.assert(
      fc.asyncProperty(
        fc.scheduler(),
        fc.uniqueArray(fc.nat(12), { maxLength: 4 }),
        fc.boolean(),
        async (s, killAt, shortLife) => {
          const a = await fundAccount(env, client, 100);
          const lls = (await validatedLedger()) + (shortLife ? 2 : 30);
          const tx = await signed(client, a, { ...pay(dest.classicAddress), LastLedgerSequence: lls });
          const c = new xrpl.Client(proxy.url, { timeout: 5_000 });
          await c.connect();
          try {
            const inner = rpcOf(c);
            // The kill happens when the scheduler releases it: before or after any pending answer is delivered.
            const kill = () => s.schedule(Promise.resolve(), 'kill').then(() => proxy.killAll());
            const request = s.scheduleFunction(inner.request);
            let n = 0;
            const rpc: Rpc = {
              ...inner,
              request: (req) => {
                if (killAt.includes(n++)) void kill();
                return request(req);
              },
            };
            const r = await s.waitFor(submitReliable(rpc, tx.blob, { pollMs: 20, timeoutMs: 60_000 }));
            const seq = await accountSequence(client, a.classicAddress);
            if (r.status === 'validated') {
              const t = await client.request({ command: 'tx', transaction: r.hash });
              expect(t.result.validated).toBe(true);
              expect(r.result).toBe((t.result.meta as { TransactionResult: string }).TransactionResult);
              expect(seq).toBe((tx.tx.Sequence ?? 0) + 1);
            } else {
              expect(r.status).toBe('expired');
              expect(seq).toBe(tx.tx.Sequence);
              expect(await validatedLedger()).toBeGreaterThan(lls);
            }
          } finally {
            await disconnectQuietly(c);
          }
        },
      ),
      { numRuns: 25 },
    );
  });
});
