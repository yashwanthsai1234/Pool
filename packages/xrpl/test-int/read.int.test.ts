// Task 2.2 one-ledger reads against the standalone ledger: P2.2-05..08, T-A-13 and the LedgerPort.
import type { XrplAddress } from '@legx/contracts/values';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'xrpl';
import { connect } from '../src/connect.ts';
import { standaloneEnv } from '../src/env.ts';
import { fundAccount, GENESIS } from '../src/fund.ts';
import { advanceLedgers } from '../src/ledger.ts';
import { deliveredAmount, ledgerHeader, type Rpc, type RpcRequest, rpcOf, snapshot } from '../src/read.ts';
import { ledgerPort, submitReliable } from '../src/submit.ts';
import { closer, signed } from './support.ts';

const env = standaloneEnv();
const opts = { pollMs: 50, timeoutMs: 60_000 };
let client: Client;

beforeAll(async () => {
  client = await connect(env);
});
afterAll(async () => {
  await client.disconnect();
});

/** Records every response, so tests can look at each page. */
function recording(c: Client): { rpc: Rpc; seen: { req: RpcRequest; result: Record<string, unknown> }[] } {
  const inner = rpcOf(c);
  const seen: { req: RpcRequest; result: Record<string, unknown> }[] = [];
  return {
    seen,
    rpc: {
      ...inner,
      request: async (req) => {
        const r = await inner.request(req);
        seen.push({ req, result: r.result as Record<string, unknown> });
        return r;
      },
    },
  };
}

describe('snapshot', () => {
  it('P2.2-05 and P2.2-06: 500 objects force paging; one ledger_index; every object exactly once', async () => {
    const w = await fundAccount(env, client, 3000); // 20 XRP base + 500 x 5 XRP owner reserve on this config
    const addr = w.classicAddress;
    // 250 tickets in one transaction (the per-account maximum), then 250 checks.
    const tc = await signed(client, w, { TransactionType: 'TicketCreate', TicketCount: 250 });
    await client.request({ command: 'submit', tx_blob: tc.blob });
    await advanceLedgers(client, 1);
    const tmpl = await signed(client, w, {
      TransactionType: 'CheckCreate',
      Destination: GENESIS.classicAddress,
      SendMax: '1000000',
    });
    for (let i = 0; i < 250; i++) {
      const s = w.sign({ ...tmpl.tx, Sequence: (tmpl.tx.Sequence ?? 0) + i, LastLedgerSequence: undefined } as never);
      const r = await client.request({ command: 'submit', tx_blob: s.tx_blob });
      expect(r.result.engine_result).toBe('tesSUCCESS');
      if (i % 50 === 49) await advanceLedgers(client, 1);
    }
    await advanceLedgers(client, 1);

    const { rpc, seen } = recording(client);
    const s = await snapshot(rpc, [addr as XrplAddress]);
    const pages = seen.filter((x) => x.req.command === 'account_objects');
    expect(pages.length).toBeGreaterThan(1);
    for (const x of seen.filter((y) => y.req.command !== 'ledger')) {
      expect(x.result.ledger_index).toBe(s.ledger.ledgerIndex);
      expect(x.result.validated).toBe(true);
    }
    const objects = s.accounts[addr]?.objects ?? [];
    const pageSum = pages.reduce((n, p) => n + (p.result.account_objects as unknown[]).length, 0);
    expect(objects).toHaveLength(pageSum);
    expect(objects).toHaveLength(500);
    expect(new Set(objects.map((o) => o.index)).size).toBe(500);
    expect(s.accounts[addr]?.accountData.OwnerCount).toBe(500);
    const kinds = objects.map((o) => o.LedgerEntryType);
    expect(kinds.filter((k) => k === 'Ticket')).toHaveLength(250);
    expect(kinds.filter((k) => k === 'Check')).toHaveLength(250);
  });

  it('P2.2-05 several accounts at one past ledger: the state as it was then', async () => {
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const before = (await ledgerHeader(rpcOf(client), 'validated')).ledgerIndex;
    const t = await signed(client, a, { TransactionType: 'TicketCreate', TicketCount: 3 });
    await client.request({ command: 'submit', tx_blob: t.blob });
    await advanceLedgers(client, 2);
    const then = await snapshot(
      rpcOf(client),
      [a.classicAddress as XrplAddress, b.classicAddress as XrplAddress],
      before,
    );
    const now = await snapshot(rpcOf(client), [a.classicAddress as XrplAddress]);
    expect(then.ledger.ledgerIndex).toBe(before);
    expect(then.accounts[a.classicAddress]?.objects).toHaveLength(0);
    expect(now.accounts[a.classicAddress]?.objects).toHaveLength(3);
    expect(Object.keys(then.accounts)).toEqual([a.classicAddress, b.classicAddress]);
  });

  it('an account that does not exist at that ledger: actNotFound, never an empty snapshot', async () => {
    const w = (await import('xrpl')).default.Wallet.generate();
    await expect(snapshot(rpcOf(client), [w.classicAddress as XrplAddress])).rejects.toThrow(/Account not found/);
  });
});

describe('ledgerHeader', () => {
  it('P2.2-07 hash and close_time of a past validated ledger match the ledger RPC', async () => {
    await advanceLedgers(client, 3);
    const v = (await ledgerHeader(rpcOf(client), 'validated')).ledgerIndex;
    const past = v - 2;
    const h = await ledgerHeader(rpcOf(client), past);
    const raw = (await client.request({ command: 'ledger', ledger_index: past })).result;
    expect(h).toEqual({ ledgerIndex: past, ledgerHash: raw.ledger_hash, closeTime: raw.ledger.close_time });
    await expect(ledgerHeader(rpcOf(client), v + 100)).rejects.toThrow();
  });
});

describe('deliveredAmount', () => {
  let stop: () => Promise<void>;
  let ticker: Client;
  beforeAll(async () => {
    ticker = await connect(env);
    stop = closer(ticker);
  });
  afterAll(async () => {
    await stop();
    await ticker.disconnect();
  });

  const submit = async (w: Parameters<typeof signed>[1], tx: Record<string, unknown>) => {
    const r = await submitReliable(rpcOf(client), (await signed(client, w, tx)).blob, opts);
    if (r.status !== 'validated' || r.result !== 'tesSUCCESS') throw new Error(`setup failed: ${JSON.stringify(r)}`);
    return r;
  };

  it('P2.2-08 an XRP payment: delivered_amount', async () => {
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const r = await submit(a, { TransactionType: 'Payment', Destination: b.classicAddress, Amount: '1234567' });
    expect(deliveredAmount(r.meta)).toBe('1234567');
  });

  it('T-A-13 a partial payment into the deal wallet is credited from delivered_amount only', async () => {
    const [issuer, sender, deal] = [
      await fundAccount(env, client),
      await fundAccount(env, client),
      await fundAccount(env, client),
    ];
    const USD = (value: string) => ({ currency: 'USD', issuer: issuer.classicAddress, value });
    await submit(issuer, { TransactionType: 'AccountSet', SetFlag: 8 }); // asfDefaultRipple
    await submit(sender, { TransactionType: 'TrustSet', LimitAmount: USD('100000') });
    await submit(deal, { TransactionType: 'TrustSet', LimitAmount: USD('100000') });
    await submit(issuer, { TransactionType: 'Payment', Destination: sender.classicAddress, Amount: USD('100') });
    const r = await submit(sender, {
      TransactionType: 'Payment',
      Destination: deal.classicAddress,
      Amount: USD('10000'), // asks for 10,000
      SendMax: USD('100'), // can only send 100
      Flags: 0x00020000, // tfPartialPayment
    });
    const t = await client.request({ command: 'tx', transaction: r.hash });
    expect((t.result.tx_json as { DeliverMax?: unknown }).DeliverMax).toEqual(USD('10000'));
    const delivered = deliveredAmount(r.meta);
    expect(delivered).toEqual(USD('100'));
    const lines = await client.request({
      command: 'account_lines',
      account: deal.classicAddress,
      ledger_index: 'validated',
    });
    expect(lines.result.lines[0]?.balance).toBe((delivered as { value: string }).value);
  });
});

describe('LedgerPort', () => {
  it('serves validated reads, tx, fees, autofill and submitReliable over one client', async () => {
    const port = ledgerPort(client, env, opts);
    expect(port.network).toBe('standalone');
    expect(await port.fees()).toEqual({ baseFee: '200', reserveBase: '20000000', reserveInc: '5000000' });
    const [a, b] = [await fundAccount(env, client), await fundAccount(env, client)];
    const filled = await port.autofill(
      { TransactionType: 'Payment', Account: a.classicAddress, Destination: b.classicAddress, Amount: '1000' },
      0,
    );
    expect(filled.Sequence).toEqual(expect.any(Number));
    const ticker = await connect(env);
    const stop = closer(ticker);
    try {
      const r = await port.submitReliable(a.sign(filled as never).tx_blob);
      if (r.status !== 'validated') throw new Error(JSON.stringify(r));
      const t = await port.tx(r.hash);
      const h = await port.ledgerHeader(r.ledgerIndex);
      expect(t).toMatchObject({ hash: r.hash, ledgerIndex: r.ledgerIndex, closeTime: h.closeTime, meta: r.meta });
      expect(await port.tx('0'.repeat(64) as never)).toBeUndefined();
      const v = await port.validatedLedger();
      const snap = await port.snapshot([b.classicAddress as XrplAddress], v.ledgerIndex);
      expect(snap.ledger).toEqual(v);
    } finally {
      await stop();
      await ticker.disconnect();
    }
  });
});
