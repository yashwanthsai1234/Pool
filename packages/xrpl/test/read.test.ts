import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import xrpl from 'xrpl';
import { deliveredAmount, ledgerHeader, type Rpc, type RpcRequest, rpcOf, snapshot } from '../src/read.ts';
import { hashOf } from './fakeLedger.ts';

const A = 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe';
const B = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const N = 50;
const obj = (i: number) => ({ LedgerEntryType: 'Ticket', index: i.toString(16).toUpperCase().padStart(64, '0') });

/** account_objects split into pages of `size`; `hook` may change any response. */
function fakeRpc(count: number, size: number, hook?: (req: RpcRequest, res: Record<string, unknown>) => unknown) {
  const calls: RpcRequest[] = [];
  const rpc: Rpc = {
    isConnected: () => true,
    connect: async () => undefined,
    request: async (req) => {
      calls.push(req);
      let res: Record<string, unknown>;
      const at = req.ledger_index === 'validated' ? N : (req.ledger_index as number);
      if (req.command === 'ledger') {
        if (at > N) throw new xrpl.RippledError('lgrNotFound', { error: 'lgrNotFound' });
        res = {
          ledger: { ledger_index: at, ledger_hash: hashOf(at), close_time: 800_000_000 + at },
          ledger_hash: hashOf(at),
          ledger_index: at,
          validated: true,
        };
      } else if (req.command === 'account_info') {
        res = {
          account_data: { Account: req.account, Sequence: 7, OwnerCount: count },
          ledger_index: at,
          ledger_hash: hashOf(at),
          validated: true,
        };
      } else {
        const start = typeof req.marker === 'string' ? Number(req.marker) : 0;
        const objs = Array.from({ length: Math.max(0, Math.min(size, count - start)) }, (_, i) => obj(start + i));
        res = {
          account: req.account,
          account_objects: objs,
          ledger_index: at,
          ledger_hash: hashOf(at),
          validated: true,
          ...(start + size < count ? { marker: String(start + size) } : {}),
        };
      }
      return { result: hook ? hook(req, res) : res };
    },
  };
  return { rpc, calls };
}

describe('rpcOf', () => {
  const client = (request: () => Promise<unknown>) =>
    ({ request, isConnected: () => false, connect: async () => undefined }) as never;

  it('a raw socket error (ws "not open") becomes a ConnectionError, so callers retry it', async () => {
    const rpc = rpcOf(client(() => Promise.reject(new Error('WebSocket is not open: readyState 0 (CONNECTING)'))));
    await expect(rpc.request({ command: 'ping' })).rejects.toBeInstanceOf(xrpl.ConnectionError);
    expect(rpc.isConnected()).toBe(false);
    await rpc.connect();
  });

  it('xrpl.js errors pass through unchanged', async () => {
    const e = new xrpl.RippledError('txnNotFound', { error: 'txnNotFound' });
    await expect(rpcOf(client(() => Promise.reject(e))).request({ command: 'tx' })).rejects.toBe(e);
    expect(await rpcOf(client(async () => ({ result: 1 }))).request({ command: 'ping' })).toEqual({ result: 1 });
  });
});

describe('ledgerHeader', () => {
  it('P2.2-07 returns index, hash and close_time of a validated ledger', async () => {
    const { rpc } = fakeRpc(0, 1);
    expect(await ledgerHeader(rpc, 40)).toEqual({ ledgerIndex: 40, ledgerHash: hashOf(40), closeTime: 800_000_040 });
    expect(await ledgerHeader(rpc, 'validated')).toMatchObject({ ledgerIndex: N });
  });

  it('refuses a ledger that is not validated, the wrong ledger, or a malformed header', async () => {
    const bad = async (h: (res: Record<string, unknown>) => unknown) =>
      ledgerHeader(fakeRpc(0, 1, (_r, res) => h(res)).rpc, 40);
    await expect(bad((r) => ({ ...r, validated: false }))).rejects.toThrow(/not validated/);
    await expect(bad((r) => ({ ...r, ledger: { ...(r.ledger as object), ledger_index: 41 } }))).rejects.toThrow(/41/);
    await expect(bad((r) => ({ ...r, ledger: { ...(r.ledger as object), ledger_hash: 'zz' } }))).rejects.toThrow();
    await expect(bad((r) => ({ ...r, ledger: { ...(r.ledger as object), close_time: -1 } }))).rejects.toThrow();
    await expect(bad(() => null)).rejects.toThrow(/ledger/);
  });

  it('a future ledger: the rippled error comes through', async () => {
    await expect(ledgerHeader(fakeRpc(0, 1).rpc, N + 1)).rejects.toThrow(/lgrNotFound/);
  });
});

describe('snapshot', () => {
  it('P2.2-05 account_info and every account_objects page come from one ledger_index', async () => {
    const { rpc, calls } = fakeRpc(7, 3);
    const s = await snapshot(rpc, [A as never, B as never]);
    expect(s.ledger.ledgerIndex).toBe(N);
    expect(Object.keys(s.accounts)).toEqual([A, B]);
    expect(s.accounts[A]?.objects).toHaveLength(7);
    expect(s.accounts[A]?.accountData.Sequence).toBe(7);
    const reads = calls.filter((c) => c.command !== 'ledger');
    expect(reads).toHaveLength(2 * (1 + 3));
    for (const c of reads) expect(c.ledger_index).toBe(N);
  });

  it('I-18: a missing account is listed in `missing` only when asked; by default actNotFound comes through', async () => {
    const gone = (req: { command: string; account?: unknown }, res: Record<string, unknown>) => {
      if (req.account === B && req.command !== 'ledger') throw new xrpl.RippledError('x', { error: 'actNotFound' });
      return res;
    };
    await expect(snapshot(fakeRpc(1, 3, gone as never).rpc, [A as never, B as never])).rejects.toThrow();
    const s = await snapshot(fakeRpc(1, 3, gone as never).rpc, [A as never, B as never], undefined, {
      allowMissing: true,
    });
    expect(Object.keys(s.accounts)).toEqual([A]);
    expect(s.missing).toEqual([B]);
  });

  it('reads at a given past ledger', async () => {
    const { rpc, calls } = fakeRpc(1, 3);
    expect((await snapshot(rpc, [A as never], 33)).ledger.ledgerIndex).toBe(33);
    for (const c of calls) expect(c.ledger_index).toBe(33);
  });

  it('property: every object exactly once, whatever the page size', async () => {
    await fc.assert(
      fc.asyncProperty(fc.nat(60), fc.integer({ min: 1, max: 25 }), async (count, size) => {
        const s = await snapshot(fakeRpc(count, size).rpc, [A as never]);
        const ids = s.accounts[A]?.objects.map((o) => o.index);
        expect(ids).toHaveLength(count);
        expect(new Set(ids).size).toBe(count);
      }),
    );
  });

  it('follows a marker even when a page is empty', async () => {
    let first = true;
    const { rpc } = fakeRpc(2, 1, (req, res) => {
      if (req.command === 'account_objects' && first) {
        first = false;
        return { ...res, account_objects: [], marker: '0' };
      }
      return res;
    });
    expect((await snapshot(rpc, [A as never])).accounts[A]?.objects).toHaveLength(2);
  });

  const hostile: [string, (req: RpcRequest, res: Record<string, unknown>) => unknown, RegExp][] = [
    ['a page from another ledger', (r, res) => (r.marker ? { ...res, ledger_index: N - 1 } : res), /ledger/],
    ['a page from another ledger hash', (r, res) => (r.marker ? { ...res, ledger_hash: hashOf(1) } : res), /hash/],
    ['a page that is not validated', (r, res) => (r.marker ? { ...res, validated: false } : res), /validated/],
    [
      'account_info from another ledger',
      (r, res) => (r.command === 'account_info' ? { ...res, ledger_index: 1 } : res),
      /ledger/,
    ],
    ['a repeated marker', (r, res) => (r.command === 'account_objects' ? { ...res, marker: 'same' } : res), /marker/],
    [
      'an object twice',
      (r, res) =>
        r.command === 'account_objects'
          ? { ...res, account_objects: [obj(1)], ...(r.marker ? {} : { marker: 'x' }) }
          : res,
      /twice/,
    ],
    [
      'objects that are not an array',
      (r, res) => (r.command === 'account_objects' ? { ...res, account_objects: {} } : res),
      /account_objects/,
    ],
    [
      'an object without index',
      (r, res) => (r.command === 'account_objects' ? { ...res, account_objects: [{}] } : res),
      /index/,
    ],
    [
      'account_data missing',
      (r, res) => (r.command === 'account_info' ? { ...res, account_data: 'x' } : res),
      /account_data/,
    ],
  ];
  it.each(hostile)('refuses %s', async (_name, hook, msg) => {
    await expect(snapshot(fakeRpc(5, 2, hook).rpc, [A as never])).rejects.toThrow(msg);
  });
});

describe('deliveredAmount', () => {
  const issued = { currency: 'USD', issuer: B, value: '12.5' };
  it('P2.2-08 reads delivered_amount, never Amount', () => {
    expect(deliveredAmount({ TransactionResult: 'tesSUCCESS', delivered_amount: '1000' })).toBe('1000');
    expect(deliveredAmount({ TransactionResult: 'tesSUCCESS', delivered_amount: issued })).toEqual(issued);
    const mpt = { mpt_issuance_id: '0'.repeat(48), value: '5' };
    expect(deliveredAmount({ TransactionResult: 'tesSUCCESS', delivered_amount: mpt })).toEqual(mpt);
  });

  it('T-A-13 a partial payment: the credited amount is delivered_amount, not the larger Amount', () => {
    const meta = { TransactionResult: 'tesSUCCESS', delivered_amount: '10', DeliveredAmount: '10' };
    const tx = { Amount: '1000000', Flags: 0x00020000 };
    expect(deliveredAmount(meta)).toBe('10');
    expect(deliveredAmount(meta)).not.toBe(tx.Amount);
  });

  it('nothing delivered: a failed or non-payment result gives undefined', () => {
    expect(deliveredAmount({ TransactionResult: 'tecUNFUNDED_PAYMENT', delivered_amount: '1000' })).toBeUndefined();
    expect(deliveredAmount({ TransactionResult: 'tesSUCCESS' })).toBeUndefined();
  });

  it('refuses "unavailable" and malformed amounts instead of guessing', () => {
    const m = (d: unknown) => ({ TransactionResult: 'tesSUCCESS', delivered_amount: d });
    expect(() => deliveredAmount(m('unavailable'))).toThrow(/unavailable/);
    expect(() => deliveredAmount(m('-5'))).toThrow();
    expect(() => deliveredAmount(m('01'))).toThrow();
    expect(() => deliveredAmount(m(5))).toThrow();
    expect(() => deliveredAmount(m({ currency: 'USD', value: '1' }))).toThrow();
    expect(() => deliveredAmount(m(null))).toThrow();
  });
});
