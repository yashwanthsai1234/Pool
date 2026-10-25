import fc from 'fast-check';
import { beforeEach, describe, expect, it } from 'vitest';
import xrpl from 'xrpl';
import { coversRange, NotFinalError, submitReliable } from '../src/submit.ts';
import { FakeLedger, payment, variant } from './fakeLedger.ts';

const fast = { pollMs: 0, timeoutMs: 2_000 };
const wallet = xrpl.Wallet.fromSeed('sEdTM1uX8pu2do5XvTnutH6HsouMaM2', { algorithm: xrpl.ECDSA.ed25519 });
const A = wallet.classicAddress;

let L: FakeLedger;
beforeEach(() => {
  L = new FakeLedger();
  L.addAccount(A, { seq0: 5, tickets: [3, 4] });
});

describe('submitReliable: engine result classes', () => {
  it('P2.2-01 a good transaction: validated tesSUCCESS with ledger index, hash and meta', async () => {
    const { blob, hash } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    const r = await submitReliable(L.rpc(), blob, fast);
    expect(r).toEqual({ status: 'validated', result: 'tesSUCCESS', hash, ledgerIndex: 12, meta: expect.any(Object) });
    if (r.status === 'validated') expect(r.meta.TransactionResult).toBe('tesSUCCESS');
  });

  it('P2.2-02 a tec result is final and validated (the sequence was used)', async () => {
    L.engine = () => 'tecUNFUNDED_PAYMENT';
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    const r = await submitReliable(L.rpc(), blob, fast);
    expect(r).toMatchObject({ status: 'validated', result: 'tecUNFUNDED_PAYMENT' });
  });

  it.each(['temMALFORMED', 'temBAD_FEE', 'tefBAD_AUTH', 'tefMASTER_DISABLED', 'tefBAD_QUORUM'])(
    'P2.2-03 %s is final and not applied, with the engine code',
    async (code) => {
      L.engine = () => code;
      const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
      expect(await submitReliable(L.rpc(), blob, fast)).toEqual({ status: 'rejected', result: code });
    },
  );

  it.each(['telINSUF_FEE_P', 'telCAN_NOT_QUEUE', 'terRETRY', 'terPRE_SEQ'])(
    '%s is never final: the transaction is resubmitted and its validated result returned',
    async (code) => {
      L.engine = (_tx, n) => (n === 0 ? code : undefined);
      const { blob, hash } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
      const r = await submitReliable(L.rpc(), blob, fast);
      expect(r).toMatchObject({ status: 'validated', result: 'tesSUCCESS', hash });
    },
  );

  it('terQUEUED: waits until the queued transaction validates', async () => {
    L.engine = (_tx, n) => (n === 0 ? 'terQUEUED' : undefined);
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    expect(await submitReliable(L.rpc(), blob, fast)).toMatchObject({ status: 'validated', ledgerIndex: 13 });
  });

  it('a tel result that never clears stays not final until LastLedgerSequence passes, then expired', async () => {
    L.engine = () => 'telINSUF_FEE_P';
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 14 });
    expect(await submitReliable(L.rpc(), blob, fast)).toEqual({ status: 'expired', lastLedgerSequence: 14 });
    expect(L.V).toBeGreaterThan(14);
  });
});

describe('submitReliable: track by account and sequence, never by hash', () => {
  it('T-A-14 replaying our own validated blob gets tefPAST_SEQ but reports the original validation (no second payment)', async () => {
    const { blob, hash } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    L.include(blob, 8);
    const r = await submitReliable(L.rpc(), blob, fast);
    expect(r).toMatchObject({ status: 'validated', hash, ledgerIndex: 8 });
    expect(L.entries).toHaveLength(1);
  });

  it('T-A-14 an old blob whose sequence another transaction used: rejected tefPAST_SEQ', async () => {
    L.include(payment(wallet, { Sequence: 5, Amount: '7' }).blob, 8);
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    expect(await submitReliable(L.rpc(), blob, fast)).toEqual({ status: 'rejected', result: 'tefPAST_SEQ' });
  });

  it('tefPAST_SEQ while our earlier submission sits in the open ledger is not final: waits for validation', async () => {
    const { blob, hash } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    L.include(blob, L.V + 1); // in the open ledger, not validated yet
    L.autoClose = false;
    const p = submitReliable(L.rpc(), blob, { pollMs: 5, timeoutMs: 2_000 });
    await new Promise((r) => setTimeout(r, 40));
    L.close();
    expect(await p).toMatchObject({ status: 'validated', hash });
  });

  it('a malleated copy (other signatures, other hash) validated: reported as validated with the hash that validated', async () => {
    const { blob, hash } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    const v = variant(blob);
    expect(v.hash).not.toBe(hash);
    L.include(v.blob, 9);
    expect(await submitReliable(L.rpc(), blob, fast)).toMatchObject({ status: 'validated', hash: v.hash });
  });

  it('tem or tef for our blob while a copy sits in the open ledger: not rejected, the copy validates', async () => {
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    const v = variant(blob);
    L.include(v.blob, L.V + 1); // pending, not validated
    L.autoClose = false;
    L.engine = () => 'tefBAD_QUORUM';
    const p = submitReliable(L.rpc(), blob, { pollMs: 5, timeoutMs: 2_000 });
    await new Promise((r) => setTimeout(r, 40));
    L.close();
    expect(await p).toMatchObject({ status: 'validated', hash: v.hash });
  });

  it('a malleated copy validated while the original is still pending: found by sequence, not by hash', async () => {
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    const v = variant(blob);
    L.engine = (_tx, n) => {
      if (n === 0) L.include(v.blob, L.V + 1);
      return 'tefPAST_SEQ';
    };
    expect(await submitReliable(L.rpc(), blob, fast)).toMatchObject({ status: 'validated', hash: v.hash });
  });

  it('a validated tec copy is still our result', async () => {
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    L.include(blob, 9, 'tecNO_DST_INSUF_XRP');
    expect(await submitReliable(L.rpc(), blob, fast)).toMatchObject({
      status: 'validated',
      result: 'tecNO_DST_INSUF_XRP',
    });
  });

  it('tickets: a ticketed transaction is tracked by account and TicketSequence', async () => {
    const { blob, hash } = payment(wallet, { Sequence: 0, TicketSequence: 3, LastLedgerSequence: 30 });
    expect(await submitReliable(L.rpc(), blob, fast)).toMatchObject({ status: 'validated', hash });
  });

  it('tickets: replaying a used ticket reports the original; a ticket used by another transaction is tefNO_TICKET', async () => {
    const mine = payment(wallet, { Sequence: 0, TicketSequence: 3, LastLedgerSequence: 30 });
    L.include(mine.blob, 9);
    expect(await submitReliable(L.rpc(), mine.blob, fast)).toMatchObject({ status: 'validated', hash: mine.hash });
    L.include(payment(wallet, { Sequence: 0, TicketSequence: 4, Amount: '9' }).blob, 9);
    const other = payment(wallet, { Sequence: 0, TicketSequence: 4, LastLedgerSequence: 30 });
    expect(await submitReliable(L.rpc(), other.blob, fast)).toEqual({ status: 'rejected', result: 'tefNO_TICKET' });
  });

  it('tickets: a ticket that never existed is tefNO_TICKET', async () => {
    const { blob } = payment(wallet, { Sequence: 0, TicketSequence: 2, LastLedgerSequence: 30 });
    expect(await submitReliable(L.rpc(), blob, fast)).toEqual({ status: 'rejected', result: 'tefNO_TICKET' });
  });

  it('a deleted account (actNotFound) whose transaction is in history: still found', async () => {
    const { blob, hash } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    L.include(blob, 8);
    const acct = L.accounts.get(A);
    if (acct) acct.deleted = 9;
    expect(await submitReliable(L.rpc(), blob, fast)).toMatchObject({ status: 'validated', hash });
  });

  it('the slot is used but history before it is missing: never a final answer', async () => {
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    L.include(blob, 4);
    L.firstComplete = 6;
    await expect(submitReliable(L.rpc(), blob, fast)).rejects.toThrow(NotFinalError);
  });
});

describe('submitReliable: absence is final only with LastLedgerSequence passed, full history and txnNotFound', () => {
  it('T-A-15 LastLedgerSequence already passed before submit: tefMAX_LEDGER, the caller gets expired', async () => {
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 9 });
    expect(await submitReliable(L.rpc(), blob, fast)).toEqual({ status: 'expired', lastLedgerSequence: 9 });
  });

  it('a gap in complete_ledgers over the range: not final (times out instead of saying expired)', async () => {
    L.engine = () => 'telINSUF_FEE_P';
    L.complete = '1-11,13-1000';
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 14 });
    await expect(submitReliable(L.rpc(), blob, { pollMs: 0, timeoutMs: 200 })).rejects.toThrow(NotFinalError);
  });

  it('tx over the range must answer txnNotFound: any other answer is not final', async () => {
    L.engine = () => 'telINSUF_FEE_P';
    const rpc = L.rpc();
    const inner = rpc.request;
    rpc.request = async (req) => {
      if (req.command === 'tx') throw new xrpl.RippledError('internal', { error: 'internal' });
      return inner(req);
    };
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 14 });
    await expect(submitReliable(rpc, blob, { pollMs: 0, timeoutMs: 200 })).rejects.toThrow(NotFinalError);
  });

  it.each([
    [{ validated: false }, 'expired'],
    [{ validated: true, ledger_index: 12 }, 'not final'],
  ])('tx answers %j for a transaction held but never in a ledger: %s', async (answer, outcome) => {
    // xrpld 3.4.1 answers {hash, validated: false} for a held terPRE_SEQ transaction (build/tmp/2.2/gap.ts).
    L.engine = () => 'terPRE_SEQ';
    const rpc = L.rpc();
    const inner = rpc.request;
    rpc.request = async (req) => (req.command === 'tx' ? { result: { hash: req.transaction, ...answer } } : inner(req));
    const { blob } = payment(wallet, { Sequence: 6, LastLedgerSequence: 14 });
    const p = submitReliable(rpc, blob, { pollMs: 0, timeoutMs: 200 });
    if (outcome === 'expired') expect(await p).toEqual({ status: 'expired', lastLedgerSequence: 14 });
    else await expect(p).rejects.toThrow(NotFinalError);
  });

  it('splits the tx search into ranges of at most 1000 ledgers', async () => {
    L.engine = () => 'telINSUF_FEE_P';
    L.V = 3000;
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 3001 });
    expect(await submitReliable(L.rpc(), blob, { ...fast, minLedger: 500 })).toMatchObject({ status: 'expired' });
    const ranges = L.calls.filter((c) => c.command === 'tx').map((c) => [c.min_ledger, c.max_ledger]);
    expect(ranges).toEqual([
      [500, 1499],
      [1500, 2499],
      [2500, 3001],
    ]);
  });

  it('no LastLedgerSequence: never expired (the transaction could still validate), so it times out', async () => {
    L.engine = () => 'telINSUF_FEE_P';
    const { blob } = payment(wallet, { Sequence: 5 });
    await expect(submitReliable(L.rpc(), blob, { pollMs: 0, timeoutMs: 100 })).rejects.toThrow(/not final/);
  });
});

describe('submitReliable: dropped connections', () => {
  it('P2.2-04 the connection drops after submit, before the result: found by account and sequence after reconnect', async () => {
    L.fail = (req) => (req.command === 'submit' && L.entries.length === 0 ? 'after' : undefined);
    const { blob, hash } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    expect(await submitReliable(L.rpc(), blob, fast)).toMatchObject({ status: 'validated', hash });
    expect(L.entries).toHaveLength(1);
  });

  it('the connection drops before the server saw the submit: resubmitted after reconnect', async () => {
    let dropped = false;
    L.fail = (req) => {
      if (req.command !== 'submit' || dropped) return undefined;
      dropped = true;
      return 'before';
    };
    const { blob, hash } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    expect(await submitReliable(L.rpc(), blob, fast)).toMatchObject({ status: 'validated', hash });
  });

  it('a reconnect that keeps failing ends in NotFinalError, never a final answer', async () => {
    const rpc = L.rpc();
    L.fail = () => 'before';
    rpc.connect = async () => {
      throw new xrpl.ConnectionError('refused');
    };
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    await expect(submitReliable(rpc, blob, { pollMs: 0, timeoutMs: 100 })).rejects.toThrow(NotFinalError);
  });

  it('a non-connection error is not swallowed', async () => {
    L.tamper = (req, res) => (req.command === 'server_info' ? { info: {} } : res);
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    await expect(submitReliable(L.rpc(), blob, fast)).rejects.toThrow(/server_info/);
  });

  it('property: random drops and engine results never give a wrong final answer', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.record({ at: fc.nat(60), when: fc.constantFrom('before' as const, 'after' as const) }), {
          maxLength: 8,
        }),
        fc.constantFrom('tesSUCCESS', 'tecUNFUNDED_PAYMENT', 'telINSUF_FEE_P', 'terQUEUED', 'tefBAD_AUTH', 'drop'),
        fc.boolean(),
        fc.integer({ min: 11, max: 16 }),
        async (drops, first, copyFirst, lls) => {
          const L2 = new FakeLedger();
          L2.addAccount(A, { seq0: 5 });
          const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: lls });
          const v = variant(blob);
          const kills = new Map(drops.map((d) => [d.at, d.when]));
          L2.fail = (_req, n) => kills.get(n);
          L2.engine = (_tx, n) => {
            if (n > 0) return undefined;
            if (copyFirst) {
              L2.include(v.blob, L2.V + 1); // someone else's copy got there first: ours sees the slot taken
              return 'tefPAST_SEQ';
            }
            return first === 'drop' ? 'telCAN_NOT_QUEUE' : first;
          };
          const r = await submitReliable(L2.rpc(), blob, { pollMs: 0, timeoutMs: 5_000 });
          const onLedger = L2.validatedEntries(A).filter((e) => e.seq === 5);
          expect(onLedger.length).toBeLessThanOrEqual(1);
          if (r.status === 'validated') {
            expect(onLedger[0]?.hash).toBe(r.hash);
            expect(onLedger[0]?.result).toBe(r.result);
          } else {
            // Not applied: nothing of ours used the slot, and nothing can use it later.
            expect(onLedger).toHaveLength(0);
            if (r.status === 'expired') expect(L2.V).toBeGreaterThan(lls);
            if (r.status === 'rejected') expect(r.result).toBe('tefBAD_AUTH');
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe('submitReliable: edges and hostile answers', () => {
  it('a waiting ticketed transaction: the ticket still exists, so not final until it validates', async () => {
    L.engine = (_tx, n) => (n === 0 ? 'telINSUF_FEE_P' : undefined);
    const { blob, hash } = payment(wallet, { Sequence: 0, TicketSequence: 4, LastLedgerSequence: 30 });
    expect(await submitReliable(L.rpc(), blob, fast)).toMatchObject({ status: 'validated', hash });
  });

  it('a ticket number not reached yet can still be created: never rejected, expired once LastLedgerSequence passes', async () => {
    L.engine = () => 'terPRE_TICKET';
    const { blob } = payment(wallet, { Sequence: 0, TicketSequence: 9, LastLedgerSequence: 14 });
    expect(await submitReliable(L.rpc(), blob, fast)).toEqual({ status: 'expired', lastLedgerSequence: 14 });
  });

  it('a Sequence skipped by a TicketCreate: the slot is used by nothing, so rejected tefPAST_SEQ', async () => {
    L.include(payment(wallet, { Sequence: 5, Amount: '1' }).blob, 8); // stands for the TicketCreate at Sequence 5
    const acct = L.accounts.get(A);
    if (acct) acct.seq0 = 7; // the TicketCreate moved Sequence past 6
    const { blob } = payment(wallet, { Sequence: 6, LastLedgerSequence: 30 });
    expect(await submitReliable(L.rpc(), blob, fast)).toEqual({ status: 'rejected', result: 'tefPAST_SEQ' });
  });

  it('an account that never existed: no history, as if open, and expired after LastLedgerSequence', async () => {
    const stranger = xrpl.Wallet.fromSeed('sEdSkooMk31MeTjbHVE7vLvgCpEMAdB', { algorithm: xrpl.ECDSA.ed25519 });
    L.engine = () => 'terNO_ACCOUNT';
    const { blob } = payment(stranger, { Sequence: 1, LastLedgerSequence: 13 });
    expect(await submitReliable(L.rpc(), blob, fast)).toEqual({ status: 'expired', lastLedgerSequence: 13 });
  });

  it('default options: a decided case returns at once', async () => {
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 9 });
    expect(await submitReliable(L.rpc(), blob)).toEqual({ status: 'expired', lastLedgerSequence: 9 });
  });

  it('a blob without Account is refused', async () => {
    const blob = xrpl.encode({
      TransactionType: 'Payment',
      Destination: A,
      Amount: '1',
      Sequence: 1,
      Fee: '12',
    } as never);
    await expect(submitReliable(L.rpc(), blob, fast)).rejects.toThrow(TypeError);
  });

  const hostile: [string, (req: { command: string }, res: unknown) => unknown, RegExp][] = [
    ['account_tx without a list', (q, r) => (q.command === 'account_tx' ? { transactions: 'x' } : r), /not an array/],
    [
      'an unvalidated account_tx entry',
      (q, r) =>
        q.command === 'account_tx'
          ? { transactions: (r as { transactions: object[] }).transactions.map((t) => ({ ...t, validated: false })) }
          : r,
      /not validated/,
    ],
    [
      'tx not validated for a slot account_tx shows',
      (q, r) => (q.command === 'tx' ? { ...(r as object), validated: false } : r),
      /not validated by tx/,
    ],
    [
      'meta without TransactionResult',
      (q, r) => (q.command === 'tx' ? { ...(r as object), meta: {} } : r),
      /TransactionResult/,
    ],
    [
      'account_info from another ledger',
      (q, r) => (q.command === 'account_info' ? { ...(r as object), ledger_index: 1 } : r),
      /ledger/,
    ],
  ];
  it.each(hostile)('refuses %s instead of answering', async (_n, tamper, msg) => {
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    L.include(blob, 8);
    L.tamper = tamper;
    await expect(submitReliable(L.rpc(), blob, fast)).rejects.toThrow(msg);
  });

  it('a tx lookup that finds nothing for a slot account_tx shows: refused', async () => {
    const { blob } = payment(wallet, { Sequence: 5, LastLedgerSequence: 30 });
    L.include(blob, 8);
    const rpc = L.rpc();
    const inner = rpc.request;
    rpc.request = async (req) => {
      if (req.command === 'tx') throw new xrpl.RippledError('txnNotFound', { error: 'txnNotFound' });
      return inner(req);
    };
    await expect(submitReliable(rpc, blob, fast)).rejects.toThrow(/not validated by tx/);
  });

  it('a ledger_entry error other than entryNotFound is not swallowed', async () => {
    const rpc = L.rpc();
    const inner = rpc.request;
    rpc.request = async (req) => {
      if (req.command === 'ledger_entry') throw new xrpl.RippledError('internal', { error: 'internal' });
      return inner(req);
    };
    const { blob } = payment(wallet, { Sequence: 0, TicketSequence: 4, LastLedgerSequence: 30 });
    await expect(submitReliable(rpc, blob, fast)).rejects.toThrow(/internal/);
  });
});

describe('coversRange', () => {
  it('reads complete_ledgers ranges and single ledgers', () => {
    expect(coversRange('1-100', 5, 100)).toBe(true);
    expect(coversRange('1-10,12-100', 5, 20)).toBe(false);
    expect(coversRange('1-10,11-100', 5, 20)).toBe(true);
    expect(coversRange('5,6,7-9', 5, 9)).toBe(true);
    expect(coversRange('empty', 5, 9)).toBe(false);
    expect(coversRange('', 5, 9)).toBe(false);
    expect(coversRange('1-100', 9, 5)).toBe(true); // empty range
    expect(() => coversRange('1-x', 1, 2)).toThrow(/complete_ledgers/);
    expect(() => coversRange('9-1', 1, 2)).toThrow(/complete_ledgers/);
  });

  it('property: agrees with a set-based second implementation', () => {
    fc.assert(
      fc.property(
        fc.array(fc.tuple(fc.integer({ min: 1, max: 60 }), fc.nat(10)), { maxLength: 6 }),
        fc.integer({ min: 1, max: 70 }),
        fc.nat(15),
        (parts, lo, len) => {
          const have = new Set<number>();
          const text = parts
            .map(([a, l]) => {
              for (let i = a; i <= a + l; i++) have.add(i);
              return l === 0 ? `${a}` : `${a}-${a + l}`;
            })
            .join(',');
          const hi = lo + len;
          let expected = true;
          for (let i = lo; i <= hi; i++) if (!have.has(i)) expected = false;
          expect(coversRange(text || 'empty', lo, hi)).toBe(expected);
        },
      ),
    );
  });
});
