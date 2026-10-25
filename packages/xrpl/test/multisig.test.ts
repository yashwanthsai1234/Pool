// combine(): ordering, hostile blobs, and agreement with xrpl.multisign (a second implementation).

import type { SubmitResult } from '@legx/contracts/ports';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import xrpl from 'xrpl';
import { combine, exitOutcome, nextSlot } from '../src/multisig.ts';
import type { Rpc } from '../src/read.ts';

const wallets = Array.from({ length: 4 }, () => xrpl.Wallet.generate(xrpl.ECDSA.ed25519));
const shell = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
const addresses = wallets.map((w) => w.classicAddress);
const tx = (extra: object = { LastLedgerSequence: 100 }) => ({
  TransactionType: 'Payment' as const,
  Account: shell.classicAddress,
  Destination: wallets[0]?.classicAddress as string,
  Amount: '1000',
  Fee: '1000',
  Sequence: 5,
  ...extra,
});
const sign = (t: ReturnType<typeof tx>, n = 4) => wallets.slice(0, n).map((w) => w.sign(t, true).tx_blob);

describe('combine', () => {
  it('sorts by AccountID bytes for any input order, and equals xrpl.multisign', () => {
    const blobs = sign(tx());
    fc.assert(
      fc.property(fc.shuffledSubarray(blobs, { minLength: 4 }), (order) => {
        const out = combine(order, addresses);
        expect(out).toBe(xrpl.multisign(blobs));
      }),
    );
  });

  it('refuses no LastLedgerSequence, 3 of 4, a duplicate signer, a foreign signer, a tampered signature, junk', () => {
    expect(() => combine(sign(tx({})), addresses)).toThrow(/LastLedgerSequence/);
    expect(() => combine(sign(tx(), 3), addresses)).toThrow(/signer list/);
    const four = sign(tx());
    expect(() => combine([...four.slice(0, 3), four[0] as string], addresses)).toThrow(/signer list/);
    expect(() => combine(four, [...addresses.slice(1), shell.classicAddress])).toThrow(/signer list/);
    const forged = four.map((b) => xrpl.decode(b) as { Signers: { Signer: { TxnSignature: string } }[] });
    const s0 = forged[0]?.Signers[0]?.Signer as { TxnSignature: string };
    s0.TxnSignature = (s0.TxnSignature[0] === '0' ? '1' : '0') + s0.TxnSignature.slice(1);
    expect(() =>
      combine(
        forged.map((f) => xrpl.encode(f as never)),
        addresses,
      ),
    ).toThrow(/signer list/);
    expect(() => combine(['00'], addresses)).toThrow();
  });
});

// I-19: nextSlot and exitOutcome against a stub ledger (the integration race test covers the live ledger).
describe('nextSlot and exitOutcome', () => {
  const rpcAt = (sequence: number, tickets: number[] = [], validated = true): Rpc => ({
    isConnected: () => true,
    connect: async () => {},
    request: async (req) => ({
      result:
        req.command === 'account_info'
          ? { validated, account_data: { Sequence: sequence } }
          : req.command === 'ledger'
            ? { validated: true, ledger: { ledger_index: 9, ledger_hash: 'AB'.repeat(32), close_time: 1 } }
            : { account_objects: tickets.map((t) => ({ TicketSequence: t })) },
    }),
  });
  const ok = { status: 'validated', result: 'tesSUCCESS' } as unknown as SubmitResult;
  const lost = { status: 'rejected', result: 'tefPAST_SEQ' } as unknown as SubmitResult;
  const tec = { status: 'validated', result: 'tecNO_DST' } as unknown as SubmitResult;
  const expired = { status: 'expired' } as unknown as SubmitResult;
  const acct = shell.classicAddress;

  it('nextSlot reads the validated Sequence and refuses an unvalidated ledger', async () => {
    expect(await nextSlot(rpcAt(7), acct)).toEqual({ sequence: 7 });
    await expect(nextSlot(rpcAt(7, [], false), acct)).rejects.toThrow('not validated');
  });
  it('tesSUCCESS finishes the deal', async () => {
    expect(await exitOutcome(rpcAt(6), acct, { sequence: 5 }, ok)).toEqual({ done: true });
  });
  it('a lost race returns the winner successor as the slot, marked used', async () => {
    expect(await exitOutcome(rpcAt(6), acct, { sequence: 5 }, lost)).toEqual({
      done: false,
      slotUsed: true,
      next: { sequence: 6 },
    });
  });
  it('a tec spends the slot; an expired exit leaves it unchanged', async () => {
    expect(await exitOutcome(rpcAt(6), acct, { sequence: 5 }, tec)).toMatchObject({ slotUsed: true });
    expect(await exitOutcome(rpcAt(5), acct, { sequence: 5 }, expired)).toEqual({
      done: false,
      slotUsed: false,
      next: { sequence: 5 },
    });
  });
  it('ticket slots: used when the ticket is gone, else unchanged', async () => {
    expect(await exitOutcome(rpcAt(5, [12, 13]), acct, { ticketSequence: 11 }, lost)).toMatchObject({
      slotUsed: true,
      next: { ticketSequence: 12 },
    });
    expect(await exitOutcome(rpcAt(5, [11, 12]), acct, { ticketSequence: 11 }, expired)).toMatchObject({
      slotUsed: false,
    });
  });
});
