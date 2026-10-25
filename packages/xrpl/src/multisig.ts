// Collecting the four signatures and the exit slot S (DESIGN 7.5, decision D9, OD-11).
// Source: https://xrpl.org/docs/concepts/accounts/multi-signing
// Source: https://xrpl.org/docs/concepts/accounts/tickets

import type { SubmitResult } from '@legx/contracts/ports';
import { verifyMultisigned } from '@legx/core/verify';
import xrpl, { type SubmittableTransaction } from 'xrpl';
import type { Slot } from './builders/common.ts';
import { EXIT_FEE_MULTIPLIER, LAST_LEDGER_OFFSET, type PrepareOptions, prepare } from './prepare.ts';
import { call, ledgerHeader, pages, type Rpc, uint } from './read.ts';

type Tx = Record<string, unknown>;
type SignerEntry = { Signer: { Account: string } };

/**
 * Merge four single-signed blobs (each made with `wallet.sign(tx, true)` semantics) into one multisigned blob.
 * Refuses: a body that differs between blobs, no `LastLedgerSequence` (a fully signed exit must always expire,
 * DESIGN 7.5), and any signer set that is not exactly `expected` or has a bad signature (`verifyMultisigned`, 6.8).
 * Signers are sorted by decoded AccountID bytes, as rippled requires.
 */
// Source: https://xrpl.org/docs/references/protocol/transactions/common-fields#signers-field
export function combine(blobs: readonly string[], expected: readonly string[]): string {
  if (blobs.length === 0) throw new Error('combine: no blobs');
  const decoded = blobs.map((b) => xrpl.decode(b) as Tx);
  const bodies = decoded.map(({ Signers: _s, ...body }) => xrpl.encode(body as never));
  if (bodies.some((b) => b !== bodies[0])) throw new Error('combine: the blobs are not the same transaction');
  const first = decoded[0] as Tx;
  if (typeof first.LastLedgerSequence !== 'number') throw new Error('combine: LastLedgerSequence is required');
  const signers = decoded.flatMap((t) => (t.Signers as SignerEntry[] | undefined) ?? []);
  const key = (s: SignerEntry) => Buffer.from(xrpl.decodeAccountID(s.Signer.Account)).toString('hex');
  signers.sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
  const blob = xrpl.encode({ ...first, Signers: signers } as never);
  if (!verifyMultisigned(blob, [...expected]).ok) throw new Error('combine: signatures do not match the signer list');
  return blob;
}

/** The deal wallet's next Sequence at the latest validated ledger (autofill would count queued transactions). */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_info
export async function nextSlot(rpc: Rpc, account: string): Promise<{ sequence: number }> {
  const r = await call(rpc, { command: 'account_info', account, ledger_index: 'validated' });
  if (r.validated !== true) throw new Error('account_info: ledger is not validated');
  const data = r.account_data as Record<string, unknown>;
  return { sequence: uint(data.Sequence, 'account_data.Sequence') };
}

/** The deal wallet's Tickets at one validated ledger, lowest first. */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_objects
export async function ticketSlots(rpc: Rpc, account: string): Promise<{ ticketSequence: number }[]> {
  const { ledgerIndex } = await ledgerHeader(rpc, 'validated');
  const out: number[] = [];
  for await (const page of pages(rpc, {
    command: 'account_objects',
    account,
    type: 'ticket',
    ledger_index: ledgerIndex,
  }))
    for (const o of page.account_objects as Record<string, unknown>[])
      out.push(uint(o.TicketSequence, 'TicketSequence'));
  return out.sort((a, b) => a - b).map((ticketSequence) => ({ ticketSequence }));
}

/** An exit gets 5 to 10 times the builder's fee and the collection window (OD-11). AccountDelete is refused by `prepare`. */
export async function prepareExit<T extends SubmittableTransaction>(
  tx: T,
  o: Omit<PrepareOptions, 'feeMultiplier'> & { feeMultiplier?: number },
): Promise<T> {
  const m = o.feeMultiplier ?? EXIT_FEE_MULTIPLIER.min;
  if (!Number.isInteger(m) || m < EXIT_FEE_MULTIPLIER.min || m > EXIT_FEE_MULTIPLIER.max)
    throw new Error(
      `exit feeMultiplier must be an integer from ${EXIT_FEE_MULTIPLIER.min} to ${EXIT_FEE_MULTIPLIER.max}`,
    );
  return prepare(tx, { lastLedgerOffset: LAST_LEDGER_OFFSET.collection, ...o, feeMultiplier: m });
}

export type ExitOutcome = { done: true } | { done: false; slotUsed: boolean; next: Slot | undefined };

/**
 * What an exit result means for slot S (DESIGN 7.5). Only `tesSUCCESS` finishes the deal. Anything else leaves the
 * deal open: the slot is re-read from the validated ledger, so a `tec` (which spends S) returns S+1, a lost race
 * (`tefPAST_SEQ`) returns the winner's successor, and an expired or rejected exit returns the unchanged slot.
 * `slotUsed` tells the caller whether to void both candidates (always when true) and collect signatures again.
 */
export async function exitOutcome(rpc: Rpc, account: string, slot: Slot, r: SubmitResult): Promise<ExitOutcome> {
  if (r.status === 'validated' && r.result === 'tesSUCCESS') return { done: true };
  if ('ticketSequence' in slot) {
    const left = await ticketSlots(rpc, account);
    return { done: false, slotUsed: !left.some((t) => t.ticketSequence === slot.ticketSequence), next: left[0] };
  }
  const next = await nextSlot(rpc, account);
  return { done: false, slotUsed: next.sequence > slot.sequence, next };
}
