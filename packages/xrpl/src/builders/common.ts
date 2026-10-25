// Shared helpers for the transaction builders (DESIGN 7.3). Builders are pure: they never touch the network and
// never autofill. They set the minimum Fee that rippled charges; `prepare` adds headroom.

import { Drops, SequenceNumber, XrplAddress } from '@legx/contracts/values';
import { bytesToHex, utf8ToBytes } from '@legx/core/dealcore';
import type { Memo } from 'xrpl';
import { isValidXAddress } from 'xrpl';

/** Test networks only. Hard rule 1: Mainnet is not a member, so a builder given it throws. */
export type BuildNetwork = 'standalone' | 'testnet' | 'devnet';
const NETWORKS: readonly string[] = ['standalone', 'testnet', 'devnet'];

export interface BuildCtx {
  network: BuildNetwork;
  /** The ledger's base fee in drops (10 on Mainnet and Testnet, 200 on the standalone config). Default 10. */
  baseFeeDrops?: number;
}

/** Throws on Mainnet or any unknown network. Source: https://xrpl.org/docs/concepts/networks-and-servers/parallel-networks */
export function baseFee(ctx: BuildCtx): number {
  if (!NETWORKS.includes(ctx.network)) {
    throw new Error(
      `builder refuses network "${String(ctx.network)}": this project never builds for Mainnet (hard rule 1)`,
    );
  }
  const base = ctx.baseFeeDrops ?? 10;
  if (!Number.isInteger(base) || base < 1) throw new Error('baseFeeDrops must be a positive integer');
  return base;
}

/**
 * A classic address with a valid checksum. An X-address is refused: the tag lives in its own field, and an
 * X-address starting with `X` is the Mainnet form. Source: https://xrpl.org/docs/concepts/accounts/addresses#x-addresses
 */
export function addr(a: string): string {
  if (isValidXAddress(a)) {
    throw new Error(
      a.startsWith('X')
        ? 'Mainnet X-address refused (hard rule 1)'
        : 'X-addresses are refused: use a classic address and a tag',
    );
  }
  return XrplAddress.parse(a);
}

/** rippled refuses these (temREDUNDANT, tecDST_TAG_NEEDED aside): a payment, close or preauth to oneself. */
export function distinct(what: string, a: string, b: string): void {
  if (a === b) throw new Error(`${what}: the two accounts must differ`);
}

export const drops = (d: string): string => Drops.parse(d);
export const seq = (n: number): number => SequenceNumber.parse(n);

/** Uppercase hex, as rippled returns it. */
export const hexUp = (b: Uint8Array): string => bytesToHex(b).toUpperCase();
export const hexOfText = (s: string): string => hexUp(utf8ToBytes(s));

export function bytes32(name: string, b: Uint8Array): Uint8Array {
  if (b.length !== 32) throw new Error(`${name} must be 32 bytes, got ${b.length}`);
  return b;
}

/** One memo. Source: https://xrpl.org/docs/references/protocol/transactions/common-fields#memos-field */
export const memo = (type: string, dataHex: string): Memo => ({
  Memo: { MemoType: hexOfText(type), MemoData: dataHex },
});

/** A transaction slot: the account Sequence (slot S) or a Ticket (Sequence must then be 0). */
export type Slot = { sequence: number } | { ticketSequence: number };
export function slotFields(slot: Slot | undefined): { Sequence?: number; TicketSequence?: number } {
  if (slot === undefined) return {};
  if ('ticketSequence' in slot) return { Sequence: 0, TicketSequence: seq(slot.ticketSequence) };
  return { Sequence: seq(slot.sequence) };
}

export const DAY = 86_400;
