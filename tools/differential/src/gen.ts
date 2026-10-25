// Random values in the shapes the protocol uses. All of them come from a seeded Prng.
import { bytesToHex } from '@noble/hashes/utils.js';
import { encodeAccountID } from 'xrpl';
import type { Prng } from './prng.ts';

export const hex = (b: Uint8Array): string => bytesToHex(b);
export const hexUp = (b: Uint8Array): string => bytesToHex(b).toUpperCase();

/** A classic address with a valid checksum. */
export const address = (r: Prng): string => encodeAccountID(r.bytes(20));

/** The 33-byte XRPL form of an Ed25519 key: `ED` + 32 bytes, uppercase hex. */
export const edKey = (r: Prng): string => `ED${hexUp(r.bytes(32))}`;

/** A payout: `rAddr` or `rAddr:tag`, the tag in base 10 without leading zeros, 0 to 4294967295. */
export const payout = (r: Prng): string => (r.chance(0.5) ? address(r) : `${address(r)}:${r.u32()}`);

/** Drops, 0 to 10^17. */
export const dropsStr = (r: Prng): string => {
  const digits = r.range(1, 17);
  let s = String(r.range(1, 9));
  for (let i = 1; i < digits; i++) s += String(r.int(10));
  return r.chance(0.02) ? '100000000000000000' : s;
};

export const ledgerSeq = (r: Prng): number => r.range(1, 2 ** 32 - 1);
