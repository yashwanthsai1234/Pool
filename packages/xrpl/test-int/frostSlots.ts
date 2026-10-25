// Four FROST slots (A, B, LA, LB) that sign XRPL multisig messages with 2 of 3 shares through the core session
// (OD-4). The DKG runs once per test file; signing rotates through the six ordered pairs of holders, so a run replays
// (I-2.5-d: no Math.random).
import xrpl from 'xrpl';
import {
  aggregateChecked,
  type Commitment,
  SigningSession,
  type SlotName,
  slotAddress,
  slotPubkey,
} from '../../core/src/frost.ts';
import type { DkgKey } from '../../core/src/frostDkg.ts';
import { dkgKeys } from '../../core/test/helpers/frost.ts';

export interface FrostSlot {
  name: SlotName;
  address: string;
  keys: DkgKey[];
}

export async function makeSlots(): Promise<FrostSlot[]> {
  const out: FrostSlot[] = [];
  for (const name of ['A', 'B', 'LA', 'LB'] as const) {
    const { keys, pub } = await dkgKeys(name);
    out.push({ name, address: slotAddress(pub), keys });
  }
  return out;
}

// Draws that make the pair for call n: first holder n mod 3, second holder (first + 1 + (n/3 mod 2)) mod 3.
let calls = 0;
const rotating = (): (() => number) => {
  const n = calls++;
  const draws = [((n % 3) + 0.5) / 3, (Math.floor(n / 3) % 2) * 0.5 + 0.25];
  let i = 0;
  return () => draws[i++ % 2] as number;
};

/** One slot's multi-signature blob for `tx`: 2 of 3 shares (the pair is chosen by `pick`), aggregated and checked. */
export function slotSign(slot: FrostSlot, tx: Record<string, unknown>, pick = rotating()): string {
  const first = Math.floor(pick() * 3);
  const pair = [slot.keys[first], slot.keys[(first + 1 + Math.floor(pick() * 2)) % 3]] as DkgKey[];
  const pub = pair[0]?.public as DkgKey['public'];
  const unsigned = { ...tx, SigningPubKey: '' };
  const msg = Buffer.from(xrpl.encodeForMultiSigning(unsigned as never, slot.address), 'hex');
  const sessions = pair.map((k) => SigningSession.open(k.secret, pub, msg));
  const list: Commitment[] = sessions.map((s) => s.commitment);
  const shares: Record<string, Uint8Array> = {};
  for (const [i, s] of sessions.entries())
    shares[(pair[i] as DkgKey).secret.identifier] = s.signShare(msg, list, () => ({ ok: true }));
  const sig = aggregateChecked(pub, list, msg, shares);
  const signer = {
    Signer: {
      Account: slot.address,
      SigningPubKey: Buffer.from(slotPubkey(pub)).toString('hex').toUpperCase(),
      TxnSignature: Buffer.from(sig).toString('hex').toUpperCase(),
    },
  };
  return xrpl.encode({ ...unsigned, Signers: [signer] } as never);
}
