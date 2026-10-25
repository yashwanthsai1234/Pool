// The per-slot post-quantum binding, browser half (DESIGN 6.13; IMPLEMENTATION 4.9). The device computes every field
// itself: `pqKeyHash_slot` from the three holder ML-DSA-65 keys it pinned (task 4.7) in role order, `dealSeal` and the
// slot key from its own verified copy of the seal. Any two holders sign `pqBindMsg` with ML-DSA-65 under the context
// `legx/pq-binding/v1`, the slot key cross-signs it through the vault's FROST path (task 4.7), and the binding is
// checked with core `verifyPqBinding` (task 1.16) before it may leave the device. The session lives in memory only:
// a reload between the two signatures starts over, so a half-signed binding is never submitted.
// Source: DESIGN.md 6.13; https://csrc.nist.gov/pubs/fips/204/final (contexts)

import { PqBinding } from '@legx/contracts/records';
import type { Slot } from '@legx/contracts/values';
import { bytesToHex } from '@legx/core/dealcore';
import { verifyEd25519Strict } from '@legx/core/frost';
import type { SignRequest } from '@legx/core/frostRules';
import {
  type HolderKey,
  type HolderSig,
  mldsaVerify,
  type PqBindingCode,
  pqBindMsg,
  pqKeyHash,
  signPqBinding,
  toBase64,
  verifyPqBinding,
} from '@legx/core/pq';
import type { z } from 'zod';
import type { PqHalf } from '../enrollment.ts';

const CTX = 'legx/pq-binding/v1';

export { PQ_BINDING_TEXT } from './text.ts';

import type { PQ_BINDING_TEXT } from './text.ts';

export type BindingProgress = keyof typeof PQ_BINDING_TEXT.progress;
export type BindingCode = 'KEY_MISMATCH' | 'SEAL_MISMATCH' | PqBindingCode;

export class PqBindingError extends Error {
  readonly code: BindingCode;
  constructor(code: BindingCode) {
    super(code);
    this.name = 'PqBindingError';
    this.code = code;
  }
}

/** The values from the frame's own verified seal. */
export interface SealView {
  readonly dealSeal: Uint8Array;
  readonly slotPub: Uint8Array; // 33 bytes, 0xED prefix
  readonly pqKeyHash: Uint8Array;
}
/** What the coordinator presents for signing. */
export interface BindingOffer {
  readonly dealSeal: Uint8Array;
  readonly slotPub: Uint8Array;
  readonly holders: readonly HolderKey[];
}
type Three = readonly [HolderKey, HolderKey, HolderKey];

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * The fields the screen shows. A pinned key set that does not hash to the seal, or an offer whose holder keys differ
 * from the pinned ones, is `KEY_MISMATCH`; an offer for another deal seal or slot key is `SEAL_MISMATCH`.
 */
export function bindingFields(seal: SealView, pinned: Three, offer: BindingOffer) {
  const keyHash = pqKeyHash([pinned[0].mlDsa65, pinned[1].mlDsa65, pinned[2].mlDsa65]);
  const offered = (h: HolderKey, i: number) =>
    offer.holders[i]?.keyId === h.keyId && same(offer.holders[i]?.mlDsa65 ?? new Uint8Array(), h.mlDsa65);
  if (!same(keyHash, seal.pqKeyHash) || offer.holders.length !== 3 || !pinned.every(offered))
    throw new PqBindingError('KEY_MISMATCH');
  if (!same(offer.dealSeal, seal.dealSeal) || !same(offer.slotPub, seal.slotPub))
    throw new PqBindingError('SEAL_MISMATCH');
  return { dealSeal: seal.dealSeal, slotPub: seal.slotPub, pqKeyHash: keyHash };
}

export interface BindingSessionInput {
  readonly slot: Slot;
  readonly seal: SealView;
  readonly pinned: Three;
  readonly offer: BindingOffer;
  readonly onProgress?: (step: BindingProgress) => void;
}

export function pqBindingSession(input: BindingSessionInput) {
  const fields = bindingFields(input.seal, input.pinned, input.offer);
  const msg = pqBindMsg(fields.dealSeal, fields.slotPub, fields.pqKeyHash);
  const sigs: HolderSig[] = [];
  const progress = (s: BindingProgress) => input.onProgress?.(s);

  /** Keeps a holder signature only if it is a valid signature by a pinned holder not already counted. */
  const add = (s: HolderSig) => {
    const h = input.pinned.find((k) => k.keyId === s.keyId);
    if (!h) throw new PqBindingError('HOLDER_KEY_UNKNOWN');
    if (!mldsaVerify('ml-dsa-65', h.mlDsa65, msg, s.sig, CTX)) throw new PqBindingError('HOLDER_SIG_INVALID');
    if (sigs.some((x) => x.keyId === s.keyId)) throw new PqBindingError('DUPLICATE_HOLDER');
    if (sigs.length < 2) sigs.push({ keyId: s.keyId, sig: s.sig.slice() });
  };

  return {
    fields,
    status: (): 'waiting-for-second-holder' | 'ready' => (sigs.length >= 2 ? 'ready' : 'waiting-for-second-holder'),

    /** This device's holder signs with its vault key (the message never comes from outside). */
    async signWith(half: PqHalf): Promise<HolderSig> {
      progress('signing');
      const s = await signPqBinding(msg, { keyId: half.keyId, sign: (m) => half.sign(m, CTX) });
      add(s);
      return s;
    },

    /** Another holder's signature, received over the relay. */
    add,

    /**
     * Cross-signs with the slot key, verifies the whole binding with core, and only then submits the contracts record.
     * `crossSign` is the vault's FROST signer for this deal (`vault.signFrost`); a cancelled tap rejects, nothing is sent.
     */
    async finish(
      crossSign: (req: SignRequest) => Promise<Uint8Array>,
      submit: (b: z.infer<typeof PqBinding>) => Promise<void>,
    ): Promise<z.infer<typeof PqBinding>> {
      if (sigs.length < 2) throw new PqBindingError('BELOW_TWO_HOLDERS');
      progress('cross-signing');
      const crossSig = await crossSign({
        kind: 'tagged',
        tag: CTX,
        parts: [fields.dealSeal, fields.slotPub, fields.pqKeyHash],
      });
      progress('verifying');
      const res = verifyPqBinding({ ...fields, holderSigs: sigs, crossSig }, fields, input.pinned, (pub, m, sig) =>
        verifyEd25519Strict(sig, m, pub),
      );
      if (!res.ok) throw new PqBindingError(res.code);
      const record = PqBinding.parse({
        slot: input.slot,
        deal_seal: bytesToHex(fields.dealSeal),
        slot_pub: bytesToHex(fields.slotPub).toUpperCase(),
        pq_key_hash: bytesToHex(fields.pqKeyHash),
        holder_sigs: sigs.map((s) => ({ key_id: s.keyId, sig: toBase64(s.sig) })),
        cross_sig: bytesToHex(crossSig),
      });
      progress('submitting');
      await submit(record);
      return record;
    },
  };
}
