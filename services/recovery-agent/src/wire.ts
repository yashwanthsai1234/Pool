// The holder's side of the relay wire format (schema.ts in the coordinator is the shared definition): turns a core
// `FrostMsg` into a contracts message, signs it with both enrollment keys, and checks both signatures on the way in.
// A relay is not trusted, so a participant verifies the ML-DSA half too, not only core's Ed25519 half.
// Source: DESIGN 6.3 (every message is signed by the sender's enrollment keys), 6.13 (ML-DSA-65, context `legx/dsse/v1`)
import type { FrostSignedMessage } from '@legx/contracts/frost';
import type { Slot } from '@legx/contracts/values';
import {
  bytesToSign,
  type Decoded,
  decodeSigned,
  type RelayMessage,
  signedBytes,
  toCore,
} from '@legx/coordinator/frost/schema';
import { bytesToHex } from '@legx/core/dealcore';
import { FrostError, type FrostMsg, holderId } from '@legx/core/frost';
import { mldsaSign, mldsaVerify, toBase64 } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { z } from 'zod';
import { XWING_ENC_LENGTH } from './cipher.ts';

const RELAY_CONTEXT = 'legx/dsse/v1';
const hex = bytesToHex;
const b64 = toBase64;

export type Signed = z.infer<typeof FrostSignedMessage>;

/** A holder's enrollment key pair as it signs: the key id of the pair, the Ed25519 seed and the ML-DSA-65 secret key. */
export interface HolderKeys {
  readonly keyId: string;
  readonly edSecret: Uint8Array;
  readonly pqSecret: Uint8Array;
}

/** Everything a holder knows about another holder, pinned out of band. */
export interface HolderInfo {
  readonly identifier: string;
  readonly keyId: string;
  readonly role: string;
  /** 33 bytes, 0xED then the Ed25519 key (the XRPL form core uses). */
  readonly edPub: Uint8Array;
  readonly pqPub: Uint8Array;
  readonly deviceId: string;
}

export interface WireContext {
  readonly dealId: string;
  readonly slot: Slot;
  readonly holders: readonly HolderInfo[];
}

/** Signs the message bytes with both enrollment keys. */
export function signRelayMessage(message: RelayMessage, keys: HolderKeys): Signed {
  const payload = new TextEncoder().encode(JSON.stringify(message));
  const bytes = bytesToSign(message, payload);
  return {
    payload: b64(payload),
    key_id: keys.keyId,
    signatures: [
      { keyid: `${keys.keyId}#ed25519`, sig: b64(ed25519.sign(bytes, keys.edSecret)) },
      { keyid: `${keys.keyId}#ml-dsa-65`, sig: toBase64(mldsaSign('ml-dsa-65', keys.pqSecret, bytes, RELAY_CONTEXT)) },
    ],
  } as Signed;
}

const header = (ctx: WireContext, m: FrostMsg) => ({
  session_id: hex(m.session),
  deal_id: ctx.dealId,
  slot: ctx.slot,
  from: holderId(m.from),
});
const box = (ctx: WireContext, m: FrostMsg, blob: Uint8Array) => ({
  suite: 'hpke-xwing-v1' as const,
  recipient_key_id: (ctx.holders[m.to - 1] as HolderInfo).keyId,
  enc: b64(blob.slice(0, XWING_ENC_LENGTH)),
  ciphertext: b64(blob.slice(XWING_ENC_LENGTH)),
});

/** What a complaint needs beyond the core message: the accused's round-2 message as received, and the opened share. */
export interface ComplaintExtra {
  readonly accusedMessage: Signed;
  readonly decryptedShare: Uint8Array;
}
export interface RefreshExtra {
  readonly epoch: number;
}

/** The contracts message for a core `FrostMsg` of the DKG or refresh. */
export function toWire(
  ctx: WireContext,
  m: FrostMsg,
  extra: { complaint?: ComplaintExtra; refresh?: RefreshExtra } = {},
): RelayMessage {
  const h = header(ctx, m);
  const f = m.fields;
  const epoch = extra.refresh?.epoch ?? 1;
  switch (m.kind) {
    case 'dkg-r1':
      return {
        ...h,
        kind: 'dkg.round1',
        commitment: [hex(f[0] as Uint8Array), hex(f[1] as Uint8Array)],
        proof_of_knowledge: hex(f[2] as Uint8Array),
        kem_pub: b64(f[3] as Uint8Array),
      } as RelayMessage;
    case 'dkg-echo':
      return { ...h, kind: 'dkg.echo', transcript_hash: hex(f[0] as Uint8Array) } as RelayMessage;
    case 'dkg-r2':
      return { ...h, kind: 'dkg.round2', to: holderId(m.to), box: box(ctx, m, f[0] as Uint8Array) } as RelayMessage;
    case 'dkg-complaint': {
      if (!extra.complaint) throw new FrostError('INPUT_INVALID', 'complaint needs the accused message');
      const accused = new DataView((f[0] as Uint8Array).buffer, (f[0] as Uint8Array).byteOffset).getUint32(0);
      return {
        ...h,
        kind: 'dkg.complaint',
        accused: holderId(accused),
        accused_message: b64(new TextEncoder().encode(JSON.stringify(extra.complaint.accusedMessage))),
        kem_secret: hex(f[3] as Uint8Array),
        decrypted_share: hex(extra.complaint.decryptedShare),
      } as RelayMessage;
    }
    case 'refresh-commit':
      return {
        ...h,
        kind: 'refresh.commit',
        epoch,
        commitment: [hex(f[0] as Uint8Array), hex(f[1] as Uint8Array)],
        kem_pub: b64(f[2] as Uint8Array),
      } as RelayMessage;
    case 'refresh-share':
      return {
        ...h,
        kind: 'refresh.subshare',
        epoch,
        to: holderId(m.to),
        box: box(ctx, m, f[0] as Uint8Array),
      } as RelayMessage;
    case 'refresh-deleted':
      return {
        ...h,
        kind: 'refresh.deleted',
        epoch,
        old_shares_hash: hex(f[0] as Uint8Array),
        new_shares_hash: hex(f[1] as Uint8Array),
      } as RelayMessage;
  }
}

/**
 * Opens an incoming relay message: strict decoding, then both signatures against the pinned keys of the named sender.
 * Returns the core message (its `sig` is the Ed25519 half) for the core round functions, which check it again.
 */
export function openRelayed(ctx: WireContext, signed: Signed): { decoded: Decoded; core: FrostMsg } {
  const decoded = decodeSigned(signed);
  const sender = ctx.holders.find((h) => h.identifier === decoded.message.from);
  const from = ctx.holders.findIndex((h) => h.identifier === decoded.message.from) + 1;
  if (!sender || sender.keyId !== decoded.keyId) throw new FrostError('ENROLLMENT_SIG_INVALID', 'unknown sender', from);
  const bytes = signedBytes(decoded);
  if (
    decoded.message.deal_id !== ctx.dealId ||
    decoded.message.slot !== ctx.slot ||
    !ed25519.verify(decoded.edSig, bytes, sender.edPub.slice(1), { zip215: false }) ||
    !mldsaVerify('ml-dsa-65', sender.pqPub, bytes, decoded.pqSig, RELAY_CONTEXT)
  )
    throw new FrostError('ENROLLMENT_SIG_INVALID', `from ${from}`, from);
  return { decoded, core: toCore(decoded) };
}
