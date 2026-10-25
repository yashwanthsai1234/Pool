// The browser side of the FROST relay wire format (task 3.9). A relay message is a contracts `FrostSignedMessage`: the
// exact JSON bytes of a `FrostMessage` plus the sender's two enrollment signatures (Ed25519 and ML-DSA-65). Both
// signatures cover one byte string: core's `frostMsgBytes` of the matching core `FrostMsg`, so the Ed25519 half is the
// core `sig` and task 1.15's round functions consume the message unchanged. Kinds core has no `MsgKind` for (signing,
// repair, abort) sign `[sha256(payload)]`.
// This mirrors `services/coordinator/src/frost/schema.ts` and `services/recovery-agent/src/wire.ts`, which use Node's
// `Buffer` and so cannot run here (OD-27). `test/frost/interop.test.ts` checks byte equality with both, kind by kind.
// The relay is untrusted: every incoming message is checked against the sender's pinned keys (both halves) here,
// and again by core (Ed25519) before any content is used.
// Source: DESIGN 6.3, 6.4, 6.13; https://www.rfc-editor.org/rfc/rfc9591
import { FrostMessage, FrostSignedMessage } from '@legx/contracts/frost';
import { tupleHash } from '@legx/core/dealcore';
import {
  FrostError,
  type FrostMsg,
  frostMsgBytes,
  holderId,
  idScalar,
  type MsgKind,
  type Role,
  u32,
  verifyEd25519Strict,
} from '@legx/core/frost';
import { fromBase64Strict, mldsaVerify, toBase64 } from '@legx/core/pq';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { z } from 'zod';
import { XWING_ENC_LENGTH } from './cipher.ts';

/** ML-DSA context of relay messages (as 3.9; DQ-3.9-1). */
export const RELAY_CONTEXT = 'legx/dsse/v1' as const;

export type Signed = z.infer<typeof FrostSignedMessage>;
type Wire = z.infer<typeof FrostMessage>;
type Header = { session_id: string; deal_id: string; slot: 'A' | 'B' | 'LA' | 'LB'; from: string };
type Commit = { identifier: string; hiding: string; binding: string };
type Approval = Extract<Wire, { kind: 'sign.request' }>['approval'];

/** 3.9's wire kinds: the contracts union, with `refresh.commit`/`refresh.deleted` widened and two new kinds. */
export type RelayMessage =
  | Exclude<Wire, { kind: 'refresh.commit' | 'refresh.deleted' }>
  | (Header & { kind: 'refresh.commit'; epoch: number; commitment: [string, string]; kem_pub: string })
  | (Header & { kind: 'refresh.deleted'; epoch: number; old_shares_hash: string; new_shares_hash: string })
  | (Header & {
      kind: 'sign.begin';
      message: string;
      message_kind: 'xrpl-multisign' | 'tagged';
      commitment: Commit;
      approval?: Approval;
      tagged?: { tag: string; parts: string[] };
    })
  | (Header & { kind: 'repair.hello'; kem_pub: string });
export type RelayKind = RelayMessage['kind'];
export type OfKind<K extends RelayKind> = Extract<RelayMessage, { kind: K }>;

/** A holder of the slot as every other holder pinned it (DESIGN 6.3). */
export interface HolderInfo {
  readonly identifier: string;
  readonly keyId: string;
  readonly role: Role;
  /** 33 bytes, 0xED then the Ed25519 key. */
  readonly edPub: Uint8Array;
  readonly pqPub: Uint8Array;
  readonly deviceId: string;
  /** What the screens call this holder ("Your phone", "Recovery agent ..."). */
  readonly label: string;
}

export interface WireContext {
  readonly dealId: string;
  readonly slot: 'A' | 'B' | 'LA' | 'LB';
  readonly holders: readonly HolderInfo[];
}

/** A holder's enrollment key pair as it signs. Both halves are async (WebCrypto, task 4.9's ML-DSA). */
export interface PartyKeys {
  readonly keyId: string;
  signEd(msg: Uint8Array): Promise<Uint8Array>;
  signPq(msg: Uint8Array): Promise<Uint8Array>;
}

const enc = new TextEncoder();
const b64 = (b: Uint8Array): string => toBase64(b);
const unb64 = (s: string): Uint8Array => {
  const b = fromBase64Strict(s);
  if (!b) throw new FrostError('INPUT_INVALID', 'base64');
  return b;
};
export const hex = (b: Uint8Array): string => bytesToHex(b);
export const unhex = (s: string): Uint8Array => hexToBytes(s);
/** The holder index (1, 2 or 3) of a FROST identifier. */
export const indexOf = (id: string): number => Number(idScalar(id));

export const boxBytes = (b: { enc: string; ciphertext: string }): Uint8Array => {
  const e = unb64(b.enc);
  const ct = unb64(b.ciphertext);
  const out = new Uint8Array(e.length + ct.length);
  out.set(e);
  out.set(ct, e.length);
  return out;
};
export const sealedBox = (to: HolderInfo, blob: Uint8Array) => ({
  suite: 'hpke-xwing-v1' as const,
  recipient_key_id: to.keyId,
  enc: b64(blob.slice(0, XWING_ENC_LENGTH)),
  ciphertext: b64(blob.slice(XWING_ENC_LENGTH)),
});

/** Strict decoding of the signed envelope (canonical base64, fatal UTF-8, the payload schema). */
export function decodeSigned(signed: Signed): {
  payload: Uint8Array;
  message: RelayMessage;
  edSig: Uint8Array;
  pqSig: Uint8Array;
} {
  if (!FrostSignedMessage.safeParse(signed).success) throw new FrostError('INPUT_INVALID', 'envelope');
  const payload = unb64(signed.payload);
  let message: RelayMessage;
  try {
    message = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload)) as RelayMessage;
  } catch {
    throw new FrostError('INPUT_INVALID', 'payload');
  }
  if (!isRelayMessage(message)) throw new FrostError('INPUT_INVALID', 'payload schema');
  const [ed, pq] = signed.signatures;
  if (ed.keyid !== `${signed.key_id}#ed25519` || pq.keyid !== `${signed.key_id}#ml-dsa-65`)
    throw new FrostError('INPUT_INVALID', 'signature key ids');
  return { payload, message, edSig: unb64(ed.sig), pqSig: unb64(pq.sig) };
}

const WIDE_KINDS = new Set(['refresh.commit', 'refresh.deleted', 'sign.begin', 'repair.hello']);
const HEX = (n: number) => new RegExp(`^[0-9a-f]{${2 * n}}$`);
/** The contracts schema for the narrow kinds; a structural check for 3.9's wide kinds (their full schema is 3.9's). */
function isRelayMessage(m: unknown): m is RelayMessage {
  const o = m as Record<string, unknown>;
  if (typeof o !== 'object' || o === null || typeof o.kind !== 'string') return false;
  if (!WIDE_KINDS.has(o.kind)) return FrostMessage.safeParse(m).success;
  const header =
    HEX(32).test(String(o.session_id)) &&
    HEX(32).test(String(o.from)) &&
    ['A', 'B', 'LA', 'LB'].includes(String(o.slot));
  return header && typeof o.deal_id === 'string';
}

/** The core `FrostMsg` for a decoded message (exactly 3.9's `toCore`). */
export function toCore(d: { payload: Uint8Array; message: RelayMessage; edSig: Uint8Array }): FrostMsg {
  const m = d.message;
  const to = 'to' in m ? indexOf(m.to) : 0;
  const make = (kind: string, fields: Uint8Array[]): FrostMsg => ({
    session: unhex(m.session_id),
    kind: kind as MsgKind,
    from: indexOf(m.from),
    to,
    fields,
    sig: d.edSig,
  });
  switch (m.kind) {
    case 'dkg.round1':
      return make('dkg-r1', [...m.commitment.map(unhex), unhex(m.proof_of_knowledge), unb64(m.kem_pub)]);
    case 'dkg.echo':
      return make('dkg-echo', [unhex(m.transcript_hash)]);
    case 'dkg.round2':
      return make('dkg-r2', [boxBytes(m.box)]);
    case 'dkg.complaint': {
      const inner = decodeSigned(JSON.parse(new TextDecoder().decode(unb64(m.accused_message))) as Signed);
      if (inner.message.kind !== 'dkg.round2' || inner.message.from !== m.accused)
        throw new FrostError('INPUT_INVALID', 'accused message');
      return make('dkg-complaint', [
        u32(indexOf(m.accused)),
        boxBytes(inner.message.box),
        inner.edSig,
        unhex(m.kem_secret),
      ]);
    }
    case 'refresh.commit':
      return make('refresh-commit', [...m.commitment.map(unhex), unb64(m.kem_pub)]);
    case 'refresh.subshare':
      return make('refresh-share', [boxBytes(m.box)]);
    case 'refresh.deleted':
      return make('refresh-deleted', [unhex(m.old_shares_hash), unhex(m.new_shares_hash)]);
    default:
      return make(m.kind, [sha256(d.payload)]);
  }
}

/** What both enrollment signatures cover. */
export function bytesToSign(message: RelayMessage, payload: Uint8Array): Uint8Array {
  const { sig: _sig, ...unsigned } = toCore({ payload, message, edSig: new Uint8Array(64) });
  return frostMsgBytes(unsigned);
}

/** Serializes and signs a message with both halves of the holder's enrollment key. */
export async function signRelayMessage(message: RelayMessage, keys: PartyKeys): Promise<Signed> {
  const payload = enc.encode(JSON.stringify(message));
  const bytes = bytesToSign(message, payload);
  const [ed, pq] = await Promise.all([keys.signEd(bytes), keys.signPq(bytes)]);
  return {
    payload: b64(payload),
    key_id: keys.keyId,
    signatures: [
      { keyid: `${keys.keyId}#ed25519`, sig: b64(ed) },
      { keyid: `${keys.keyId}#ml-dsa-65`, sig: b64(pq) },
    ],
  } as Signed;
}

const header = (ctx: WireContext, m: FrostMsg): Header => ({
  session_id: hex(m.session),
  deal_id: ctx.dealId,
  slot: ctx.slot,
  from: holderId(m.from),
});

/** The contracts message for a core DKG or refresh `FrostMsg` (3.9's `toWire`). */
export function toWire(
  ctx: WireContext,
  m: FrostMsg,
  extra: { accusedMessage?: Signed; epoch?: number } = {},
): RelayMessage {
  const h = header(ctx, m);
  const f = m.fields as Uint8Array[];
  const at = (i: number): Uint8Array => {
    const v = f[i];
    if (!v) throw new FrostError('INPUT_INVALID', `field ${i}`);
    return v;
  };
  const box = () => sealedBox(ctx.holders[m.to - 1] as HolderInfo, at(0));
  const epoch = extra.epoch ?? 1;
  switch (m.kind) {
    case 'dkg-r1':
      return {
        ...h,
        kind: 'dkg.round1',
        commitment: [hex(at(0)), hex(at(1))],
        proof_of_knowledge: hex(at(2)),
        kem_pub: b64(at(3)),
      } as RelayMessage;
    case 'dkg-echo':
      return { ...h, kind: 'dkg.echo', transcript_hash: hex(at(0)) } as RelayMessage;
    case 'dkg-r2':
      return { ...h, kind: 'dkg.round2', to: holderId(m.to), box: box() } as RelayMessage;
    case 'dkg-complaint': {
      if (!extra.accusedMessage) throw new FrostError('INPUT_INVALID', 'complaint needs the accused message');
      const accused = new DataView(at(0).buffer, at(0).byteOffset).getUint32(0);
      return {
        ...h,
        kind: 'dkg.complaint',
        accused: holderId(accused),
        accused_message: b64(enc.encode(JSON.stringify(extra.accusedMessage))),
        kem_secret: hex(at(3)),
        decrypted_share: hex(new Uint8Array(32)), // the revealed KEM secret lets anyone open the box (OD-16)
      } as RelayMessage;
    }
    case 'refresh-commit':
      return { ...h, kind: 'refresh.commit', epoch, commitment: [hex(at(0)), hex(at(1))], kem_pub: b64(at(2)) };
    case 'refresh-share':
      return { ...h, kind: 'refresh.subshare', epoch, to: holderId(m.to), box: box() } as RelayMessage;
    case 'refresh-deleted':
      return { ...h, kind: 'refresh.deleted', epoch, old_shares_hash: hex(at(0)), new_shares_hash: hex(at(1)) };
  }
}

/**
 * Opens an incoming relay message: strict decoding, then both signatures against the pinned keys of the named sender.
 * Returns the core message for the core round functions, which check the Ed25519 half again.
 */
export function openRelayed(ctx: WireContext, signed: Signed): { message: RelayMessage; core: FrostMsg } {
  const d = decodeSigned(signed);
  const from = ctx.holders.findIndex((h) => h.identifier === d.message.from) + 1;
  const sender = ctx.holders[from - 1];
  if (!sender || sender.keyId !== signed.key_id)
    throw new FrostError('ENROLLMENT_SIG_INVALID', 'unknown sender', from || undefined);
  const core = toCore(d);
  const bytes = bytesToSign(d.message, d.payload);
  if (
    d.message.deal_id !== ctx.dealId ||
    d.message.slot !== ctx.slot ||
    !verifyEd25519Strict(d.edSig, bytes, sender.edPub) ||
    !mldsaVerify('ml-dsa-65', sender.pqPub, bytes, d.pqSig, RELAY_CONTEXT)
  )
    throw new FrostError('ENROLLMENT_SIG_INVALID', `from ${from}`, from);
  return { message: d.message, core };
}

/** The commitment-list digest that goes in `sign.share` (3.9's `commitmentsDigest`). */
export const commitmentsDigest = (
  list: readonly { identifier: string; hiding: Uint8Array; binding: Uint8Array }[],
): string =>
  hex(
    tupleHash(
      'legx/frost-commitments/v1',
      [...list]
        .sort((a, b) => (idScalar(a.identifier) < idScalar(b.identifier) ? -1 : 1))
        .flatMap((c) => [unhex(c.identifier), c.hiding, c.binding]),
    ),
  );
