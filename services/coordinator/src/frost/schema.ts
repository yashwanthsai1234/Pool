// The relay's wire format (DESIGN 6.3, 6.4; IMPLEMENTATION 3.9). A relay message is a contracts `FrostSignedMessage`:
// the exact JSON bytes of a `FrostMessage` plus the sender's two enrollment signatures. Both signatures cover one
// byte string, `signedBytes`, which is core's `frostMsgBytes` (tag `legx/frost-msg/v1`, with the session id, kind,
// sender and recipient inside). So the Ed25519 half IS the `sig` of the core `FrostMsg` and the core round functions
// (task 1.15) consume the message unchanged. Kinds core has no `MsgKind` for (signing, repair, abort) put the
// SHA-256 of the payload bytes in `fields`, so every field of those is signed.
// Source: https://www.rfc-editor.org/rfc/rfc9591 (FROST), https://frost.zfnd.org/tutorial/dkg.html (round 2 is private)
import { FrostMessage, FrostSignedMessage } from '@legx/contracts/frost';
import { hexToBytes, sha256 } from '@legx/core/dealcore';
import { type FrostMsg, frostMsgBytes, idScalar, type MsgKind, u32 } from '@legx/core/frost';
import { fromBase64Strict } from '@legx/core/pq';
import type { z } from 'zod';

const hex = (s: string): Uint8Array => hexToBytes(s);

export type RelayMessage = z.infer<typeof FrostMessage>;
export type RelayKind = RelayMessage['kind'];
type Kind<K extends RelayKind> = Extract<RelayMessage, { kind: K }>;

/** The identifier's holder index (1, 2 or 3). */
export const indexOf = (id: string): number => Number(idScalar(id));

/** Kinds that go to one named receiver. */
export const DIRECT_KINDS: ReadonlySet<RelayKind> = new Set([
  'dkg.round2',
  'refresh.subshare',
  'repair.delta',
  'repair.sigma',
]);
export const recipientOf = (m: RelayMessage): string | undefined => ('to' in m ? m.to : undefined);

export interface Decoded {
  readonly payload: Uint8Array;
  readonly message: RelayMessage;
  readonly keyId: string;
  readonly edSig: Uint8Array;
  readonly pqSig: Uint8Array;
}

export class WireError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = 'WireError';
    this.code = code;
  }
}

/** Strict decoding: base64 that round-trips, JSON that matches the schema, signatures named for the pair's two halves. */
export function decodeSigned(signed: z.infer<typeof FrostSignedMessage>): Decoded {
  const payload = fromBase64Strict(signed.payload);
  if (!payload) throw new WireError('payload_base64');
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload));
  } catch {
    throw new WireError('payload_json');
  }
  const parsed = FrostMessage.safeParse(json);
  if (!parsed.success) throw new WireError('payload_schema');
  const [ed, pq] = signed.signatures;
  if (ed.keyid !== `${signed.key_id}#ed25519` || pq.keyid !== `${signed.key_id}#ml-dsa-65`)
    throw new WireError('signature_key_ids');
  const edSig = fromBase64Strict(ed.sig);
  const pqSig = fromBase64Strict(pq.sig);
  if (!edSig || !pqSig) throw new WireError('signature_base64');
  return { payload, message: parsed.data, keyId: signed.key_id, edSig, pqSig };
}

const boxBytes = (b: { enc: string; ciphertext: string }): Uint8Array => {
  const enc = fromBase64Strict(b.enc);
  const ct = fromBase64Strict(b.ciphertext);
  if (!enc || !ct) throw new WireError('box_base64');
  return new Uint8Array([...enc, ...ct]);
};

/** The inner signed round-2 message of a complaint: its ciphertext and the accused's Ed25519 signature over it. */
function accusedParts(m: Kind<'dkg.complaint'>): { ct: Uint8Array; sig: Uint8Array } {
  const raw = fromBase64Strict(m.accused_message);
  if (!raw) throw new WireError('accused_message_base64');
  let inner: Decoded;
  try {
    inner = decodeSigned(FrostSignedMessage.parse(JSON.parse(new TextDecoder().decode(raw))));
  } catch {
    throw new WireError('accused_message_malformed');
  }
  if (inner.message.kind !== 'dkg.round2' || inner.message.from !== m.accused)
    throw new WireError('accused_message_wrong');
  return { ct: boxBytes(inner.message.box), sig: inner.edSig };
}

/** The core `FrostMsg` for a decoded message: `sig` is the Ed25519 half, so core's `openEnrollmentMessage` accepts it. */
export function toCore(d: Decoded): FrostMsg {
  const m = d.message;
  const session = hex(m.session_id);
  const from = indexOf(m.from);
  const to = (recipientOf(m) ?? undefined) === undefined ? 0 : indexOf(recipientOf(m) as string);
  const make = (kind: MsgKind | string, fields: Uint8Array[]): FrostMsg => ({
    session,
    kind: kind as MsgKind,
    from,
    to,
    fields,
    sig: d.edSig,
  });
  switch (m.kind) {
    case 'dkg.round1':
      return make('dkg-r1', [
        ...m.commitment.map(hex),
        hex(m.proof_of_knowledge),
        fromBase64Strict(m.kem_pub) as Uint8Array,
      ]);
    case 'dkg.echo':
      return make('dkg-echo', [hex(m.transcript_hash)]);
    case 'dkg.round2':
      return make('dkg-r2', [boxBytes(m.box)]);
    case 'dkg.complaint': {
      const { ct, sig } = accusedParts(m);
      return make('dkg-complaint', [u32(indexOf(m.accused)), ct, sig, hex(m.kem_secret)]);
    }
    case 'refresh.commit':
      return make('refresh-commit', [...m.commitment.map(hex), fromBase64Strict(m.kem_pub) as Uint8Array]);
    case 'refresh.subshare':
      return make('refresh-share', [boxBytes(m.box)]);
    case 'refresh.deleted':
      return make('refresh-deleted', [hex(m.old_shares_hash), hex(m.new_shares_hash)]);
    default:
      return make(m.kind, [sha256(d.payload)]);
  }
}

/** What both enrollment signatures cover. */
export const signedBytes = (d: Decoded): Uint8Array => {
  const { sig: _sig, ...unsigned } = toCore(d);
  return frostMsgBytes(unsigned);
};

/** The bytes a sender signs for a message it has built (the same function, before a signature exists). */
export function bytesToSign(message: RelayMessage, payload: Uint8Array): Uint8Array {
  const zero = new Uint8Array(64);
  return signedBytes({ payload, message, keyId: '', edSig: zero, pqSig: zero });
}
