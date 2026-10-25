// Messages that FrostRelayPort carries between share holders (DESIGN 6.3, 6.4; IMPLEMENTATION 1.15, 3.9).
// The relay only ever sees public data: commitments, signature shares, transcript hashes and sealed boxes.
// A secret share travels only inside a SealedBox (HPKE X-Wing). The one share in the clear is a complaint's
// bad share from an aborted DKG, which is never used.
// Byte shapes follow @noble/curves 2.4.0 `abstract/frost.d.ts` (ed25519_FROST): identifiers are 32-byte
// scalars in hex, points 32 bytes, the proof of knowledge 64 bytes. Source: https://www.rfc-editor.org/rfc/rfc9591
import { z } from 'zod';
import { HybridSignatures, SealedBox } from './records.ts';
import { Base64, Base64Bytes, Hex32, Hex32Point, HexBytes, HexBytesRange, KeyId, Slot } from './values.ts';

/** noble `Identifier`: the participant's scalar, 32 bytes, lowercase hex. */
export const FrostIdentifier = HexBytes(32).brand<'FrostIdentifier'>();

/** RFC 9591 round-1 commitment of one signer. */
export const NonceCommitment = z.strictObject({
  identifier: FrostIdentifier,
  hiding: Hex32Point,
  binding: Hex32Point,
});

/** A user-verified WebAuthn approval by the lawyer over the same message hash (DESIGN 6.4; T-U-31a). Source: https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion */
export const WebAuthnApproval = z.strictObject({
  credential_id: Base64(1024),
  authenticator_data: Base64(1024),
  client_data_json: Base64(4096),
  signature: Base64(512),
  message_hash: Hex32,
});

const MessageKind = z.enum(['xrpl-multisign', 'tagged']);

/** A tagged `tupleHash` message travels with its preimage, so every signer decodes the exact message (DESIGN 6.4). */
export const TaggedPreimage = z.strictObject({
  tag: z.string().regex(/^legx\/[a-z0-9-]{1,64}\/v[0-9]{1,3}$/),
  parts: z.array(HexBytesRange(0, 16384)).max(16),
});

const Header = {
  session_id: Hex32,
  deal_id: z.uuid({ version: 'v7' }),
  slot: Slot,
  from: FrostIdentifier,
};

/** Every relay message kind. The session id and the recipient are inside the signed bytes (P1.15-02). */
export const FrostMessage = z.discriminatedUnion('kind', [
  // DKG round 1: echo-broadcast VSS commitment (threshold 2, so 2 points) and proof of knowledge.
  z.strictObject({
    ...Header,
    kind: z.literal('dkg.round1'),
    commitment: z.tuple([Hex32Point, Hex32Point]),
    proof_of_knowledge: HexBytes(64),
    kem_pub: Base64Bytes(1216), // fresh per-session X-Wing public key; round-2 shares are sealed to it
  }),
  // After round 1 every holder signs the hash of the full round-1 transcript (DESIGN 6.4 rule 2).
  z.strictObject({ ...Header, kind: z.literal('dkg.echo'), transcript_hash: Hex32 }),
  // DKG round 2: the signing share for one receiver, sealed to that receiver's enrollment key (rule 3).
  z.strictObject({ ...Header, kind: z.literal('dkg.round2'), to: FrostIdentifier, box: SealedBox }),
  // A signed complaint (DESIGN 6.4 rule 3): the accused's signed round-2 message, ciphertext included, the
  // complainant's per-session X-Wing secret (so anyone can open that ciphertext) and the decrypted share. Anyone
  // checks the share against the accused's Feldman commitments; the DKG then aborts and restarts with fresh
  // randomness, so revealing this session key and this bad share costs nothing.
  z.strictObject({
    ...Header,
    kind: z.literal('dkg.complaint'),
    accused: FrostIdentifier,
    accused_message: Base64(131072), // exact bytes of the accused's signed dkg.round2 FrostSignedMessage
    kem_secret: HexBytes(32), // X-Wing secret (32-byte seed) whose public key the complainant sent in dkg.round1
    decrypted_share: Hex32Point, // the share the box opened to (a scalar, 32 bytes)
  }),
  // Signing round 0: the aggregator sends the exact message and the commitment list; every signer decodes it.
  z.strictObject({
    ...Header,
    kind: z.literal('sign.request'),
    message: HexBytesRange(32, 16384),
    message_kind: MessageKind,
    commitments: z.tuple([NonceCommitment, NonceCommitment]),
    approval: WebAuthnApproval.optional(), // required by the firm-hsm and second-authenticator holders
    tagged: TaggedPreimage.optional(), // required when message_kind is `tagged`
  }),
  // Signing round 0 from the primary holder to a server holder (firm HSM, recovery agent): the exact message and
  // the opener's first commitment, so the server holder can open its side of the session (task 3.9).
  z.strictObject({
    ...Header,
    kind: z.literal('sign.begin'),
    message: HexBytesRange(32, 16384),
    message_kind: MessageKind,
    commitment: NonceCommitment,
    approval: WebAuthnApproval.optional(),
    tagged: TaggedPreimage.optional(),
  }),
  // Signing round 1: a fresh commitment for one message hash.
  z.strictObject({ ...Header, kind: z.literal('sign.commit'), message_hash: Hex32, commitment: NonceCommitment }),
  // Signing round 2: the signature share (a public scalar), bound to the message and commitment list.
  z.strictObject({
    ...Header,
    kind: z.literal('sign.share'),
    message_hash: Hex32,
    commitments_hash: Hex32,
    share: Hex32Point,
  }),
  // Refresh: a zero-constant dealing; commitment[0] must be the identity point (P1.15-15).
  z.strictObject({
    ...Header,
    kind: z.literal('refresh.commit'),
    epoch: z.int().min(1),
    commitment: z.tuple([Hex32Point, Hex32Point]),
    kem_pub: Base64Bytes(1216), // the dealer's per-session X-Wing key; sub-shares to it are sealed to it
  }),
  z.strictObject({
    ...Header,
    kind: z.literal('refresh.subshare'),
    epoch: z.int().min(1),
    to: FrostIdentifier,
    box: SealedBox,
  }),
  // Deletion statement of an old share (P1.15-18).
  // The statement signs the hashes of the old and the new verifying shares (task 3.9).
  z.strictObject({
    ...Header,
    kind: z.literal('refresh.deleted'),
    epoch: z.int().min(0),
    old_shares_hash: Hex32,
    new_shares_hash: Hex32,
  }),
  // Repair: the new holder's per-session X-Wing key, so helpers can seal their sigmas to it.
  z.strictObject({ ...Header, kind: z.literal('repair.hello'), kem_pub: Base64Bytes(1216) }),
  // Repair (DESIGN 6.4): a helper sends a sealed delta to each other helper, with public commitments
  // D_ij = delta_ij * G to all its deltas, so a cheating helper can be named.
  z.strictObject({
    ...Header,
    kind: z.literal('repair.delta'),
    to: FrostIdentifier,
    box: SealedBox,
    delta_commitments: z.tuple([
      z.strictObject({ to: FrostIdentifier, commitment: Hex32Point }),
      z.strictObject({ to: FrostIdentifier, commitment: Hex32Point }),
    ]),
  }),
  // Repair: a helper's sigma (the sum of the deltas it received), sealed to the new holder.
  z.strictObject({ ...Header, kind: z.literal('repair.sigma'), to: FrostIdentifier, box: SealedBox }),
  z.strictObject({ ...Header, kind: z.literal('abort'), reason: z.string().regex(/^[A-Z_]{1,64}$/) }),
]);
export type FrostMessage = z.infer<typeof FrostMessage>;
export const FROST_MESSAGE_KINDS = FrostMessage.options.map((o) => o.shape.kind.value);

/** A relay message as sent: the exact JSON bytes of a FrostMessage plus the sender's hybrid enrollment signatures. */
export const FrostSignedMessage = z.strictObject({
  payload: Base64(131072),
  key_id: KeyId,
  signatures: HybridSignatures,
});
