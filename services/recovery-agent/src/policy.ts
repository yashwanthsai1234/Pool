// The co-signing check a holder runs on the exact message before it signs a share (DESIGN 6.4 "Signing rules"): it
// decodes the message itself and passes it to task 1.15's allow-list (`cosign`). A refusal comes before any nonce is
// used (`SigningSession.signShare` runs the check first).
//  - XRPL multisign messages are decoded from their bytes and must match the sealed deal (wallet, destination, amount).
//  - Tagged `tupleHash` messages travel with their preimage in `sign.begin`; the tag must be on the allow-list and the
//    parts must match the seal. A holder that signs exits only (the recovery agent) refuses every tagged message.
// Source: https://xrpl.org/docs/references/protocol/binary-format (multisigning prefix 0x534D5400 and the signer suffix)

import type { RelayMessage } from '@legx/coordinator/frost/schema';
import { bytesToHex, sha256, tupleHash } from '@legx/core/dealcore';
import type { CheckResult, Commitment, SlotName } from '@legx/core/frost';
import { type Approval, type ApproverKey, cosign, type SealedDeal } from '@legx/core/frostRules';
import { decode } from 'xrpl';

export type SignMessage = Extract<RelayMessage, { kind: 'sign.request' }>;

/** The decision a signer makes about the exact message and the commitment list (task 1.15 `cosign` or a test check). */
export type SignBegin = Extract<RelayMessage, { kind: 'sign.begin' }>;
export interface SignContext {
  readonly request: SignMessage | undefined;
  readonly begin: SignBegin | undefined;
}
export type SignCheck = (msg: Uint8Array, list: readonly Commitment[], ctx: SignContext) => CheckResult;

export interface CosignOptions {
  /** The recovery agent signs XRPL exits only. */
  readonly exitsOnly?: boolean;
  /** The WebAuthn key of the approving device, for roles that need a user-verified approval. */
  readonly approver?: ApproverKey;
}

/** The 6.17 gate record is signed as the SHA-256 of its envelope, not as a `tupleHash`: its preimage is the envelope. */
export const GATE_RECORD_TAG = 'legx/gate-record/v1';

/** The bytes a tagged message signs, from its preimage. */
export const taggedMessage = (tag: string, parts: readonly Uint8Array[]): Uint8Array =>
  tag === GATE_RECORD_TAG ? sha256(parts[0] ?? new Uint8Array()) : tupleHash(tag, [...parts]);

const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

export function cosignCheck(
  deal: SealedDeal,
  slot: SlotName,
  role: Parameters<typeof cosign>[0]['role'],
  o: CosignOptions = {},
): SignCheck {
  return (msg, _list, { begin }) => {
    const approval: Approval | undefined = begin?.approval && {
      authenticatorData: b64(begin.approval.authenticator_data),
      clientDataJSON: b64(begin.approval.client_data_json),
      signature: b64(begin.approval.signature),
    };
    const base = {
      msg,
      deal,
      slot,
      role,
      ...(approval ? { approval } : {}),
      ...(o.approver ? { approver: o.approver } : {}),
    };
    if (begin?.message_kind === 'xrpl-multisign') {
      let tx: Record<string, unknown>;
      try {
        // encodeForMultiSigning = prefix (4 bytes) || serialized transaction || signer account (20 bytes)
        tx = decode(bytesToHex(msg).toUpperCase().slice(8, -40)) as unknown as Record<string, unknown>;
      } catch {
        return { ok: false, reason: 'not an XRPL multisign message' };
      }
      return cosign({ ...base, request: { kind: 'xrpl-multisign', tx } });
    }
    if (o.exitsOnly || begin?.message_kind !== 'tagged' || !begin.tagged) return { ok: false, reason: 'message kind' };
    const parts = begin.tagged.parts.map((p) => new Uint8Array(Buffer.from(p, 'hex')));
    if (begin.tagged.tag === GATE_RECORD_TAG)
      return cosign({ ...base, request: { kind: 'gate-record', envelope: parts[0] ?? new Uint8Array() } });
    return cosign({ ...base, request: { kind: 'tagged', tag: begin.tagged.tag, parts } });
  };
}
