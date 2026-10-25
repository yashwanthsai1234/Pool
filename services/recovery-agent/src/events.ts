// The evidence events this service writes (DESIGN 8.1: `frost.dkg.completed`, `frost.signed`, `frost.refreshed`) and
// the port it writes them through. In production the port posts a hybrid-signed event to the coordinator's
// `events.append`; the demo and the tests keep them in memory. The `data` shapes are the contracts' strict schemas.

import { bytesToHex } from '@legx/core/dealcore';
import { holderId, type SlotPublic } from '@legx/core/frost';
import type { DkgCompleted, DkgContext } from '@legx/core/frostDkg';
import type { FrostRefreshed } from '@legx/core/frostRefresh';
import type { HolderInfo } from './wire.ts';

export type EvidenceKind =
  | 'frost.dkg.completed'
  | 'frost.signed'
  | 'frost.refreshed'
  | 'frost.recovery.requested'
  | 'frost.recovery.cancelled'
  | 'frost.recovery.authorized'
  | 'frost.recovery.signed'
  | 'frost.refused';

export interface EvidencePort {
  append(dealId: string, kind: EvidenceKind, data: Record<string, unknown>): Promise<void>;
}

/** An in-memory log for the demo profile and the tests. */
export class MemoryEvidence implements EvidencePort {
  readonly events: { dealId: string; kind: EvidenceKind; data: Record<string, unknown> }[] = [];
  async append(dealId: string, kind: EvidenceKind, data: Record<string, unknown>): Promise<void> {
    this.events.push({ dealId, kind, data });
  }
  ofKind(kind: EvidenceKind) {
    return this.events.filter((e) => e.kind === kind);
  }
}

const hex = (b: Uint8Array) => bytesToHex(b);
const edKeyId = (h: HolderInfo) => `${h.keyId}#ed25519`;
const shares = (pub: SlotPublic) =>
  [1, 2, 3].map((i) => ({ identifier: holderId(i), share: hex(pub.verifyingShares[holderId(i)] as Uint8Array) }));

/** `frost.dkg.completed` data (DESIGN 6.4 rule 5). */
export function dkgCompletedData(rec: DkgCompleted, ctx: DkgContext, holders: readonly HolderInfo[], pub: SlotPublic) {
  return {
    session_id: hex(ctx.sessionId),
    slot: rec.slot,
    group_pub: hex(rec.slotPub).toUpperCase(),
    slot_policy: hex(rec.slotPolicy),
    roles: holders.map((h) => h.role),
    transcript_hash: hex(rec.transcriptHash),
    holder_sigs: holders.map((h, i) => ({ key_id: edKeyId(h), sig: hex(rec.transcriptSigs[i] as Uint8Array) })),
    verifying_shares: shares(pub),
    test_sigs: rec.testSignatures.map((t) => hex(t.sig)),
  };
}

/** `frost.signed` data: written once the aggregate verified. */
export function signedData(input: {
  slot: string;
  messageHash: Uint8Array;
  signers: readonly [HolderInfo, HolderInfo];
  signature: Uint8Array;
}) {
  return {
    slot: input.slot,
    message_hash: hex(input.messageHash),
    signer_key_ids: [edKeyId(input.signers[0]), edKeyId(input.signers[1])],
    signature: hex(input.signature),
  };
}

/** `frost.recovery.signed` data (I-E6): the recovery that was used and the two holder roles that signed. */
export function recoverySignedData(recoveryId: string, slot: string, signers: readonly [HolderInfo, HolderInfo]) {
  return { recovery_id: recoveryId, slot, holder_roles: [signers[0].role, signers[1].role] };
}

/** `frost.refreshed` data. The status is not in the event: an event with fewer than three deletion signatures is incomplete. */
export function refreshedData(
  ev: FrostRefreshed,
  slot: string,
  epoch: number,
  groupPub: Uint8Array,
  holders: readonly HolderInfo[],
) {
  const vs = (m: Record<string, Uint8Array>) =>
    [1, 2, 3].map((i) => ({ identifier: holderId(i), share: hex(m[holderId(i)] as Uint8Array) }));
  return {
    slot,
    group_pub: `ED${hex(groupPub).toUpperCase()}`,
    epoch,
    old_verifying_shares: vs(ev.oldVerifyingShares),
    new_verifying_shares: vs(ev.newVerifyingShares),
    deletion_sigs: ev.statements.map((s) => ({ key_id: edKeyId(holders[s.from - 1] as HolderInfo), sig: hex(s.sig) })),
  };
}
