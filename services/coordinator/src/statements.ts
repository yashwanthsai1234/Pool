// Evidence events the coordinator makes itself (a deal's genesis, a pinned enrollment key, an exit it assembled, a
// close it saw validated). Each is a hybrid-signed in-toto statement appended inside the caller's transaction, with
// the outbox row that tells subscribers (OD-9). Source: DESIGN 8.1; IMPLEMENTATION P3.2-03.
import type { LegxEvent } from '@legx/contracts/events';
import type { SignerPort } from '@legx/contracts/ports';
import { sha256, utf8ToBytes } from '@legx/core/dealcore';
import { PAYLOAD_TYPE } from '@legx/core/evidence';
import { signHybrid } from '@legx/core/hybridEnvelope';
import type { EvidenceEventRow, Repos } from '@legx/db';
import { uuid7 } from './uuid.ts';

const ZERO32 = '00'.repeat(32);
export const RIPPLE_EPOCH = 946_684_800;
const enc = (o: unknown) => utf8ToBytes(JSON.stringify(o));

/** Coordinator statements that DESIGN 8.1 does not list yet (request to contracts in 3.2.md). */
export type LocalKind = 'deal.created' | 'enrollment.pinned';
export type StatementKind = LegxEvent['predicate']['kind'] | LocalKind;

export interface OutboxSummary {
  readonly kind: string;
  readonly state: string;
  readonly ledger?: { readonly tx_hash: string; readonly ledger_index: number };
}

/** The OD-9 outbox payload of a stored event: the exact stored envelope bytes plus a short summary. */
function outboxPayload(envelope: Uint8Array, summary: OutboxSummary): Uint8Array {
  return enc({ envelope: Buffer.from(envelope).toString('base64'), summary });
}

/**
 * The live-feed rows of a stored event, in its transaction: `deal.event` (the exact envelope bytes, OD-9) and `deal.state`
 * (the deal's state after it). Both take the deal's next outbox seq, one gap-free sequence for the whole feed (I-W-5).
 */
export async function enqueueStored(
  repos: Repos,
  dealId: string,
  row: EvidenceEventRow,
  summary: OutboxSummary,
): Promise<void> {
  await repos.outbox.enqueueNext(dealId, 'deal.event', outboxPayload(row.envelope, summary));
  await repos.outbox.enqueueNext(dealId, 'deal.state', enc({ dealId, eventSeq: row.seq, state: summary.state }));
}

/** The `signature.request` feed row of a new request, in the transaction that stores it. */
export async function enqueueSignatureRequest(
  repos: Repos,
  r: { dealId: string; requestId: string; purpose: string; lastLedger: number; status: string },
): Promise<void> {
  await repos.outbox.enqueueNext(r.dealId, 'signature.request', enc(r));
}

export interface CoordinatorStatement {
  readonly dealId: string;
  readonly kind: StatementKind;
  readonly data: Record<string, unknown>;
  readonly contractRoot: string;
  /** Validated ledger close time (Ripple epoch seconds): the claimed time of the event. */
  readonly closeTime: number;
  /**
   * Runs inside the head lock, before the event is built: read the deal, apply the transition, write the state. Returns
   * the deal's state after it (for the outbox summary). Throwing rolls the whole transaction back.
   */
  readonly beforeAppend: () => Promise<string>;
  readonly ledger?: { tx_hash: string; ledger_index: number };
}

/** Appends one coordinator-signed event and its outbox row. Call on a transaction's repos (the head row is locked). */
export async function appendCoordinatorEvent(
  repos: Repos,
  signer: SignerPort,
  s: CoordinatorStatement,
): Promise<EvidenceEventRow> {
  const keys = await signer.publicKeys();
  let state = '';
  const row = await repos.evidenceEvents.appendNext(s.dealId, async (head) => {
    state = await s.beforeAppend();
    const statement = {
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{ name: `deal:${s.dealId}`, digest: { sha256: s.contractRoot } }],
      predicateType: 'https://legx.dev/event/v1',
      predicate: {
        event_id: uuid7(),
        deal_id: s.dealId,
        seq: head.nextSeq,
        kind: s.kind,
        actor: { role: 'coordinator', key_id: keys.keyIds.ed25519 },
        occurred_at: new Date((s.closeTime + RIPPLE_EPOCH) * 1000).toISOString(),
        prev_hash: head.prevHash,
        payload_commitment: ZERO32,
        ...(s.ledger ? { ledger: { ...s.ledger, validated: true } } : {}),
        sig_algs: ['ed25519', 'ml-dsa-65'],
        data: s.data,
      },
    };
    const env = await signHybrid(PAYLOAD_TYPE, enc(statement), signer);
    const bytes = enc(env);
    return { envelope: bytes, leaf_hash: Buffer.from(sha256(bytes)).toString('hex') };
  });
  await enqueueStored(repos, s.dealId, row, {
    kind: s.kind,
    state,
    ...(s.ledger ? { ledger: s.ledger } : {}),
  });
  return row;
}
