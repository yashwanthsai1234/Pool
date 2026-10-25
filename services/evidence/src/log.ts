// Module `log` (DESIGN 8.2, 8.9): every stored envelope becomes a leaf of the Merkle log, `evidence_log_entry` records
// its index in a separate insert, checkpoints are C2SP signed notes with both lines (0x01 Ed25519, 0x06 ML-DSA-44), and
// every envelope and checkpoint is copied to the WORM store. `verifyDeal` is the check that a rewrite of Postgres
// cannot pass: the row, the WORM copy, the signatures, the chain, the log and the head must all agree.
// Source: https://www.rfc-editor.org/rfc/rfc9162#section-2.1 (tree, inclusion proofs)
// Source: https://c2sp.org/tlog-checkpoint and https://c2sp.org/signed-note (checkpoint format)
// Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html (the WORM copy)
import type { Checkpoint, ObjectStorePort, TransparencyLogPort } from '@legx/contracts/ports';
import { verifyInclusion } from '@legx/core/dealcore';
import { leafHashOf, ZERO } from '@legx/core/evidence';
import { type HybridCode, type KeyRegistry, verifyHybrid } from '@legx/core/hybridEnvelope';
import { type CheckpointCode, type CheckpointKeys, verifyCheckpoint } from '@legx/core/pqCheckpoint';
import type { Database, EvidenceEventRow } from '@legx/db';
import { parseEnvelope } from './events.ts';
import { serial } from './serial.ts';

const utf8 = new TextEncoder();
const hexToBytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

export class WormConflict extends Error {
  readonly key: string;
  constructor(key: string) {
    super(`the WORM store already holds different bytes under ${key}`);
    this.name = 'WormConflict';
    this.key = key;
  }
}

export const envelopeKey = (leafHash: string) => `envelopes/${leafHash}`;
export const checkpointKey = (treeSize: number, root: string) =>
  `checkpoints/${String(treeSize).padStart(16, '0')}-${root}`;

/** Same bytes under a key is a no-op; different bytes is refused (P3.4-09). Returns whether this call created it. */
export async function putWorm(
  objects: ObjectStorePort,
  key: string,
  bytes: Uint8Array,
  retainDays: number,
): Promise<boolean> {
  const r = await objects.put(key, bytes, retainDays);
  if (r.status === 'conflict') throw new WormConflict(key);
  return r.status === 'created';
}

export interface LogDeps {
  readonly db: Database;
  readonly log: TransparencyLogPort;
  readonly objects: ObjectStorePort;
  readonly retainDays: number;
  /** The deal head as `deal_head` reports it (the events module's `head`). */
  readonly head: (dealId: string) => Promise<{ nextSeq: number }>;
}

export interface PublishedCheckpoint {
  readonly checkpoint: Checkpoint;
  readonly note: Uint8Array;
}

export type Problem =
  | { readonly seq: number; readonly code: 'LEAF_HASH_MISMATCH' | 'WORM_MISSING' | 'WORM_MISMATCH' | 'CHAIN_BROKEN' }
  | { readonly seq: number; readonly code: 'SIGNATURE_INVALID'; readonly detail: HybridCode }
  | { readonly seq: number; readonly code: 'NOT_IN_LOG' | 'INCLUSION_FAILED' }
  | { readonly seq: number; readonly code: 'HEAD_MISMATCH' }
  | { readonly seq: -1; readonly code: 'CHECKPOINT_INVALID' | 'NO_CHECKPOINT'; readonly detail?: CheckpointCode };

export interface IntegrityReport {
  readonly ok: boolean;
  readonly problems: readonly Problem[];
  /** Events newer than the checkpoint: covered by the chain and the WORM copy, not yet by the log. */
  readonly uncheckpointed: number;
}

export function createLogService(deps: LogDeps) {
  const { db, log, objects, retainDays } = deps;
  // The log numbers leaves in the order they are added, so adds are serialized in this process. A second process
  // needs an advisory lock around `integrate` (known gap, status file).
  const exclusive = serial();

  /** Copies the envelope to WORM, adds the leaf, records the index. Safe to repeat: a known event is not added twice. */
  const integrate = (row: Pick<EvidenceEventRow, 'event_id' | 'envelope' | 'leaf_hash'>): Promise<number> =>
    exclusive(async () => {
      const known = await db.repos.evidenceLogEntries.get(row.event_id);
      if (known !== undefined) return known;
      await putWorm(objects, envelopeKey(row.leaf_hash), row.envelope, retainDays);
      const { index } = await log.add(row.envelope);
      await db.repos.evidenceLogEntries.insert(row.event_id, index);
      return index;
    });

  return {
    integrate,

    /** After a crash between commit and integration: adds every event of the deal that has no log entry yet. */
    async integratePending(dealId: string): Promise<number> {
      let n = 0;
      for (const row of await db.repos.evidenceEvents.listAfter(dealId, -1, 100_000)) {
        if ((await db.repos.evidenceLogEntries.get(row.event_id)) === undefined) {
          await integrate(row);
          n++;
        }
      }
      return n;
    },

    /**
     * A hybrid checkpoint of the whole log, copied to WORM and recorded in `checkpoint_anchor`. A tree size already
     * published keeps its first note: the ML-DSA line is randomized, so a second signing would be different bytes.
     */
    async checkpoint(): Promise<PublishedCheckpoint> {
      const fresh = await log.checkpoint();
      const key = checkpointKey(fresh.treeSize, fresh.rootHash);
      const stored = await objects.get(key);
      const note = stored ?? utf8.encode(fresh.note);
      if (!stored) await putWorm(objects, key, note, retainDays);
      await db.repos.checkpointAnchors.insert({ tree_size: fresh.treeSize, root: fresh.rootHash, checkpoint: note });
      return { checkpoint: { ...fresh, note: new TextDecoder().decode(note) }, note };
    },

    /**
     * What a verifier does with the deal as Postgres reports it. A superuser who edits a row, deletes one, or rewrites
     * the head fails at least one of: the stored hash, the WORM copy, the signature, the chain, the log, the head.
     */
    async verifyDeal(
      dealId: string,
      o: { registry: KeyRegistry; at: number; origin: string; keys: CheckpointKeys },
    ): Promise<IntegrityReport> {
      const problems: Problem[] = [];
      const latest = await db.repos.checkpointAnchors.latest();
      let cp: { treeSize: number; rootHash: Uint8Array } | undefined;
      if (!latest) problems.push({ seq: -1, code: 'NO_CHECKPOINT' });
      else {
        const v = verifyCheckpoint(new TextDecoder().decode(latest.checkpoint), o.origin, o.keys);
        if (v.ok) cp = v;
        else problems.push({ seq: -1, code: 'CHECKPOINT_INVALID', detail: v.code });
      }

      const rows = await db.repos.evidenceEvents.listAfter(dealId, -1, 100_000);
      let prev = ZERO;
      let uncheckpointed = 0;
      for (const [i, r] of rows.entries()) {
        const bad = (
          code:
            | 'LEAF_HASH_MISMATCH'
            | 'WORM_MISSING'
            | 'WORM_MISMATCH'
            | 'CHAIN_BROKEN'
            | 'NOT_IN_LOG'
            | 'INCLUSION_FAILED',
        ) => problems.push({ seq: r.seq, code });
        if (leafHashOf(r.envelope) !== r.leaf_hash) bad('LEAF_HASH_MISMATCH');
        const worm = await objects.get(envelopeKey(r.leaf_hash));
        if (!worm) bad('WORM_MISSING');
        else if (!same(worm, r.envelope)) bad('WORM_MISMATCH');
        try {
          const { env, event } = parseEnvelope(r.envelope);
          const v = verifyHybrid(env, o.registry, o.at);
          if (!v.ok) problems.push({ seq: r.seq, code: 'SIGNATURE_INVALID', detail: v.code });
          const p = event.predicate;
          if (p.seq !== i || r.seq !== i || p.prev_hash !== prev || r.prev_hash !== prev) bad('CHAIN_BROKEN');
        } catch {
          problems.push({ seq: r.seq, code: 'SIGNATURE_INVALID', detail: 'MALFORMED' });
        }
        prev = r.leaf_hash;

        const index = await db.repos.evidenceLogEntries.get(r.event_id);
        if (index === undefined) bad('NOT_IN_LOG');
        else if (cp && index >= cp.treeSize) uncheckpointed++;
        else if (cp) {
          const path = (await log.inclusionProof(index, cp.treeSize)).map(hexToBytes);
          if (!verifyInclusion(r.envelope, index, cp.treeSize, path, cp.rootHash)) bad('INCLUSION_FAILED');
        }
      }
      // Dropping the newest events leaves a clean chain; only the head row, kept apart from the events, notices.
      if ((await deps.head(dealId)).nextSeq !== rows.length) problems.push({ seq: rows.length, code: 'HEAD_MISMATCH' });
      return { ok: problems.length === 0, problems, uncheckpointed };
    },
  };
}
