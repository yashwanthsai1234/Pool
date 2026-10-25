// Module `events` (DESIGN 8.1): who assigns `seq` and `prev_hash`, and how an envelope is stored.
//   nextSeq   -> the head a signer must put inside its payload
//   append    -> verify both signatures, then store in one transaction (event row, deal head, outbox row)
//   appendOwn -> the service's own events: nextSeq, sign, append, and on `seq_taken` fetch the head and sign again
// The database's UNIQUE (deal_id, seq) and the head row lock decide every race; nothing here trusts a client's seq.
// Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (PAE, envelope)
// Source: https://www.rfc-editor.org/rfc/rfc8785 (the JSON bytes we sign and store are canonical, so they are stable)
// Source: https://www.rfc-editor.org/rfc/rfc9562 (UUIDv7 event ids)
import { randomBytes } from 'node:crypto';
import { LegxEvent } from '@legx/contracts/events';
import type { AppendResult, ChainHead, ClockPort, SignerPort, StoredEvent } from '@legx/contracts/ports';
import type { Hex32 } from '@legx/contracts/values';
import { pairIdOf } from '@legx/coordinator/keys';
import { type Envelope, leafHashOf, PAYLOAD_TYPE, pae } from '@legx/core/evidence';
import { type HybridCode, type KeyRegistry, signHybrid, verifyHybrid } from '@legx/core/hybridEnvelope';
import type { Database, EvidenceEventRow, Repos } from '@legx/db';
import { SeqTaken } from '@legx/db';
import canonicalize from 'canonicalize';

/** KMS signs at most 4,096 raw bytes with Ed25519, and Ed25519 has no EXTERNAL_MU (task 3.6; AWS KMS Sign API). */
export const SERVICE_PAE_LIMIT = 4096;
export const MAX_APPEND_ATTEMPTS = 8;
export const OUTBOX_TOPIC = 'deal.event';

const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder('utf-8', { fatal: true });

export class EnvelopeRejected extends Error {
  readonly code: HybridCode | 'NOT_JSON' | 'SCHEMA' | 'DEAL_MISMATCH' | 'ACTOR_KEY_MISMATCH' | 'ACTOR_ROLE_MISMATCH';
  constructor(code: EnvelopeRejected['code'], detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'EnvelopeRejected';
    this.code = code;
  }
}
export class PaeTooLarge extends Error {
  readonly size: number;
  constructor(size: number) {
    super(`the PAE is ${size} bytes; the service key signs at most ${SERVICE_PAE_LIMIT} (Ed25519 has no EXTERNAL_MU)`);
    this.name = 'PaeTooLarge';
    this.size = size;
  }
}

/** UUIDv7: 48-bit millisecond time, version 7, variant 10, random rest. Source: https://www.rfc-editor.org/rfc/rfc9562#section-5.7 */
export function uuidv7(now: number = Date.now()): string {
  const b = randomBytes(16);
  b.writeUIntBE(now, 0, 6);
  b[6] = ((b[6] as number) & 0x0f) | 0x70;
  b[8] = ((b[8] as number) & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export const canonicalBytes = (x: unknown): Uint8Array => {
  const s = canonicalize(x);
  if (s === undefined) throw new Error('value has no JSON form');
  return utf8.encode(s);
};

/** What a signer chooses; the head supplies `seq` and `prev_hash`. */
export interface EventInput {
  readonly dealId: string;
  /** The deal's contract root: the in-toto subject digest. */
  readonly contractRoot: string;
  readonly kind: LegxEvent['predicate']['kind'];
  readonly data: unknown;
  readonly actor: { readonly role: LegxEvent['predicate']['actor']['role']; readonly keyId: string };
  readonly occurredAt: string;
  readonly payloadCommitment: string;
  readonly ledger?: { readonly txHash: string; readonly ledgerIndex: number };
  readonly traceId?: string;
  readonly eventId?: string;
}

/** The canonical in-toto Statement bytes for an event at `head`, validated against the contracts schema. */
export function eventBody(input: EventInput, head: ChainHead): Uint8Array {
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: `deal:${input.dealId}`, digest: { sha256: input.contractRoot } }],
    predicateType: 'https://legx.dev/event/v1',
    predicate: {
      event_id: input.eventId ?? uuidv7(),
      deal_id: input.dealId,
      seq: head.nextSeq,
      kind: input.kind,
      actor: { role: input.actor.role, key_id: input.actor.keyId },
      occurred_at: input.occurredAt,
      prev_hash: head.prevHash,
      payload_commitment: input.payloadCommitment,
      ...(input.ledger
        ? { ledger: { tx_hash: input.ledger.txHash, ledger_index: input.ledger.ledgerIndex, validated: true } }
        : {}),
      ...(input.traceId ? { trace_id: input.traceId } : {}),
      sig_algs: ['ed25519', 'ml-dsa-65'],
      data: input.data,
    },
  };
  return canonicalBytes(LegxEvent.parse(statement));
}

/** The exact bytes that are stored and hashed: canonical JSON of the DSSE envelope. */
export const envelopeBytes = (env: Envelope): Uint8Array => canonicalBytes(env);

/** Signs `body` as the service. Refuses before the signer is called if the PAE is beyond what the key can sign. */
export async function signAsService(signer: SignerPort, body: Uint8Array): Promise<Envelope> {
  const size = pae(PAYLOAD_TYPE, body).length;
  if (size > SERVICE_PAE_LIMIT) throw new PaeTooLarge(size);
  return signHybrid(PAYLOAD_TYPE, body, signer);
}

export interface EventsDeps {
  readonly db: Database;
  /** The keys that may sign this deal's events (enrollment keys plus service keys), loaded per call. */
  readonly registry: (dealId: string) => Promise<KeyRegistry>;
  /** Validated ledger time: the `at` the key validity windows are checked at (never the wall clock). */
  readonly clock: ClockPort;
  /** The service's own hybrid signer, for `appendOwn`. */
  readonly signer?: SignerPort;
  /** Runs after the event is committed (log integration, milestone anchors). A failure here never undoes the append. */
  readonly afterStore?: (row: EvidenceEventRow, event: LegxEvent) => Promise<void>;
}

const PARTY_ROLE_OF_SLOT: Readonly<Record<string, string>> = { A: 'alice', LA: 'lawyerA', B: 'bob', LB: 'lawyerB' };
const PARTY_ROLES: ReadonlySet<string> = new Set(Object.values(PARTY_ROLE_OF_SLOT));

/**
 * The key that signed an event is the key of the actor the event names (I-S-E4): an enrollment key signs only as the
 * role of its own slot, and a party key never signs as the coordinator, the verifier or the watcher. The key id inside
 * the statement must be the key that signed.
 * Source: DESIGN 8.2 (each event names its actor; that actor's enrollment key signs it), 6.3 (keys are bound to a slot)
 */
async function checkActor(
  db: Database,
  dealId: string,
  actor: { role: string; key_id: string },
  signingKeyId: string,
): Promise<void> {
  // An enrollment key is named by its pair id (the signature id minus `#ed25519`, I-3.7-e); a service key by itself.
  const named = pairIdOf(signingKeyId, 'ed25519') ?? signingKeyId;
  if (actor.key_id !== named) throw new EnvelopeRejected('ACTOR_KEY_MISMATCH');
  const row = (await db.repos.enrollmentKeys.listForDeal(dealId)).find((r) => r.key_id === named);
  if (row) {
    if (PARTY_ROLE_OF_SLOT[row.slot] !== actor.role) throw new EnvelopeRejected('ACTOR_ROLE_MISMATCH');
  } else if (PARTY_ROLES.has(actor.role)) throw new EnvelopeRejected('ACTOR_ROLE_MISMATCH');
}

class HeadMoved extends Error {
  readonly head: ChainHead;
  constructor(head: ChainHead) {
    super('head moved');
    this.head = head;
  }
}

const toHead = (h: { nextSeq: number; prevHash: string }): ChainHead => ({
  nextSeq: h.nextSeq,
  prevHash: h.prevHash as Hex32,
});

/** Parses and validates a stored envelope's event; throws `EnvelopeRejected`. Exact bytes in, nothing re-serialized. */
export function parseEnvelope(bytes: Uint8Array): { env: Envelope; event: LegxEvent; body: Uint8Array } {
  let env: Envelope;
  try {
    env = JSON.parse(strictUtf8.decode(bytes));
  } catch {
    throw new EnvelopeRejected('NOT_JSON');
  }
  const body = Uint8Array.from(Buffer.from(String(env?.payload), 'base64'));
  const parsed = LegxEvent.safeParse(safeJson(body));
  if (!parsed.success) throw new EnvelopeRejected('SCHEMA', parsed.error.issues[0]?.message);
  return { env, event: parsed.data, body };
}

function safeJson(body: Uint8Array): unknown {
  try {
    return JSON.parse(strictUtf8.decode(body));
  } catch {
    return undefined;
  }
}

/** `EvidenceStorePort` for deal events (the record methods come from the composition), plus the service's own appends. */
export interface Events {
  head(dealId: string): Promise<ChainHead>;
  append(dealId: string, envelope: Uint8Array): Promise<AppendResult>;
  list(dealId: string, afterSeq: number, limit: number): Promise<readonly StoredEvent[]>;
  appendOwn(dealId: string, make: (head: ChainHead) => EventInput): Promise<{ seq: number; leafHash: Hex32 }>;
}

export function createEvents(deps: EventsDeps): Events {
  const { db } = deps;

  // Reads the head under the row lock and rolls back: the repository has no plain getter, and a rollback means that
  // asking about an unknown deal leaves no `deal_head` row behind.
  async function head(dealId: string): Promise<ChainHead> {
    try {
      await db.transaction(async (r) => {
        throw new HeadMoved(await headIn(r, dealId));
      });
    } catch (e) {
      if (e instanceof HeadMoved) return e.head;
      throw e;
    }
    throw new Error('unreachable');
  }

  async function append(dealId: string, bytes: Uint8Array): Promise<AppendResult> {
    const { env, event, body } = parseEnvelope(bytes);
    if (event.predicate.deal_id !== dealId) throw new EnvelopeRejected('DEAL_MISMATCH');
    const at = (await deps.clock.now()).closeTime;
    const verdict = verifyHybrid(env, await deps.registry(dealId), at);
    if (!verdict.ok) throw new EnvelopeRejected(verdict.code);
    if (!sameBytes(verdict.payload, body)) throw new EnvelopeRejected('MALFORMED');
    await checkActor(db, dealId, event.predicate.actor, verdict.keyIds.ed25519);

    const p = event.predicate;
    const leaf = leafHashOf(bytes) as Hex32;
    let row: EvidenceEventRow;
    try {
      row = await db.transaction(async (r) => {
        const stored = await r.evidenceEvents.getBySeq(dealId, p.seq);
        if (stored) {
          if (stored.leaf_hash === leaf) return stored; // an idempotent retry
          throw new HeadMoved(await headIn(r, dealId));
        }
        const appended = await r.evidenceEvents.appendNext(dealId, (h) => {
          if (h.nextSeq !== p.seq || h.prevHash !== p.prev_hash) throw new HeadMoved(toHead(h));
          return { event_id: p.event_id, envelope: bytes, leaf_hash: leaf };
        });
        await r.outbox.enqueueNext(dealId, OUTBOX_TOPIC, bytes);
        return appended;
      });
    } catch (e) {
      if (e instanceof HeadMoved) return { status: 'seq_taken', head: e.head };
      if (e instanceof SeqTaken) return { status: 'seq_taken', head: await head(dealId) };
      throw e;
    }
    await deps.afterStore?.(row, event);
    return { status: 'stored', seq: row.seq, leafHash: row.leaf_hash as Hex32 };
  }

  return {
    head,
    append,

    async list(dealId, afterSeq, limit): Promise<readonly StoredEvent[]> {
      const rows = await db.repos.evidenceEvents.listAfter(dealId, afterSeq, limit);
      return Promise.all(
        rows.map(async (r) => {
          const logIndex = await db.repos.evidenceLogEntries.get(r.event_id);
          return {
            seq: r.seq,
            leafHash: r.leaf_hash as Hex32,
            envelope: r.envelope,
            ...(logIndex === undefined ? {} : { logIndex }),
          };
        }),
      );
    },

    async appendOwn(dealId, make) {
      const signer = deps.signer;
      if (!signer) throw new Error('appendOwn needs a signer');
      let h = await head(dealId);
      for (let attempt = 0; attempt < MAX_APPEND_ATTEMPTS; attempt++) {
        const input = make(h);
        const keys = await signer.publicKeys();
        const body = eventBody({ ...input, actor: { ...input.actor, keyId: keys.keyIds.ed25519 } }, h);
        const res = await append(dealId, envelopeBytes(await signAsService(signer, body)));
        if (res.status === 'stored') return { seq: res.seq, leafHash: res.leafHash };
        h = res.head;
      }
      throw new Error(`appendOwn: still losing the race after ${MAX_APPEND_ATTEMPTS} attempts`);
    },
  };
}

async function headIn(r: Repos, dealId: string): Promise<ChainHead> {
  try {
    await r.evidenceEvents.appendNext(dealId, (h) => {
      throw new HeadMoved(toHead(h));
    });
  } catch (e) {
    if (e instanceof HeadMoved) return e.head;
    throw e;
  }
  throw new Error('unreachable');
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
