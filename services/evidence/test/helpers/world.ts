// A test world: a PGlite database with one deal, a service signer, enrolled parties with real Ed25519 + ML-DSA-65
// keys, and the events module wired to them. Later helpers add the log, the anchors and the bundle.
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EventKind, LegxEvent } from '@legx/contracts/events';
import type { ClockPort, ObjectStorePort, SignerPort, TransparencyLogPort } from '@legx/contracts/ports';
import { KeyId, type RippleTime, type XrplHash } from '@legx/contracts/values';
import { PAYLOAD_TYPE } from '@legx/core/evidence';
import { signHybrid } from '@legx/core/hybridEnvelope';
import type { CheckpointKeys } from '@legx/core/pqCheckpoint';
import type { KyselyDatabase } from '@legx/db/client';
import { openPglite } from '@legx/db/pglite';
import {
  generateNodeCheckpointKeys,
  generateNodeSignerKeys,
  nodeCheckpointSigner,
  nodeSigner,
} from '@legx/signer/node';
import { inProcessLog } from '@legx/storage/inProcessLog';
import { localObjectStore } from '@legx/storage/localStore';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  canonicalBytes,
  createEvents,
  type EventInput,
  type Events,
  type EventsDeps,
  envelopeBytes,
  eventBody,
} from '../../src/events.ts';
import { registryFromRows } from '../../src/keys.ts';
import { createLogService } from '../../src/log.ts';

const GOLDEN = JSON.parse(
  readFileSync(new URL('../../../../packages/contracts/examples/LegxEvent.json', import.meta.url), 'utf8'),
) as LegxEvent[];
export const goldenOf = (kind: EventKind) => GOLDEN.find((e) => e.predicate.kind === kind) as LegxEvent;

export interface Party {
  readonly keyId: string;
  readonly signer: SignerPort;
}

/** A service signer: its key ids are plain (no pair suffix), unlike an enrollment key's. */
export const makeService = (keyId: string): Party => ({
  ...makeParty(keyId),
  signer: nodeSigner(generateNodeSignerKeys(KeyId.parse(keyId), KeyId.parse(`${keyId}:pq`))),
});

export const makeParty = (keyId: string): Party => ({
  keyId,
  signer: nodeSigner(generateNodeSignerKeys(KeyId.parse(`${keyId}#ed25519`), KeyId.parse(`${keyId}#ml-dsa-65`))),
});

interface Clock extends ClockPort {
  closeTime: number;
}
const makeClock = (closeTime = 810_000_000): Clock => {
  const c = {
    closeTime,
    async now() {
      return { ledgerIndex: 1000, ledgerHash: '0'.repeat(64) as XrplHash, closeTime: c.closeTime as RippleTime };
    },
  };
  return c as Clock;
};

/** An EventInput for `kind` that reuses the golden data of that kind (valid under the contracts schema). */
export function inputFor(
  world: Pick<World, 'dealId' | 'contractRoot'>,
  kind: EventKind,
  actor: EventInput['actor'],
  patch: Partial<EventInput> = {},
): EventInput {
  const g = goldenOf(kind).predicate;
  return {
    dealId: world.dealId,
    contractRoot: world.contractRoot,
    kind,
    data: g.data,
    actor,
    occurredAt: '2026-10-24T10:00:00Z',
    payloadCommitment: g.payload_commitment,
    ...(g.ledger ? { ledger: { txHash: g.ledger.tx_hash, ledgerIndex: g.ledger.ledger_index } } : {}),
    ...patch,
  };
}

export interface World {
  readonly db: KyselyDatabase;
  readonly dealId: string;
  readonly contractRoot: string;
  readonly clock: Clock;
  readonly service: Party;
  readonly deps: EventsDeps;
  readonly events: Events;
  readonly parties: Map<string, Party>;
  readonly origin: string;
  readonly objects: ObjectStorePort;
  readonly log: TransparencyLogPort;
  readonly logSvc: ReturnType<typeof createLogService>;
  readonly cpKeys: CheckpointKeys;
  /** Enrols a party's keys (the key hash is logged first, signed by the service key), as DESIGN 6.3 requires. */
  enroll(role: 'alice' | 'bob' | 'lawyerA' | 'lawyerB', slot: 'A' | 'LA' | 'B' | 'LB', party?: Party): Promise<Party>;
  /** A party-signed event envelope for the next seq of the deal. */
  sign(
    party: Party,
    role: EventInput['actor']['role'],
    kind: EventKind,
    patch?: Partial<EventInput>,
  ): Promise<Uint8Array>;
}

export async function makeWorld(over: Partial<EventsDeps> = {}): Promise<World> {
  const db = openPglite();
  await db.migrate();
  const contractRoot = '11'.repeat(32);
  const dealId = (
    await db.repos.deals.insert({
      state: 'DRAFT',
      network: 'standalone',
      contract_root: contractRoot,
      payout_a: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
      payout_b: 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn',
      amount_drops: '1000000',
    })
  ).deal_id;
  const clock = makeClock();
  // A service key is named by itself (no pair suffix); only enrollment keys use the `#` convention (I-3.7-e).
  const service = makeService('svc/evidence');
  const svcKeys = await service.signer.publicKeys();
  const registry = async (id: string) =>
    registryFromRows(await db.repos.enrollmentKeys.listForDeal(id), { keys: svcKeys, validFrom: 0 });
  const origin = 'legx.test/evidence';
  const cpSigner = nodeCheckpointSigner(generateNodeCheckpointKeys(KeyId.parse('log/ed'), KeyId.parse('log/pq')));
  const cpPub = await cpSigner.publicKeys();
  const cpKeys: CheckpointKeys = {
    ed: { name: origin, publicKey: cpPub.ed25519 },
    pq: { name: `${origin}-mldsa44`, publicKey: cpPub.mlDsa44 },
  };
  const objects = localObjectStore({ dir: mkdtempSync(join(tmpdir(), 'legx-evidence-')) });
  const log = inProcessLog({ origin, signer: cpSigner, clock });
  // biome-ignore lint/style/useConst: the events module needs the log service, which needs the events module's head
  let logSvc!: ReturnType<typeof createLogService>;
  const deps: EventsDeps = {
    db,
    registry,
    clock,
    signer: service.signer,
    afterStore: (row) => logSvc.integrate(row).then(() => undefined),
    ...over,
  };
  const events = createEvents(deps);
  logSvc = createLogService({ db, log, objects, retainDays: 3650, head: events.head });
  const parties = new Map<string, Party>();
  const world: World = {
    db,
    dealId,
    contractRoot,
    clock,
    service,
    deps,
    events,
    parties,
    origin,
    objects,
    log,
    logSvc,
    cpKeys,
    async enroll(role, slot, party = makeParty(`enroll/${role}`)) {
      const bound = await events.appendOwn(dealId, () =>
        inputFor(
          { dealId, contractRoot },
          'key.bound',
          { role: 'coordinator', keyId: '' },
          { actor: { role: 'coordinator', keyId: '' } },
        ),
      );
      const keys = await party.signer.publicKeys();
      const row = await db.repos.evidenceEvents.getBySeq(dealId, bound.seq);
      await db.repos.enrollmentKeys.insert({
        key_id: party.keyId as never,
        deal_id: dealId,
        slot,
        holder_role: 'phone',
        ed25519_pub: bytesToHex(keys.ed25519) as never,
        mldsa65_pub: Buffer.from(keys.mlDsa65).toString('base64') as never,
        valid_from: 0 as never,
        evidence_event_id: (row as { event_id: string }).event_id,
      });
      parties.set(role, party);
      return party;
    },
    async sign(party, role, kind, patch = {}) {
      const head = await events.head(dealId);
      const input = inputFor({ dealId, contractRoot }, kind, { role, keyId: party.keyId }, patch);
      return envelopeBytes(await signHybrid(PAYLOAD_TYPE, eventBody(input, head), party.signer));
    },
  };
  return world;
}

{
  canonicalBytes;
}
