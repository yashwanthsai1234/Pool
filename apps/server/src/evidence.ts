// The evidence side of the composition (3.4 with the post-quantum parts of 3.12): the key registry events are checked
// against, the log service over a hybrid-cosigning log, and the checkpoint job. What 3.12's status file asks 3.7 to do:
// `hybridCheckpointLog` around the log, `registerCheckpointJob` on the job port, `resilientSigner` around the signer.
// Source: IMPLEMENTATION 3.12 (Requests: "call hybridCheckpointLog ... registerCheckpointJob ... resilientSigner")
import type {
  CheckpointSignerPort,
  ClockPort,
  ObjectStorePort,
  SignerPort,
  TransparencyLogPort,
} from '@legx/contracts/ports';
import { registryOf } from '@legx/coordinator/keys';
import type { KeyRegistry, RegisteredKey } from '@legx/core/hybridEnvelope';
import type { Database } from '@legx/db';
import type { Jobs } from '@legx/evidence/jobs';
import { createLogService } from '@legx/evidence/log';
import { hybridCheckpointLog, registerCheckpointJob, resilientSigner } from '@legx/evidence/pq/index';

export interface EvidenceParts {
  readonly db: Database;
  /** The service's hybrid signer (the coordinator's evidence key); wrapped so a half pair is never returned. */
  readonly signer: SignerPort;
  readonly checkpointSigner: CheckpointSignerPort;
  readonly log: TransparencyLogPort;
  readonly objects: ObjectStorePort;
  readonly clock: ClockPort;
  readonly retainDays?: number;
  readonly jobs?: Jobs;
}

/** The keys that may sign a deal's events: its enrollment keys (coordinator key ids) and the service key. */
export function dealRegistry(db: Database, signer: SignerPort): (dealId: string) => Promise<KeyRegistry> {
  return async (dealId) => {
    const rows = await db.repos.enrollmentKeys.listForDeal(dealId);
    const base = registryOf(rows);
    const k = await signer.publicKeys();
    const svc = new Map<string, RegisteredKey>([
      [
        k.keyIds.ed25519,
        { alg: 'ed25519', publicKey: k.ed25519, validFrom: 0, logged: true, pair: `service:${k.keyIds.ed25519}` },
      ],
      [
        k.keyIds.mlDsa65,
        { alg: 'ml-dsa-65', publicKey: k.mlDsa65, validFrom: 0, logged: true, pair: `service:${k.keyIds.ed25519}` },
      ],
    ]);
    return (id) => base(id) ?? svc.get(id);
  };
}

export async function composeEvidence(p: EvidenceParts) {
  const signer = resilientSigner(p.signer);
  const last = async () => {
    const a = await p.db.repos.checkpointAnchors.latest();
    return a ? { treeSize: a.tree_size, rootHash: a.root } : undefined;
  };
  const log = hybridCheckpointLog(p.log, { signer: p.checkpointSigner, clock: p.clock, previous: last });
  const service = createLogService({
    db: p.db,
    log,
    objects: p.objects,
    retainDays: p.retainDays ?? 3650,
    head: async (dealId) => {
      const h = await p.db.repos.evidenceEvents.listAfter(dealId, -1, 100_000);
      return { nextSeq: h.length };
    },
  });
  if (p.jobs) await registerCheckpointJob(p.jobs, service.checkpoint);
  return { signer, log, service, registry: dealRegistry(p.db, signer) };
}
