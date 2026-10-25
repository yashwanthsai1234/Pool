// The database handle: repositories return plain objects, and no Kysely type crosses the package boundary.
// Source: https://kysely.dev/docs/category/getting-started
import type { Kysely } from 'kysely';
import { migrateToLatest } from './migrate.ts';
import { DealKeysRepo, DealsRepo } from './repos/deals.ts';
import { CheckpointAnchorsRepo, EvidenceEventsRepo, EvidenceLogEntriesRepo } from './repos/evidence.ts';
import { EnrollmentKeysRepo, PassportAttestationsRepo, ZkProofsRepo } from './repos/identity.ts';
import { AttorneyCredentialsRepo, BarDealLinksRepo, BarVerificationsRepo, LawyersRepo } from './repos/lawyers.ts';
import {
  LedgerObservationsRepo,
  ReleaseGatesRepo,
  SignatureRequestsRepo,
  SignaturesRepo,
  WatcherCursorsRepo,
} from './repos/ops.ts';
import { FrostNonceUsesRepo, OutboxRepo, UsedNoncesRepo } from './repos/queue.ts';
import type { DB } from './schema.ts';

/** One repository per table of DESIGN 9, plus the working-state tables of task 3.1. */
export interface Repos {
  readonly deals: DealsRepo;
  readonly dealKeys: DealKeysRepo;
  readonly lawyers: LawyersRepo;
  readonly barVerifications: BarVerificationsRepo;
  readonly attorneyCredentials: AttorneyCredentialsRepo;
  readonly barDealLinks: BarDealLinksRepo;
  readonly passportAttestations: PassportAttestationsRepo;
  readonly zkProofs: ZkProofsRepo;
  readonly enrollmentKeys: EnrollmentKeysRepo;
  readonly releaseGates: ReleaseGatesRepo;
  readonly signatureRequests: SignatureRequestsRepo;
  readonly signatures: SignaturesRepo;
  readonly evidenceEvents: EvidenceEventsRepo;
  readonly evidenceLogEntries: EvidenceLogEntriesRepo;
  readonly ledgerObservations: LedgerObservationsRepo;
  readonly watcherCursors: WatcherCursorsRepo;
  readonly outbox: OutboxRepo;
  readonly checkpointAnchors: CheckpointAnchorsRepo;
  readonly usedNonces: UsedNoncesRepo;
  readonly frostNonceUses: FrostNonceUsesRepo;
}

export interface Database {
  /** Repositories on the pool: each call is its own statement. */
  readonly repos: Repos;
  /** Runs `fn` in one transaction; every repository in `fn` shares it. A throw rolls it back. */
  transaction<T>(fn: (repos: Repos) => Promise<T>): Promise<T>;
  /** Applies pending migrations; returns the names applied by this call. */
  migrate(): Promise<string[]>;
  close(): Promise<void>;
}

/** The internal view used by tests and the schema generator. Not exported from the package index. */
export interface KyselyDatabase extends Database {
  readonly kysely: Kysely<DB>;
}

function makeRepos(db: Kysely<DB>): Repos {
  return {
    deals: new DealsRepo(db),
    dealKeys: new DealKeysRepo(db),
    lawyers: new LawyersRepo(db),
    barVerifications: new BarVerificationsRepo(db),
    attorneyCredentials: new AttorneyCredentialsRepo(db),
    barDealLinks: new BarDealLinksRepo(db),
    passportAttestations: new PassportAttestationsRepo(db),
    zkProofs: new ZkProofsRepo(db),
    enrollmentKeys: new EnrollmentKeysRepo(db),
    releaseGates: new ReleaseGatesRepo(db),
    signatureRequests: new SignatureRequestsRepo(db),
    signatures: new SignaturesRepo(db),
    evidenceEvents: new EvidenceEventsRepo(db),
    evidenceLogEntries: new EvidenceLogEntriesRepo(db),
    ledgerObservations: new LedgerObservationsRepo(db),
    watcherCursors: new WatcherCursorsRepo(db),
    outbox: new OutboxRepo(db),
    checkpointAnchors: new CheckpointAnchorsRepo(db),
    usedNonces: new UsedNoncesRepo(db),
    frostNonceUses: new FrostNonceUsesRepo(db),
  };
}

export function createDatabase(k: Kysely<unknown>): KyselyDatabase {
  const kysely = k as Kysely<DB>;
  return {
    kysely,
    repos: makeRepos(kysely),
    transaction: (fn) => kysely.transaction().execute((trx) => fn(makeRepos(trx))),
    migrate: () => migrateToLatest(kysely),
    close: () => kysely.destroy(),
  };
}
