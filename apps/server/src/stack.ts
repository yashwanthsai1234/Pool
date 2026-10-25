// The one composition both profiles share (IMPLEMENTATION 3.7; closes I-3.7-g, I-W-4..7, I-3.7-h). The profiles differ
// only in the `Adapters` they pass: keys, object store, log, bar registry, ledger network, ZK settings. Everything else
// is wired here, the same for both: the real release gate, records.bundle, zk.verify, the watcher over every deal wallet
// of the database, the pump (log integration, checkpoints), the checkpoint and
// anchor jobs, RFC 3161 time stamps.

import type {
  CheckpointSignerPort,
  ClockPort,
  LedgerPort,
  ObjectStorePort,
  SignerPort,
  TransparencyLogPort,
} from '@legx/contracts/ports';
import { ZK_DOMAIN } from '@legx/contracts/records';
import type { PinnedKey } from '@legx/coordinator/deps';
import type { Profile } from '@legx/core/attest';
import type { CheckpointKeys } from '@legx/core/pqCheckpoint';
import { type Database, openPg } from '@legx/db';
import { createAnchorService } from '@legx/evidence/anchor';
import { type Jobs, pgBossJobs } from '@legx/evidence/jobs';
import { CHECKPOINT_QUEUE_OPTIONS, QUEUE_CHECKPOINT } from '@legx/evidence/pq/index';
import { type Authority, DIGICERT, nodeRootCertificates, SSL_COM, tsaClient } from '@legx/evidence/tsa';
import { createVerifier, startOnboardingJobs } from '@legx/verifier';
import type { VerifierDeps } from '@legx/verifier/service';
import { WatcherService } from '@legx/watcher';
import { connect } from '@legx/xrpl/connect';
import type { LedgerEnv } from '@legx/xrpl/env';
import { ledgerPort } from '@legx/xrpl/submit';
import { xrplLink } from '@legx/xrpl/watcher/index';
import { PINNED } from '@legx/zk/sdk';
import { createZkAdapter, type ZkVerifierConfig } from '@legx/zk-verifier';
import pg from 'pg';
import { PgBoss } from 'pg-boss';
import type { PortSpec, ProfileName } from './config.ts';
import type { ServerDeps } from './deps.ts';
import { composeEvidence } from './evidence.ts';
import { realGate, releaseInputJson } from './gate.ts';
import { pgLiveSource } from './pgSource.ts';
import { dealWatcher, startPump, watcherEvidence } from './wiring.ts';

export interface AccountKey {
  readonly address: string;
  sign(tx: Record<string, unknown>): Promise<string>;
}

/** What a profile decides. Every port a profile brings names its implementation, so `/health` and the profile check see it. */
export interface Adapters {
  readonly profile: ProfileName;
  readonly ledgerEnv: LedgerEnv;
  /** A second server for the raw anchor transaction JSON of the bundle (DESIGN 8.8 item 5); default: the first. */
  readonly ledgerEnv2?: LedgerEnv;
  /** Standalone only: close a ledger this often, so the validated index moves. */
  readonly closeLedgerEveryMs?: number;
  readonly signer: SignerPort;
  readonly checkpointSigner: CheckpointSignerPort;
  readonly objects: ObjectStorePort;
  readonly origin: string;
  readonly makeLog: (clock: ClockPort, pool: pg.Pool) => TransparencyLogPort | Promise<TransparencyLogPort>;
  readonly issuer: (client: Awaited<ReturnType<typeof connect>>) => Promise<AccountKey>;
  readonly anchor: (client: Awaited<ReturnType<typeof connect>>) => Promise<AccountKey>;
  readonly barAdapters: VerifierDeps['adapters'];
  readonly manual?: NonNullable<ServerDeps['verifier']>['manual'];
  readonly zk: Omit<ZkVerifierConfig, 'domain' | 'sdkVersion'>;
  /** Time stamp authorities; default: the two independent public ones (DESIGN 8.4). */
  readonly tsa?: readonly Authority[];
  /** Roots that vouch for the authorities; default: the system roots shipped with Node. */
  readonly tsaRoots?: readonly Uint8Array[];
  readonly ports: Readonly<Record<string, PortSpec>>;
  readonly retainDays?: number;
  readonly verifyScript: string;
  readonly agents?:
    | ServerDeps['agents']
    | ((c: ServerDeps['coordinator']) => ServerDeps['agents'] | Promise<ServerDeps['agents']>);
  readonly demo?: ServerDeps['demo'];
  /** Closers for what the adapters opened. */
  readonly stops?: readonly (() => Promise<void>)[];
}

export interface Built {
  readonly deps: ServerDeps;
  readonly db: Database;
  stop(): Promise<void>;
}

type Env = Readonly<Record<string, string | undefined>>;

const hex = (s: string) => Uint8Array.from(Buffer.from(s, 'hex'));
const b64 = (s: string) => Uint8Array.from(Buffer.from(s, 'base64'));

/** `{ "<pairId>": { "ed25519": hex, "mlDsa65": base64 } }` from one env variable (lawyer, operator or observer keys). */
export function pinnedKeys(json: string | undefined): (pairId: string) => PinnedKey | undefined {
  const keys: Record<string, PinnedKey> = {};
  for (const [id, v] of Object.entries(
    JSON.parse(json ?? '{}') as Record<string, { ed25519: string; mlDsa65: string }>,
  ))
    keys[id] = { ed25519: hex(v.ed25519), mlDsa65: b64(v.mlDsa65) };
  return (id) => keys[id];
}

export async function buildStack(env: Env, a: Adapters): Promise<Built> {
  const stops: (() => Promise<void>)[] = [];
  const url = env.LEGX_PG as string;
  const db: Database = openPg(url);
  stops.push(() => db.close());
  await db.migrate();
  const pool = new pg.Pool({ connectionString: url, max: 4 });
  pool.on('error', () => undefined);
  stops.push(async () => void (await pool.end().catch(() => undefined)));

  const client = await connect(a.ledgerEnv);
  stops.push(() => client.disconnect());
  const ledger: LedgerPort = ledgerPort(client, a.ledgerEnv, { pollMs: 200, timeoutMs: 30_000 });
  const ledger2 = a.ledgerEnv2
    ? ledgerPort(await connect(a.ledgerEnv2), a.ledgerEnv2, { pollMs: 200, timeoutMs: 30_000 })
    : ledger;
  const clock: ClockPort = { now: () => ledger.validatedLedger() };

  const issuer = await a.issuer(client);
  const anchorKey = await a.anchor(client);

  // Jobs: pg-boss in its own schema. The checkpoint queue is created here (the job port creates the other two).
  const boss = new PgBoss({ connectionString: url, schema: 'legx_evidence_jobs' });
  boss.on('error', () => undefined);
  await boss.start();
  stops.push(() => boss.stop({ graceful: false }));
  const jobs: Jobs = await pgBossJobs(boss);
  await boss.createQueue(QUEUE_CHECKPOINT, CHECKPOINT_QUEUE_OPTIONS);

  const evidence = await composeEvidence({
    db,
    signer: a.signer,
    checkpointSigner: a.checkpointSigner,
    log: await a.makeLog(clock, pool),
    objects: a.objects,
    clock,
    retainDays: a.retainDays ?? 3650,
    jobs,
  });

  const authorities = a.tsa ?? [DIGICERT, SSL_COM];
  const tsaRoots = a.tsaRoots ?? nodeRootCertificates();
  const anchors = createAnchorService({
    db,
    logSvc: evidence.service,
    ledger,
    signTx: (tx) => anchorKey.sign(tx),
    anchorAccount: anchorKey.address,
    baseFeeDrops: Number((await ledger.fees()).baseFee), // 200 on the standalone config, 10 on the public networks
    network: a.ledgerEnv.name as never,
    origin: a.origin,
    objects: a.objects,
    retainDays: a.retainDays ?? 3650,
    jobs,
    tsa: authorities.map((authority) => tsaClient({ authority, trustedRoots: tsaRoots })),
  });
  await anchors.start();

  const gateCfg = {
    db,
    profile: (a.profile === 'production' ? 'production' : 'demo') as Profile,
    verifierSigner: a.signer,
    verifierIssuer: issuer.address,
  };
  const coordinator = {
    db,
    ledger,
    signer: evidence.signer,
    gate: realGate(gateCfg),
    lawyerKeys: pinnedKeys(env.LEGX_LAWYER_KEYS),
    observerKeys: pinnedKeys(env.LEGX_OBSERVER_KEYS),
  };

  const verifier = createVerifier({
    db,
    ledger,
    signer: a.signer,
    issuer: { address: issuer.address, signer: { sign: (tx) => issuer.sign(tx as never) } },
    adapters: a.barAdapters,
  });
  const onboarding = await startOnboardingJobs({ connectionString: url, verifier });
  stops.push(() => onboarding.stop());

  const zk = createZkAdapter({ ...a.zk, domain: ZK_DOMAIN, sdkVersion: PINNED.sdk });

  const watch = dealWatcher(db, pool, [issuer.address]);
  await watch.refresh();
  const watcher = new WatcherService({
    db,
    servers: [xrplLink('primary', a.ledgerEnv.wsUrl, { timeoutMs: 5000 })],
    accounts: watch.accounts,
    deals: () => watch.deals(),
    evidence: watcherEvidence(db, evidence.signer, ledger),
    notify: async () => undefined, // migration 0003's outbox trigger sends the NOTIFY
    pollMs: 1000,
  });
  await watcher.start();
  stops.push(() => watcher.stop());
  const wallets = setInterval(() => void watch.refresh().catch(() => undefined), 500);
  stops.push(async () => clearInterval(wallets));

  let lastAnchor = 0;
  const stopPump = startPump({
    pool,
    db,
    service: evidence.service,
    onGrown: async () => {
      if (Date.now() - lastAnchor < 30_000) return;
      lastAnchor = Date.now();
      await jobs.send('legx.anchor', { reason: 'new events' });
    },
  });
  stops.push(stopPump);

  const source = pgLiveSource(db, url);
  stops.push(() => source.close());

  const cpPub = await a.checkpointSigner.publicKeys();
  const checkpointKeys: CheckpointKeys = {
    ed: { name: a.origin, publicKey: cpPub.ed25519 },
    pq: { name: `${a.origin}-mldsa44`, publicKey: cpPub.mlDsa44 },
  };
  const deps: ServerDeps = {
    profile: a.profile,
    env,
    ports: {
      ...a.ports,
      'release-gate': { impl: 'core-gate', demo: false },
      'zk-verifier': a.ports['zk-verifier'] ?? { impl: 'adapter', demo: a.zk.devMode },
      tsa: { impl: 'rfc3161', demo: false },
      jobs: { impl: 'pg-boss', demo: false },
      watcher: { impl: 'xrpl-link', demo: false, check: () => !watcher.decisionsPaused() },
      'post-quantum': {
        impl: 'hybrid-checkpoint',
        demo: false,
        check: async () => (await evidence.log.checkpoint()).treeSize >= 0,
      },
    },
    zk: { devMode: a.zk.devMode, rpcUrls: a.zk.rpcUrls },
    coordinator,
    agents: typeof a.agents === 'function' ? await a.agents(coordinator) : a.agents,
    verifier: {
      service: verifier,
      enqueue: (ops) => onboarding.enqueue(ops),
      ...(a.manual ? { manual: a.manual } : {}),
    },
    releaseInput: (dealId) => releaseInputJson(gateCfg, ledger, dealId),
    zkVerify: {
      adapter: zk,
      objects: a.objects,
      profile: (a.profile === 'production' ? 'production' : 'demo') as Profile,
    },
    evidence: {
      records: { db, clock, ledger, registry: evidence.registry },
      bundle: {
        db,
        log: evidence.log,
        objects: a.objects,
        signer: evidence.signer,
        clock,
        retainDays: a.retainDays ?? 3650,
        origin: a.origin,
        checkpointKeys,
        ledgers: [
          { name: 'primary', ledger },
          { name: 'secondary', ledger: ledger2 },
        ],
        authorities: authorities.map((x) => x.name),
        trustedRoots: tsaRoots,
        registry: evidence.registry,
        verifyScript: a.verifyScript,
        beforeBuild: async () => void (await anchors.anchorNow()),
      },
    },
    operatorKeys: pinnedKeys(env.LEGX_OPERATOR_KEYS),
    live: { source },
    ...(a.demo ? { demo: a.demo } : {}),
  };
  const all = [...(a.stops ?? []), ...stops];
  return { deps, db, stop: async () => void (await Promise.allSettled([...all].reverse().map((s) => s()))) };
}
