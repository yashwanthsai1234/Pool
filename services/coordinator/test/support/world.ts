// The test world: a PGlite database, a stub ledger, four parties with three holder keys each, signed API calls and
// signed events. Everything a client would do, done the way a client does it, so the tests drive only the public API.
import { createHash, randomBytes } from 'node:crypto';
import { API_AUTH_HEADER } from '@legx/contracts/api';
import type { LedgerPort, SignerPort } from '@legx/contracts/ports';
import { bytesToHex, sha256 } from '@legx/core/dealcore';
import { PAYLOAD_TYPE } from '@legx/core/evidence';
import { signHybrid } from '@legx/core/hybridEnvelope';
import { mldsaSign, nobleHybridSigner, pqKeygen, toBase64 } from '@legx/core/pq';
import type { KyselyDatabase } from '@legx/db/client';
import { openPglite } from '@legx/db/pglite';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { FastifyInstance } from 'fastify';
import { vi } from 'vitest';
import { ECDSA, Wallet } from 'xrpl';
import { buildApp } from '../../src/app.ts';
import { apiRequestMessage } from '../../src/auth.ts';
import type { CoordinatorDeps, GateInput, GateResult } from '../../src/deps.ts';
import { pinEnrollmentKey } from '../../src/enroll.ts';
import { headOf } from '../../src/events.ts';
import { ED_SUFFIX, PQ_SUFFIX } from '../../src/keys.ts';
import { uuid7 } from '../../src/uuid.ts';
import { StubLedger } from './stubLedger.ts';

/** A LedgerPort with the validated index the signers put into requests. */
export type TestLedger = LedgerPort & { readonly index: number };

// ML-DSA in pure JS is slow and the unit files run in parallel: give hooks and tests room.
vi.setConfig({ testTimeout: 600_000, hookTimeout: 600_000 });

export type Role = 'alice' | 'lawyerA' | 'bob' | 'lawyerB';
export type Slot = 'A' | 'LA' | 'B' | 'LB';
export const SLOT: Record<Role, Slot> = { alice: 'A', lawyerA: 'LA', bob: 'B', lawyerB: 'LB' };
export const ROLES: Role[] = ['alice', 'lawyerA', 'bob', 'lawyerB'];
const HOLDERS = ['phone', 'passkey-same-device', 'recovery-agent'] as const;
const LAWYER_HOLDERS = ['console', 'firm-hsm', 'partner'] as const;

export const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
export const rndHex = (n: number) => randomBytes(n).toString('hex');
const upper = (s: string) => s.toUpperCase();

export interface Holder {
  pairId: string;
  holderRole: string;
  edSecret: Uint8Array;
  edPub: Uint8Array;
  pqSecret: Uint8Array;
  pqPub: Uint8Array;
}
export interface Party {
  role: Role;
  slot: Slot;
  /** The slot's XRPL key: signs the multisigned exits. */
  wallet: Wallet;
  holders: Holder[];
}

export function makeHolder(slot: Slot, holderRole: string): Holder {
  const edSecret = new Uint8Array(randomBytes(32));
  const pq = pqKeygen();
  return {
    pairId: `${slot}-${holderRole}-${rndHex(3)}`,
    holderRole,
    edSecret,
    edPub: ed25519.getPublicKey(edSecret),
    pqSecret: pq.secretKey,
    pqPub: pq.publicKey,
  };
}

const makeParty = (role: Role): Party => {
  const slot = SLOT[role];
  const names = role.startsWith('lawyer') ? LAWYER_HOLDERS : HOLDERS;
  return { role, slot, wallet: Wallet.generate(ECDSA.ed25519), holders: names.map((h) => makeHolder(slot, h)) };
};

type GateStub = (input: GateInput) => Promise<GateResult>;

export interface World {
  db: KyselyDatabase;
  /** The stub, or (integration tests) the real ledger port. Unit tests use `stub`. */
  ledger: StubLedger;
  /** The four-account addresses of the deal being built (defaults are throwaway addresses). */
  addr: { shell: string; opsA: string; opsB: string; payA: string; payB: string };
  app: FastifyInstance;
  deps: CoordinatorDeps;
  parties: Record<Role, Party>;
  lawyerCreator: Holder;
  observer: Holder;
  gate: { run: GateStub };
  crash: { fn?: (point: string) => void | Promise<void> };
  /** When true, every event post is killed once at the state write and then retried after a restart (P3.2-10). */
  killEveryStep: boolean;
  rebuild(): FastifyInstance;
  close(): Promise<void>;
}

export async function makeWorld(over: Partial<{ db: KyselyDatabase; ledger: TestLedger }> = {}): Promise<World> {
  const db = over.db ?? openPglite();
  await db.migrate();
  const ledger = (over.ledger ?? new StubLedger()) as StubLedger;
  const gate = { run: (async () => ({ ok: true })) as GateStub };
  const crash: World['crash'] = {};
  const lawyerCreator = makeHolder('LA', 'console');
  const observer = makeHolder('A', 'observer'); // OD-31: pinned by configuration, belongs to no deal
  const signer: SignerPort = nodeSigner(generateNodeSignerKeys('coordinator-ed' as never, 'coordinator-pq' as never));
  const deps: CoordinatorDeps = {
    db,
    ledger,
    signer,
    gate: { run: (i) => gate.run(i) },
    lawyerKeys: (id) =>
      id === lawyerCreator.pairId
        ? { ed25519: lawyerCreator.edPub, mlDsa65: lawyerCreator.pqPub, opsAccount: OPS_A }
        : undefined,
    observerKeys: (id) => (id === observer.pairId ? { ed25519: observer.edPub, mlDsa65: observer.pqPub } : undefined),
    crash: (p) => crash.fn?.(p),
  };
  const world: World = {
    db,
    ledger,
    addr: { shell: SHELL, opsA: OPS_A, opsB: OPS_B, payA: PAY_A, payB: PAY_B },
    deps,
    gate,
    crash,
    killEveryStep: false,
    lawyerCreator,
    observer,
    parties: Object.fromEntries(ROLES.map((r) => [r, makeParty(r)])) as Record<Role, Party>,
    app: buildApp(deps),
    rebuild: () => (world.app = buildApp(deps)),
    close: async () => {
      await world.app.close();
      await db.close();
    },
  };
  return world;
}

// ---------- signed API calls ----------

export interface Signed {
  method: 'GET' | 'POST';
  url: string;
  headers: Record<string, string>;
  payload?: string;
}

/** Signs a request the way a client does (OD-5, OD-8). Overrides let tests make stale, reused or wrong requests. */
export function signRequest(
  w: World,
  holder: Holder,
  method: 'GET' | 'POST',
  url: string,
  body?: unknown,
  over: { nonce?: string; ledgerIndex?: number; rawBody?: string } = {},
): Signed {
  const payload = over.rawBody ?? (body === undefined ? undefined : JSON.stringify(body));
  const nonce = over.nonce ?? rndHex(32);
  const ledgerIndex = over.ledgerIndex ?? w.ledger.index;
  const msg = apiRequestMessage(method, url, new TextEncoder().encode(payload ?? ''), nonce, ledgerIndex);
  const ed = ed25519.sign(msg, holder.edSecret);
  const pq = mldsaSign('ml-dsa-65', holder.pqSecret, msg, 'legx/api-request/v1' as never);
  const auth = {
    nonce,
    ledgerIndex,
    signatures: [
      { keyid: holder.pairId + ED_SUFFIX, sig: toBase64(ed) },
      { keyid: holder.pairId + PQ_SUFFIX, sig: toBase64(pq) },
    ],
  };
  return {
    method,
    url,
    headers: {
      [API_AUTH_HEADER]: JSON.stringify(auth),
      ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(payload === undefined ? {} : { payload }),
  };
}

export async function call(w: World, holder: Holder, method: 'GET' | 'POST', url: string, body?: unknown) {
  const res = await w.app.inject(signRequest(w, holder, method, url, body));
  return { status: res.statusCode, body: res.json() as Record<string, any> };
}

export const holderOf = (w: World, role: Role, i = 0) => w.parties[role].holders[i] as Holder;

// ---------- setup ----------

export const SHELL = Wallet.generate(ECDSA.ed25519).classicAddress;
export const OPS_A = Wallet.generate(ECDSA.ed25519).classicAddress;
export const OPS_B = Wallet.generate(ECDSA.ed25519).classicAddress;
export const PAY_A = Wallet.generate(ECDSA.ed25519).classicAddress;
export const PAY_B = Wallet.generate(ECDSA.ed25519).classicAddress;

/** deals.create by a pinned lawyer, then every holder key pinned (out of band), the wallet and the contract fixed. */
export async function newDeal(w: World, over: { identityPolicy?: string; amountDrops?: string } = {}) {
  const r = await call(w, w.lawyerCreator, 'POST', '/deals', {
    network: 'standalone',
    identityPolicy: over.identityPolicy ?? 'zk-or-chip',
    amountDrops: over.amountDrops ?? '5000000000',
    payoutA: `${w.addr.payA}:7`,
    payoutB: w.addr.payB,
    lawyerOpsA: w.addr.opsA,
    lawyerOpsB: w.addr.opsB,
  });
  if (r.status !== 200) throw new Error(`create failed: ${JSON.stringify(r.body)}`);
  const dealId = r.body.dealId as string;
  // Fresh holder keys for every deal: a key pair belongs to one deal (enrollment_key.deal_id).
  w.parties = Object.fromEntries(ROLES.map((x) => [x, makeParty(x)])) as Record<Role, Party>;
  for (const p of Object.values(w.parties))
    for (const h of p.holders)
      await pinEnrollmentKey(w.deps, dealId, {
        key_id: h.pairId,
        slot: p.slot,
        holder_role: h.holderRole,
        ed25519_pub: hex(h.edPub),
        mldsa65_pub: toBase64(h.pqPub),
        valid_from: 0,
      } as never);
  return dealId;
}

export const contractRoot = rndHex(32);

// ---------- events ----------

const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

/** A hybrid-signed event by `role`, for the next seq of the deal (or `seq`/`prevHash` overrides). */
export async function makeEvent(
  w: World,
  dealId: string,
  role: Role,
  kind: string,
  data: Record<string, unknown>,
  over: { seq?: number; prevHash?: string; holder?: Holder; actorRole?: string; root?: string } = {},
): Promise<string> {
  const head = await headOf(w.db.repos, dealId);
  const h = over.holder ?? holderOf(w, role);
  const signer = nobleHybridSigner(
    { keyId: (h.pairId + ED_SUFFIX) as never, publicKey: h.edPub, sign: async (m) => ed25519.sign(m, h.edSecret) },
    { keyId: (h.pairId + PQ_SUFFIX) as never, secretKey: h.pqSecret },
  );
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: `deal:${dealId}`, digest: { sha256: over.root ?? contractRoot } }],
    predicateType: 'https://legx.dev/event/v1',
    predicate: {
      event_id: uuid7(),
      deal_id: dealId,
      seq: over.seq ?? head.nextSeq,
      kind,
      actor: { role: over.actorRole ?? role, key_id: h.pairId + ED_SUFFIX },
      occurred_at: '2026-10-24T12:00:00Z',
      prev_hash: over.prevHash ?? head.prevHash,
      payload_commitment: '00'.repeat(32),
      sig_algs: ['ed25519', 'ml-dsa-65'],
      data,
    },
  };
  const env = await signHybrid(PAYLOAD_TYPE, enc(statement), signer);
  return Buffer.from(enc(env)).toString('base64');
}

export const append = (w: World, dealId: string, role: Role, b64: string, holder = holderOf(w, role)) =>
  call(w, holder, 'POST', `/deals/${dealId}/events`, { dealId, envelope: b64 });

/** Makes and posts one event. */
export async function post(w: World, dealId: string, role: Role, kind: string, data: Record<string, unknown>) {
  const b64 = await makeEvent(w, dealId, role, kind, data);
  if (!w.killEveryStep) return await append(w, dealId, role, b64);
  // Kill the process between the state write and the commit; a phone retries the same bytes after the restart.
  w.crash.fn = (p) => {
    if (p === 'deal.afterStateWrite') throw new Error('KILLED');
  };
  const first = await append(w, dealId, role, b64);
  w.crash.fn = undefined;
  if (first.status !== 500) return first; // refused before the write: nothing to restart
  w.rebuild();
  return await append(w, dealId, role, b64);
}

export const txHash = () => upper(rndHex(32));

export function addTx(
  w: World,
  type: string,
  account: string,
  extra: Record<string, unknown> = {},
  result = 'tesSUCCESS',
) {
  const hash = txHash();
  w.ledger.txs.set(hash, {
    hash: hash as never,
    ledgerIndex: w.ledger.index,
    closeTime: w.ledger.closeTime as never,
    tx: { TransactionType: type, Account: account, ...extra },
    meta: { TransactionResult: result },
  });
  return hash;
}
