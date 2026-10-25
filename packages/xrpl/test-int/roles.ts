// The role script of the full flow (IMPLEMENTATION 2.5; DESIGN 5.2, 5.3). Each role is a small object that holds its
// FROST shares, its enrollment keys and its wallet. Every slot (A, B, LA, LB) signs through a FROST 2-of-3 session of
// the core (OD-4); no slot has a plain key. Operations accounts, the verifier issuer and the shell setup key are
// ordinary XRPL accounts. E2E-P3 and SYS-01 reuse this file.
//
// The evidence records are built with the real primitives of @legx/core: hybrid DSSE envelopes, the chip checks of
// passive authentication on @legx/fixtures passports, ops bindings, post-quantum bindings and DKG records.
// Source: DESIGN.md 5.2, 5.3, 6.4, 6.13 to 6.17
import { PublicDealData } from '@legx/contracts/deal';
import type { SignerPort } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { distinctTag, presenceMsg } from '@legx/core/attest';
import { barNumberSha256, openBarCommitment } from '@legx/core/bar';
import { passportCommitment } from '@legx/core/dealcore';
import { pae } from '@legx/core/evidence';
import { type SlotName, slotAddress, slotPolicy, slotPubkey } from '@legx/core/frost';
import { type DkgKey, testSignMessage } from '@legx/core/frostDkg';
import { opsBindMsg } from '@legx/core/opsBinding';
import { aaChallenge } from '@legx/core/passport/activeAuth';
import { chipChecks, passportRecord } from '@legx/core/passport/passiveAuth';
import { mldsaSign, nobleHybridSigner, pqBindMsg, pqKeygen, pqKeyHash, toBase64 } from '@legx/core/pq';
import type { KeyRow, MintTx, ReleaseInput, SlotHolders } from '@legx/core/releaseGate';
import { chipAnswerAA, demoPassport } from '@legx/fixtures';
import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import xrpl, { type Client } from 'xrpl';
import { dkgKeys, frostSign } from '../../core/test/helpers/frost.ts';
import type { BuildCtx } from '../src/builders/index.ts';
import { connect } from '../src/connect.ts';
import { type LedgerEnv, standaloneEnv } from '../src/env.ts';
import { fundFromFaucet, GENESIS } from '../src/fund.ts';
import { advanceLedgers, type Fees, readFees } from '../src/ledger.ts';
import { combine } from '../src/multisig.ts';
import { prepare } from '../src/prepare.ts';
import { type Rpc, rpcOf, snapshot } from '../src/read.ts';
import { submitReliable } from '../src/submit.ts';
import { slotSign } from './frostSlots.ts';
import { closer } from './support.ts';

export type Json = Record<string, unknown>;
export type Side = 'A' | 'B';
export type Curve = 'ed25519' | 'secp256k1';
type Wallet = InstanceType<typeof xrpl.Wallet>;

export const ATTEST = 'application/vnd.legx.attest+json;v=1';
export const EVENT = 'application/vnd.legx.event+json;v=1';
const DSSE = 'legx/dsse/v1';
export const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();
export const bytes = (x: unknown) => utf8ToBytes(JSON.stringify(x));
const zeros32 = '00'.repeat(32);

/** A UUID version 7 (RFC 9562): 48 bits of Unix milliseconds, then random bits. */
export function uuid7(): string {
  const b = randomBytes(16);
  new DataView(b.buffer).setBigUint64(0, BigInt(Date.now()) << 16n);
  b.set(randomBytes(10), 6);
  b[6] = ((b[6] as number) & 0x0f) | 0x70;
  b[8] = ((b[8] as number) & 0x3f) | 0x80;
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// ---------- the chain: a ledger connection that logs every step ----------

export interface StepLog {
  readonly step: string;
  readonly type: string;
  readonly result: string;
  readonly hash: string;
}
export interface Validated {
  readonly hash: string;
  readonly ledgerIndex: number;
  readonly meta: Json;
  readonly blob: string;
  readonly tx: Json;
}

type SubmitOutcome = Awaited<ReturnType<typeof submitReliable>>;

/** One standalone ledger, a background closer, and `send`: prepare, sign, submit reliably, require `tesSUCCESS`. */
export interface Chain {
  readonly client: Client;
  readonly rpc: Rpc;
  readonly ctx: BuildCtx;
  readonly fees: Fees;
  readonly log: StepLog[];
  /** Runs a named step: a failure names the phase and the step. */
  step<T>(name: string, fn: () => Promise<T>): Promise<T>;
  /** Pays XRP from the genesis account (standalone) or the faucet (Testnet, Devnet). */
  fund(wallet: Wallet, xrp: number): Promise<void>;
  /** Single-signed. `tesSUCCESS` or the step fails. */
  send(wallet: Wallet, tx: xrpl.SubmittableTransaction): Promise<Validated>;
  /** Four slots sign (FROST, 2 of 3 shares each), combine, submit. `tesSUCCESS` or the step fails. */
  multisend(tx: xrpl.SubmittableTransaction, slots: readonly SlotRole[], feeMultiplier?: number): Promise<Validated>;
  /** A raw submit whose result the caller judges (for attacks and refusals). */
  submitBlob(blob: string): ReturnType<typeof submitReliable>;
  /** Single-signed. Returns the final outcome whatever it is (`tesSUCCESS`, a `tec`, or a rejection). */
  attempt(wallet: Wallet, tx: xrpl.SubmittableTransaction): Promise<SubmitOutcome>;
  /** Four slots sign (FROST) and the combined blob is submitted; the outcome is returned, never thrown. */
  attemptMulti(
    tx: xrpl.SubmittableTransaction,
    slots: readonly SlotRole[],
    feeMultiplier?: number,
  ): Promise<SubmitOutcome>;
  /** Moves the ledger on by `n`: closes them (standalone) or waits for the network to validate them. */
  advance(n: number): Promise<void>;
  /** Stops the background closer. From now on a test closes ledgers itself with `accept`. */
  pause(): Promise<void>;
  resume(): void;
  /** Runs `fn` with the closer stopped, then starts it again (a slow proof must not push the mint out of the ledger history). */
  idle<T>(fn: () => Promise<T>): Promise<T>;
  /** Closes exactly one ledger and returns its header (only while paused). */
  accept(): Promise<{ index: number; closeTime: number }>;
  /** The last validated ledger's header. */
  lcl(): Promise<{ index: number; closeTime: number }>;
  /** The engine result of a raw submit (a hint only), without waiting for a ledger. */
  rawSubmit(blob: string): Promise<string>;
  /** The close time of the parent of the ledger that holds `hash`, and the transaction's validated result. */
  placed(hash: string): Promise<{ result: string; ledgerIndex: number; parentCloseTime: number }>;
  close(): Promise<void>;
}

// Source: https://xrpl.org/docs/references/http-websocket-apis/admin-api-methods/server-control-methods/ledger_accept
export async function openChain(env: LedgerEnv = standaloneEnv()): Promise<Chain> {
  const standalone = env.name === 'standalone';
  const client = await connect(env);
  // A public network closes its own ledgers: no ticker, and `accept` does not exist there.
  const ticker = standalone ? await connect(env) : undefined;
  let stop: (() => Promise<void>) | undefined = ticker && closer(ticker);
  const rpc = rpcOf(client);
  const fees = await readFees(client);
  const ctx: BuildCtx = { network: env.name as BuildCtx['network'], baseFeeDrops: fees.baseFeeDrops };
  const log: StepLog[] = [];
  let current = 'setup';
  const opts = { pollMs: standalone ? 50 : 1000, timeoutMs: standalone ? 60_000 : 180_000 };
  const submitBlob = (blob: string) => submitReliable(rpc, blob, opts);

  const header = async (index: number | 'validated') => {
    const r = (await client.request({ command: 'ledger', ledger_index: index })).result as {
      ledger: { ledger_index: number | string; close_time: number };
    };
    return { index: Number(r.ledger.ledger_index), closeTime: r.ledger.close_time };
  };
  const pause = async () => {
    await stop?.();
    stop = undefined;
  };
  const resume = () => {
    if (ticker) stop ??= closer(ticker);
  };
  const advance = async (n: number) => {
    if (standalone) return advanceLedgers(client, n);
    const target = (await header('validated')).index + n;
    while ((await header('validated')).index < target) await new Promise((r) => setTimeout(r, 4000));
  };

  async function settle(blob: string, type: string): Promise<Validated> {
    const tx = xrpl.decode(blob) as Json;
    const r = await submitBlob(blob);
    const result = r.status === 'validated' || r.status === 'rejected' ? r.result : r.status;
    const hash = r.status === 'validated' ? r.hash : xrpl.hashes.hashSignedTx(blob);
    log.push({ step: current, type, result, hash });
    if (r.status !== 'validated' || r.result !== 'tesSUCCESS') throw new Error(`${type} ended ${JSON.stringify(r)}`);
    return { hash: r.hash, ledgerIndex: r.ledgerIndex, meta: r.meta as Json, blob, tx };
  }
  const multiBlob = async (tx: xrpl.SubmittableTransaction, slots: readonly SlotRole[], feeMultiplier: number) => {
    const prepared = await prepare(tx, { client, signers: slots.length, lastLedgerOffset: 1800, feeMultiplier });
    return combine(
      slots.map((s) => s.signTx(prepared as unknown as Json)),
      slots.map((s) => s.address),
    );
  };

  return {
    client,
    rpc,
    ctx,
    fees,
    log,
    async step(name, fn) {
      current = name;
      try {
        return await fn();
      } catch (e) {
        throw new Error(`[${name}] ${e instanceof Error ? e.message : String(e)}`, { cause: e });
      }
    },
    async fund(wallet, xrp) {
      if (!standalone) return fundFromFaucet(env, client, wallet.classicAddress, xrp);
      const tx = await client.autofill({
        TransactionType: 'Payment',
        Account: GENESIS.classicAddress,
        Destination: wallet.classicAddress,
        Amount: String(xrp * 1_000_000),
      });
      await settle(GENESIS.sign(tx).tx_blob, 'Payment (genesis)');
    },
    async send(wallet, tx) {
      return settle(wallet.sign(await prepare(tx, { client })).tx_blob, tx.TransactionType);
    },
    async multisend(tx, slots, feeMultiplier = 1) {
      return settle(await multiBlob(tx, slots, feeMultiplier), tx.TransactionType);
    },
    submitBlob,
    async attempt(wallet, tx) {
      return submitBlob(wallet.sign(await prepare(tx, { client })).tx_blob);
    },
    async attemptMulti(tx, slots, feeMultiplier = 1) {
      return submitBlob(await multiBlob(tx, slots, feeMultiplier));
    },
    advance,
    pause,
    resume,
    async idle(fn) {
      await pause();
      try {
        return await fn();
      } finally {
        resume();
      }
    },
    async accept() {
      if (!standalone || stop) throw new Error('accept: only on a standalone ledger with the closer paused');
      await advanceLedgers(client, 1);
      return header('validated');
    },
    lcl: () => header('validated'),
    async rawSubmit(blob) {
      const r = (await client.request({ command: 'submit', tx_blob: blob } as never)) as unknown as {
        result: Json;
      };
      return String(r.result.engine_result);
    },
    async placed(hash) {
      const r = (await client.request({ command: 'tx', transaction: hash })).result as unknown as {
        validated: boolean;
        ledger_index: number;
        meta: Json;
      };
      if (!r.validated) throw new Error(`tx ${hash} is not validated`);
      const parent = await header(r.ledger_index - 1);
      return {
        result: String(r.meta.TransactionResult),
        ledgerIndex: r.ledger_index,
        parentCloseTime: parent.closeTime,
      };
    },
    async close() {
      await pause();
      await Promise.all(
        [client.disconnect(), ticker?.disconnect() ?? Promise.resolve()].map((p) => p.catch(() => undefined)),
      );
    },
  };
}

// ---------- plain-key helpers for operations accounts ----------

export function newWallet(curve: Curve): Wallet {
  return xrpl.Wallet.generate(curve === 'ed25519' ? xrpl.ECDSA.ed25519 : xrpl.ECDSA.secp256k1);
}

/** A signature over `msg` by an XRPL account key, as `verifyXrplKeySig` checks it: Ed25519, or DER low-S over SHA-512Half. */
export function opsSign(w: Wallet, msg: Uint8Array): Uint8Array {
  const sk = hexToBytes(w.privateKey).subarray(1);
  return w.publicKey.startsWith('ED')
    ? ed25519.sign(msg, sk)
    : secp256k1.sign(sha512(msg).subarray(0, 32), sk, { prehash: false, format: 'der', lowS: true });
}

// ---------- FROST slots ----------

export interface Holder {
  readonly role: string;
  readonly keyIds: { readonly ed25519: string; readonly mlDsa65: string };
}
/** A slot: three shares from our DKG, three enrollment key pairs and three ML-DSA-65 keys. There is no slot wallet. */
export interface SlotRole {
  readonly name: SlotName;
  readonly address: string;
  /** The 33-byte group key, uppercase hex (the key in the seal). */
  readonly pubHex: string;
  readonly keys: DkgKey[];
  readonly roles: string[];
  readonly holders: Holder[];
  readonly rows: KeyRow[];
  readonly pq: { publicKey: Uint8Array; secretKey: Uint8Array }[];
  readonly pqKeyHash: string;
  readonly policy: string;
  /** The `frost.dkg.completed` data: the transcript, the echo signatures and the three pair test signatures. */
  readonly dkg: Json;
  /** FROST signature (2 of 3 shares, the pair rotates) over `msg`: a plain Ed25519 signature under the group key. */
  sign(msg: Uint8Array): Uint8Array;
  /** One Signer entry blob for an XRPL multisigned transaction. */
  signTx(tx: Json): string;
  /** A hybrid signer for evidence envelopes by holder `j` (enrollment Ed25519 plus ML-DSA-65). */
  holderSigner(j: number): SignerPort;
  holderIds(): SlotHolders;
}

const PAIRS = [
  [1, 2],
  [1, 3],
  [2, 3],
] as const;

export async function makeSlot(name: SlotName): Promise<SlotRole> {
  const k = await dkgKeys(name);
  const keys = k.keys as DkgKey[];
  const pq = k.holders.map(() => pqKeygen());
  const holders: Holder[] = k.holders.map((h) => ({
    role: h.key.role,
    keyIds: { ed25519: `${name}/${h.key.role}/ed`, mlDsa65: `${name}/${h.key.role}/pq` },
  }));
  const rows: KeyRow[] = holders.flatMap(({ keyIds }, j) => [
    {
      keyId: keyIds.ed25519,
      alg: 'ed25519' as const,
      publicKey: (k.holders[j] as (typeof k.holders)[0]).key.edPub.slice(1),
      validFrom: 1,
      logged: true,
      pair: `${name}/${(k.holders[j] as (typeof k.holders)[0]).key.role}`, // both halves of one holder (I-S-P1)
    },
    {
      keyId: keyIds.mlDsa65,
      alg: 'ml-dsa-65' as const,
      publicKey: (pq[j] as { publicKey: Uint8Array }).publicKey,
      validFrom: 1,
      logged: true,
      pair: `${name}/${(k.holders[j] as (typeof k.holders)[0]).key.role}`,
    },
  ]);
  const roles = k.holders.map((h) => h.key.role);
  const pubHex = up(slotPubkey(k.pub));
  let turn = 0; // the pair rotates, so every pair signs over a run and a failing run replays the same way
  const pairNow = (): [number, number] => {
    const [a, b] = PAIRS[turn++ % 3] as readonly [number, number];
    return [a - 1, b - 1];
  };
  const sign = (msg: Uint8Array) => {
    const [a, b] = pairNow();
    return frostSign(k.pub, [(keys[a] as DkgKey).secret, (keys[b] as DkgKey).secret], msg);
  };
  const pairSig = (a: number, b: number, msg: Uint8Array) =>
    frostSign(k.pub, [(keys[a - 1] as DkgKey).secret, (keys[b - 1] as DkgKey).secret], msg);
  const transcript = k.run.echoes[0]?.fields[0] as Uint8Array;
  const dkg: Json = {
    slot: name,
    session_id: bytesToHex(k.ctx.sessionId),
    group_pub: pubHex,
    slot_policy: bytesToHex(slotPolicy(name, roles)),
    roles,
    transcript_hash: bytesToHex(transcript),
    holder_sigs: holders.map(({ keyIds }, j) => ({
      key_id: keyIds.ed25519,
      sig: bytesToHex(k.run.echoes.find((e) => e.from === j + 1)?.sig as Uint8Array),
    })),
    verifying_shares: Object.entries(k.pub.verifyingShares).map(([identifier, s]) => ({
      identifier,
      share: bytesToHex(s),
    })),
    test_sigs: PAIRS.map(([a, b]) => bytesToHex(pairSig(a, b, testSignMessage(k.ctx, k.pub, [a, b])))),
  };
  const self: SlotRole = {
    name,
    address: slotAddress(k.pub),
    pubHex,
    keys,
    roles,
    holders,
    rows,
    pq,
    pqKeyHash: bytesToHex(pqKeyHash(pq.map((p) => p.publicKey) as [Uint8Array, Uint8Array, Uint8Array])),
    policy: bytesToHex(slotPolicy(name, roles)),
    dkg,
    sign,
    signTx(tx) {
      const first = turn++ % 3;
      const picks = [(first + 0.5) / 3, 0.25]; // slotSign takes the pair from these two draws
      let i = 0;
      return slotSign(self, tx, () => picks[i++ % 2] as number);
    },
    holderSigner(j) {
      const h = holders[j] as Holder;
      const secret = (k.holders[j] as (typeof k.holders)[0]).secret;
      return nobleHybridSigner(
        {
          keyId: h.keyIds.ed25519 as KeyId,
          publicKey: (k.holders[j] as (typeof k.holders)[0]).key.edPub.slice(1),
          sign: async (m) => ed25519.sign(m, secret),
        },
        { keyId: h.keyIds.mlDsa65 as KeyId, secretKey: (pq[j] as { secretKey: Uint8Array }).secretKey },
      );
    },
    holderIds: () => holders.map((h) => h.keyIds) as unknown as SlotHolders,
  };
  return self;
}

// ---------- the parties ----------

/** A client: a classic account, a chip passport with its commitment (DESIGN 6.2), and later a FROST slot (A or B). */
export interface ClientBase {
  readonly side: Side;
  readonly name: 'alice' | 'bob';
  readonly wallet: Wallet;
  readonly passport: ReturnType<typeof demoPassport>;
  readonly salt: Uint8Array;
  readonly commitment: Uint8Array;
}
export interface ClientRole extends ClientBase {
  readonly slot: SlotRole;
}

export function makeClient(side: Side): ClientBase {
  const name = side === 'A' ? 'alice' : 'bob';
  const passport = demoPassport(name);
  const salt = randomBytes(32);
  return {
    side,
    name,
    wallet: newWallet('ed25519'),
    passport,
    salt,
    commitment: passportCommitment(passportRecord(passport.passport.dg1, passport.passport.sod), salt),
  };
}

/** A lawyer: an operations account (either curve), a bar commitment (DESIGN 6.16), and later a FROST slot (LA or LB). */
export interface LawyerBase {
  readonly role: 'LA' | 'LB';
  readonly firm: string;
  readonly ops: Wallet;
  readonly jurisdiction: string;
  readonly barNumber: string;
  readonly barSalt: Uint8Array;
  readonly commitment: Uint8Array;
}
export interface LawyerRole extends LawyerBase {
  readonly slot: SlotRole;
}

export function makeLawyer(role: 'LA' | 'LB', firm: string, curve: Curve, barNumber: string): LawyerBase {
  const barSalt = randomBytes(32);
  const jurisdiction = 'US-CA';
  return {
    role,
    firm,
    ops: newWallet(curve),
    jurisdiction,
    barNumber,
    barSalt,
    commitment: openBarCommitment(barSalt, jurisdiction, barNumber),
  };
}

/** The slot is made by the DKG (P2 for lawyers, P5 for clients), after the account exists. */
export const withSlot = <T extends ClientBase | LawyerBase>(base: T, slot: SlotRole): T & { slot: SlotRole } => ({
  ...base,
  slot,
});

/** The verifier: an issuer account and a hybrid attestation key (the keys of `config.verifierKeyIds`). */
export interface Verifier {
  readonly issuer: Wallet;
  readonly signer: SignerPort;
  readonly rows: KeyRow[];
  readonly keyIds: { readonly ed25519: string; readonly mlDsa65: string };
}

export function makeVerifier(): Verifier {
  const sk = randomBytes(32);
  const pq = pqKeygen();
  const keyIds = { ed25519: 'verifier/ed', mlDsa65: 'verifier/pq' };
  const pub = ed25519.getPublicKey(sk);
  return {
    issuer: newWallet('ed25519'),
    keyIds,
    signer: nobleHybridSigner(
      { keyId: keyIds.ed25519 as KeyId, publicKey: pub, sign: async (m) => ed25519.sign(m, sk) },
      { keyId: keyIds.mlDsa65 as KeyId, secretKey: pq.secretKey },
    ),
    rows: [
      { keyId: keyIds.ed25519, alg: 'ed25519', publicKey: pub, validFrom: 1, logged: true, pair: 'verifier' },
      {
        keyId: keyIds.mlDsa65,
        alg: 'ml-dsa-65',
        publicKey: pq.publicKey,
        validFrom: 1,
        logged: true,
        pair: 'verifier',
      },
    ],
  };
}

/** P2.5-03: a slot role holds no wallet, seed or private-key field anywhere in its object graph. */
export function plainKeyFields(role: unknown, path = 'role', seen = new Set<unknown>()): string[] {
  if (typeof role !== 'object' || role === null || seen.has(role) || role instanceof Uint8Array) return [];
  seen.add(role);
  if (role instanceof xrpl.Wallet) return [path];
  return Object.entries(role).flatMap(([k, v]) =>
    /^(privateKey|seed|wallet)$/i.test(k) ? [`${path}.${k}`] : plainKeyFields(v, `${path}.${k}`, seen),
  );
}

// ---------- evidence records ----------

/** Envelope builders for one deal. Every record is hybrid-signed (DESIGN 6.13) by the signer it is given. */
export function evidenceFor(dealId: string, rootHex: string) {
  async function envelope(payloadType: string, body: unknown, signer: SignerPort): Promise<Uint8Array> {
    const b = bytes(body);
    const h = await signer.signHybrid(pae(payloadType, b), DSSE);
    return bytes({
      payloadType,
      payload: toBase64(b),
      signatures: [
        { keyid: h.keyIds.ed25519, sig: toBase64(h.ed25519) },
        { keyid: h.keyIds.mlDsa65, sig: toBase64(h.mlDsa65) },
      ],
    });
  }
  let seq = 0;
  const event = (kind: string, data: Json, by: SlotRole, role: 'lawyerA' | 'lawyerB' | 'alice' | 'bob') =>
    envelope(
      EVENT,
      {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [{ name: `deal:${dealId}`, digest: { sha256: rootHex } }],
        predicateType: 'https://legx.dev/event/v1',
        predicate: {
          event_id: uuid7(),
          deal_id: dealId,
          seq: seq++,
          kind,
          actor: { role, key_id: by.holders[0]?.keyIds.ed25519 },
          occurred_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
          prev_hash: zeros32,
          payload_commitment: zeros32,
          sig_algs: ['ed25519', 'ml-dsa-65'],
          data,
        },
      },
      by.holderSigner(0),
    );
  return { envelope, event, attestation: (body: Json, signer: SignerPort) => envelope(ATTEST, body, signer) };
}
export type Evidence = ReturnType<typeof evidenceFor>;

/** The sealed public data of the deal (DESIGN 6.6), parsed by the contracts schema. */
export function dealData(d: {
  rootHex: string;
  signedContractSeal: Uint8Array;
  wallet: string;
  alice: ClientRole;
  bob: ClientRole;
  lawyerA: LawyerRole;
  lawyerB: LawyerRole;
}): PublicDealData {
  const { alice, bob, lawyerA, lawyerB } = d;
  const slots = [alice.slot, lawyerA.slot, bob.slot, lawyerB.slot];
  return PublicDealData.parse({
    contractRoot: d.rootHex,
    signedContractSeal: bytesToHex(d.signedContractSeal),
    walletAddress: d.wallet,
    xPubA: alice.slot.pubHex,
    xPubB: bob.slot.pubHex,
    commitmentA: bytesToHex(alice.commitment),
    commitmentB: bytesToHex(bob.commitment),
    idMethodA: 'nfc-chip',
    idMethodB: 'nfc-chip',
    identityPolicy: 'chip',
    lawyerPubA: lawyerA.slot.pubHex,
    lawyerPubB: lawyerB.slot.pubHex,
    lawyerCommitmentA: bytesToHex(lawyerA.commitment),
    lawyerCommitmentB: bytesToHex(lawyerB.commitment),
    lawyerOpsA: lawyerA.ops.classicAddress,
    lawyerOpsB: lawyerB.ops.classicAddress,
    releaserAccount: lawyerB.ops.classicAddress,
    slotPolicyA: alice.slot.policy,
    slotPolicyLA: lawyerA.slot.policy,
    slotPolicyB: bob.slot.policy,
    slotPolicyLB: lawyerB.slot.policy,
    pqKeyHashA: alice.slot.pqKeyHash,
    pqKeyHashLA: lawyerA.slot.pqKeyHash,
    pqKeyHashB: bob.slot.pqKeyHash,
    pqKeyHashLB: lawyerB.slot.pqKeyHash,
    signerAccounts: slots.map((s) => s.address),
    quorum: 4,
    payoutA: `${alice.wallet.classicAddress}:7`,
    payoutB: bob.wallet.classicAddress,
  });
}

export interface LedgerRef {
  readonly index: number;
  readonly hash: string;
  readonly closeTime: number;
}

/** `BarVerification` (DESIGN 6.16, P0): the verifier checked the register for this operations account. */
export async function barVerification(ev: Evidence, v: Verifier, l: LawyerBase, checkedAt: LedgerRef) {
  const envelope = await ev.attestation(
    {
      jurisdiction: l.jurisdiction,
      bar_number_sha256: barNumberSha256(l.barNumber),
      status: 'active',
      source: {
        kind: 'manual',
        url: 'https://example.org/bar-registry',
        evidence_sha256: bytesToHex(sha256(utf8ToBytes(l.firm))),
      },
      ops_account: l.ops.classicAddress,
      checked_at_ledger: { ledger_index: checkedAt.index, ledger_hash: checkedAt.hash },
      verifier_key_id: v.keyIds.ed25519,
      sig_algs: ['ed25519', 'ml-dsa-65'],
    },
    v.signer,
  );
  return { envelope, sha256: sha256(envelope) };
}

/** `BarDealLink` (DESIGN 6.16, P2): ties the verified lawyer to this deal's sealed slot key and bar commitment. */
export const barDealLink = (
  ev: Evidence,
  v: Verifier,
  l: LawyerRole,
  verification: Uint8Array,
  d: { dealId: string; rootHex: string },
) =>
  ev.attestation(
    {
      deal_id: d.dealId,
      contract_root: d.rootHex,
      role: l.role,
      lawyer_pub: l.slot.pubHex,
      bar_commitment: bytesToHex(l.commitment),
      ops_account: l.ops.classicAddress,
      verification_sha256: bytesToHex(sha256(verification)),
      sig_algs: ['ed25519', 'ml-dsa-65'],
    },
    v.signer,
  );

/** The `ops.bound` data (DESIGN 6.14): the ops account key and the lawyer slot both sign the same message. */
export function opsBoundData(l: LawyerRole, rootHex: string): Json {
  const t = {
    contractRoot: hexToBytes(rootHex),
    opsAccount: l.ops.classicAddress,
    lawyerPub: l.slot.pubHex,
    lawyerCommitment: l.commitment,
    role: l.role,
  };
  const msg = opsBindMsg(t);
  return {
    role: l.role,
    ops_account: l.ops.classicAddress,
    ops_pub: l.ops.publicKey,
    lawyer_pub: l.slot.pubHex,
    bar_commitment: bytesToHex(l.commitment),
    sig_ops: up(opsSign(l.ops, msg)),
    sig_lawyer: up(l.slot.sign(msg)),
  };
}

/** The `pq.bound` data (DESIGN 6.13): two holders' ML-DSA-65 signatures and the slot key's cross-signature. */
export function pqBoundData(slot: SlotRole, seal: Uint8Array, holders: [number, number] = [0, 1]): Json {
  const sealHex = bytesToHex(seal);
  const msg = pqBindMsg(seal, hexToBytes(slot.pubHex), hexToBytes(slot.pqKeyHash));
  return {
    binding: {
      slot: slot.name,
      deal_seal: sealHex,
      slot_pub: slot.pubHex,
      pq_key_hash: slot.pqKeyHash,
      holder_sigs: holders.map((j) => ({
        key_id: slot.holders[j]?.keyIds.mlDsa65,
        sig: toBase64(
          mldsaSign('ml-dsa-65', (slot.pq[j] as { secretKey: Uint8Array }).secretKey, msg, 'legx/pq-binding/v1'),
        ),
      })),
      cross_sig: bytesToHex(slot.sign(msg)),
    },
  };
}

/**
 * The chip checks of a client's passport, run by the client's own lawyer (DESIGN 6.15): passive authentication, the
 * commitment opening and Active Authentication over `challenge32` (presenceMsg at release).
 */
export async function chipAttestChecks(c: ClientRole, challenge32: Uint8Array, atTime: number) {
  const { passport } = c.passport;
  const aaKey = passport.aaKey;
  if (!aaKey) throw new Error('the fixture passport has no Active Authentication key');
  const r = await chipChecks({
    dg1: passport.dg1,
    sod: passport.sod,
    dg14: passport.dg14,
    dg15: passport.dg15,
    trustList: [c.passport.csca],
    atTime,
    salt: c.salt,
    commitment: c.commitment,
    presenceMsg: challenge32,
    aaSignature: chipAnswerAA(aaKey, aaChallenge(challenge32)),
  });
  if (!r.ok) throw new Error(`chip checks failed for ${c.name}: ${r.code}`);
  return r.checks;
}

/** `identity.onboarded` (DESIGN 6.10, 6.17 ONBOARDING_OK), signed by the client's own lawyer. */
export async function onboardingRecord(
  ev: Evidence,
  c: ClientRole,
  by: LawyerRole,
  d: { dealId: string; rootHex: string; now: number },
) {
  const checks = await chipAttestChecks(c, randomBytes(32), d.now);
  return ev.attestation(
    {
      deal_id: d.dealId,
      contract_root: d.rootHex,
      side: c.side,
      slot_pub: c.slot.pubHex,
      commitment: bytesToHex(c.commitment),
      disclosure_box_sha256: bytesToHex(randomBytes(32)),
      distinct_tag: bytesToHex(distinctTag(d.dealId, sha256(c.passport.passport.dg1))), // OD-29: SHA-256(DG1) for a chip
      method: 'nfc-chip',
      checks,
      checked_by_role: `lawyer${c.side}`,
      sig_algs: ['ed25519', 'ml-dsa-65'],
    },
    by.slot.holderSigner(0),
  );
}

/** `passport.verified` at release (DESIGN 6.15): fresh Active Authentication bound to `presenceMsg`, slot-signed. */
export async function passportRecordAt(
  ev: Evidence,
  c: ClientRole,
  by: LawyerRole,
  d: { dealId: string; rootHex: string; seal: Uint8Array; anchor: LedgerRef; nonce: Uint8Array; now: number },
) {
  const msg = presenceMsg(d.seal, c.side, hexToBytes(d.anchor.hash), d.nonce);
  const checks = await chipAttestChecks(c, msg, d.now);
  return ev.attestation(
    {
      deal_id: d.dealId,
      contract_root: d.rootHex,
      deal_seal: bytesToHex(d.seal),
      side: c.side,
      commitment: bytesToHex(c.commitment),
      ledger_anchor: { ledger_index: d.anchor.index, ledger_hash: d.anchor.hash },
      method: 'nfc-chip',
      checks,
      presence_sig: bytesToHex(c.slot.sign(msg)),
      lawyer_nonce: bytesToHex(d.nonce),
      checked_by_role: `lawyer${c.side}`,
      sig_algs: ['ed25519', 'ml-dsa-65'],
    },
    by.slot.holderSigner(0),
  );
}

// ---------- reading the gate's ledger input ----------

/**
 * `ReleaseInput['ledger']` for the deal wallet and both operations accounts, all read at ONE validated ledger
 * (`snapshot`), plus the mint transaction by hash in binary form so the gate can hash the signed blob itself.
 * Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/tx (binary)
 */
export async function readGateLedger(
  chain: Chain,
  d: { wallet: string; opsA: string; opsB: string; mintHash: string; history: readonly LedgerRef[] },
): Promise<ReleaseInput['ledger']> {
  const snap = await snapshot(chain.rpc, [d.wallet, d.opsA, d.opsB] as never);
  const at = snap.ledger;
  const of = (a: string) => snap.accounts[a] as NonNullable<(typeof snap.accounts)[string]>;
  const bin = (await chain.client.request({ command: 'tx', transaction: d.mintHash, binary: true }))
    .result as unknown as Json;
  const plain = (await chain.client.request({ command: 'tx', transaction: d.mintHash })).result as unknown as Json;
  const meta = plain.meta as Json;
  const mintTx: MintTx = {
    hash: String(plain.hash),
    validated: plain.validated === true,
    ledger_index: Number(plain.ledger_index),
    tx_blob: String(bin.tx_blob),
    meta: { TransactionResult: String(meta.TransactionResult), nftoken_id: String(meta.nftoken_id) },
  };
  const ops = (a: string) => ({
    validated: true,
    account_data: { ...of(a).accountData } as { Account: string; Flags: number; RegularKey?: string },
  });
  return {
    index: at.ledgerIndex,
    hash: at.ledgerHash,
    closeTime: at.closeTime,
    account: of(d.wallet).accountData as Json,
    objects: of(d.wallet).objects as Json[],
    mintTx,
    credentials: [d.opsA, d.opsB].flatMap((a) =>
      of(a).objects.filter((o) => o.LedgerEntryType === 'Credential' && o.Subject === a),
    ) as Json[],
    opsAccounts: { LA: ops(d.opsA), LB: ops(d.opsB) },
    history: [...d.history],
  };
}

/** A validated ledger's header, by index or the latest. */
export async function ledgerRef(chain: Chain, index: number | 'validated' = 'validated'): Promise<LedgerRef> {
  const r = (await chain.client.request({ command: 'ledger', ledger_index: index })).result as {
    ledger: { ledger_index: number | string; ledger_hash: string; close_time: number };
    validated?: boolean;
  };
  if (r.validated !== true) throw new Error(`ledger ${index} is not validated`);
  return { index: Number(r.ledger.ledger_index), hash: r.ledger.ledger_hash, closeTime: r.ledger.close_time };
}
