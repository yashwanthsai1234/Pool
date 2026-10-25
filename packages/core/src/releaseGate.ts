// Release gate (DESIGN 6.17, W5): one pure function over one validated ledger and the evidence records, then the
// `release.gate.passed` record lawyer B signs and the EscrowFinish memo (D22). The gate never reads the network, so an
// arbitrator who reruns it on the same input gets the same findings in the same order (IMPLEMENTATION 1.12).
// Source: DESIGN.md 6.17 (the 15 codes), 6.15, 6.16, 6.14, 6.13, 6.12, 6.10, 6.9, 6.4, D22, D23; build/DECISIONS.md OD-2, OD-21
import type { PublicDealData } from '@legx/contracts/deal';
import { LegxEvent } from '@legx/contracts/events';
import type { SignerPort } from '@legx/contracts/ports';
import type { Finding, GATE_CODES } from '@legx/contracts/records';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { hashes, parseNFTokenID, decode as xrplDecode } from 'xrpl';
import {
  type AttestConfig,
  type Profile,
  type SealedKeys,
  type Side,
  verifyAttestation,
  verifyOnboarding,
} from './attest.ts';
import { verifyBarDealLink } from './bar.ts';
import { dealSeal } from './dealcore.ts';
import { type Envelope, leafHashOf, PAYLOAD_TYPE } from './evidence.ts';
import { frostMsgBytes, type SlotName, type SlotPublic, slotPolicy, verifyEd25519Strict } from './frost.ts';
import { testSignMessage } from './frostDkg.ts';
import { type KeyRegistry, type RegisteredKey, signHybrid, verifyHybrid } from './hybridEnvelope.ts';
import { allOk, blocking, checkLock } from './lockcheck.ts';
import { type AccountInfo, verifyOpsBinding } from './opsBinding.ts';
import { fromBase64Strict, pqKeyHash, toBase64, verifyPqBinding } from './pq.ts';
import { MINT_MEMO_TYPE, verifySignedContract } from './signedContract.ts';

export type GateCode = (typeof GATE_CODES)[number];
type Role = 'LA' | 'LB';
// biome-ignore lint/suspicious/noExplicitAny: ledger JSON exactly as rippled returns it
type LedgerJson = Record<string, any>;
type Obj = Record<string, unknown>;

/** One row of the enrollment key registry (DESIGN 6.3, 9 `enrollment_key`), as stored. */
export interface KeyRow extends RegisteredKey {
  readonly keyId: string;
}
/** A slot holder's enrollment key pair, by key ID; a slot lists its three holders in role order (DESIGN 6.4, 6.13). */
export interface HolderKeyIds {
  readonly ed25519: string;
  readonly mlDsa65: string;
}
export type SlotHolders = readonly [HolderKeyIds, HolderKeyIds, HolderKeyIds];
export interface LedgerHeader {
  readonly index: number;
  readonly hash: string; // uppercase hex
  readonly closeTime: number; // Ripple epoch seconds
}
/** The validated `tx` result of the deal's mint, in binary mode, so the gate can hash the signed blob itself. */
export interface MintTx {
  readonly hash: string;
  readonly validated: boolean;
  readonly ledger_index: number;
  readonly tx_blob: string;
  readonly meta: { readonly TransactionResult: string; readonly nftoken_id?: string };
}

/** Everything the gate reads (IMPLEMENTATION 1.12 "Think"): one plain object, no functions, no network. */
export interface ReleaseInput {
  readonly profile: Profile;
  /** Read from ONE validated ledger (`index`, `hash`), except `history`, the validated headers that records name. */
  readonly ledger: LedgerHeader & {
    readonly account: LedgerJson; // the deal wallet's AccountRoot
    readonly objects: readonly LedgerJson[]; // every account_objects page of the deal wallet
    readonly mintTx?: MintTx;
    readonly credentials: readonly LedgerJson[]; // Credential entries whose Subject is lawyerOpsA or lawyerOpsB
    readonly opsAccounts: Readonly<Record<Role, AccountInfo>>;
    readonly history: readonly LedgerHeader[];
  };
  /** Evidence records as stored, byte for byte. */
  readonly records: {
    readonly passport: Partial<Record<Side, Uint8Array>>; // PassportAttestation envelopes
    readonly zkProof: Partial<Record<Side, Uint8Array>>; // stored proof sets, for `proof_sha256`
    readonly onboarding: Partial<Record<Side, Uint8Array>>; // identity.onboarded attestation envelopes
    readonly bar: Partial<Record<Role, { readonly link: Uint8Array; readonly verification: Uint8Array }>>;
    readonly opsBound: Partial<Record<Role, Uint8Array>>; // `ops.bound` event envelopes
    readonly pqBound: Partial<Record<SlotName, Uint8Array>>; // `pq.bound` event envelopes
    readonly dkgCompleted: Partial<Record<SlotName, Uint8Array>>; // `frost.dkg.completed` event envelopes
    readonly keys: readonly KeyRow[];
    readonly slotHolders: Readonly<Record<SlotName, SlotHolders>>;
  };
  readonly deal: {
    readonly id: string;
    readonly data: PublicDealData; // the sealed public data
    readonly mintTxHash: string;
    readonly nftokenId: string;
    readonly credentialSubjects: readonly string[];
    readonly escrow: { owner: string; sequence: number; amountDrops: string; conditionHex: string };
    readonly allowedTicketSequences?: readonly number[];
  };
  /** The account that will submit the EscrowFinish. */
  readonly submitter: string;
  readonly config: {
    readonly verifierIssuer: string; // the configured verifier issuer account (LEGX_ATTORNEY credentials)
    readonly verifierKeyIds: { readonly ed25519: string; readonly mlDsa65: string }; // the verifier attestation key
    readonly attest?: AttestConfig; // the freshness limit (default 1 hour)
  };
}

type Result = { readonly ok: true } | { readonly ok: false; readonly code: string };
const OK: Result = { ok: true };
const no = (code: string): Result => ({ ok: false, code });
/** Runs per-part checks in order and reports the first failure as `<part>:<code>`. */
const each = <P extends string>(parts: readonly P[], check: (p: P) => Result): Result => {
  for (const p of parts) {
    const r = check(p);
    if (!r.ok) return no(`${p}:${r.code}`);
  }
  return OK;
};

const SIDES = ['A', 'B'] as const;
const ROLES = ['LA', 'LB'] as const;
const SLOTS = ['A', 'LA', 'B', 'LB'] as const;
const dataOf = (i: ReleaseInput) => i.deal.data;
const slotPubOf = (d: PublicDealData, s: SlotName) =>
  ({ A: d.xPubA, B: d.xPubB, LA: d.lawyerPubA, LB: d.lawyerPubB })[s];
const sealed = <K extends string>(d: PublicDealData, field: K, s: SlotName) =>
  String((d as unknown as Record<string, unknown>)[`${field}${s}`]);
const isObj = (x: unknown): x is Obj => typeof x === 'object' && x !== null && !Array.isArray(x);
const sealHex = (i: ReleaseInput) => bytesToHex(dealSeal(dataOf(i)));

// ---------- reading stored records ----------

const json = (b: Uint8Array): unknown => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b));
const envelopeOf = (b: Uint8Array): Envelope => json(b) as Envelope;
/** The signed payload of a stored envelope, unverified: only for fields a verifier checks on the same bytes. */
function payloadOf(b: Uint8Array | undefined): Obj | undefined {
  try {
    const p = json(fromBase64Strict(envelopeOf(b as Uint8Array).payload) as Uint8Array);
    return isObj(p) ? p : undefined;
  } catch {
    return undefined;
  }
}
/**
 * `predicate.data` of a stored event of this kind and deal. The gate does not rely on who wrapped it: every event it
 * reads carries its own signatures over sealed values (6.14, 6.13, 6.4), which the rule checks.
 */
function eventData(i: ReleaseInput, b: Uint8Array | undefined, kind: string): Obj | undefined {
  const st = payloadOf(b);
  const p = st?.predicate;
  const subject = Array.isArray(st?.subject) ? (st.subject[0] as Obj | undefined) : undefined;
  if (!isObj(p) || p.kind !== kind || p.deal_id !== i.deal.id || !isObj(p.data)) return undefined;
  if (!isObj(subject?.digest) || subject.digest.sha256 !== dataOf(i).contractRoot) return undefined;
  return p.data;
}

/** The registry built from the stored rows; a key ID listed twice is ambiguous and resolves to nothing. */
function registryOf(rows: readonly KeyRow[]): KeyRegistry {
  const byId = new Map<string, KeyRow | null>();
  for (const r of rows) byId.set(r.keyId, byId.has(r.keyId) ? null : r);
  return (id) => byId.get(id) ?? undefined;
}
const keyOf = (reg: KeyRegistry, id: string, alg: RegisteredKey['alg']) => {
  const k = reg(id);
  return k?.alg === alg ? k.publicKey : undefined;
};

/**
 * OD-21: the key IDs that may sign for a lawyer slot: its holders' enrollment keys, only if their three ML-DSA-65
 * keys give that slot's sealed pqKeyHash (DESIGN 6.13). Otherwise none.
 */
function boundKeyIds(d: PublicDealData, rows: readonly KeyRow[], holders: SlotHolders, slot: SlotName): string[] {
  const reg = registryOf(rows);
  const pubs = holders.map((h) => keyOf(reg, h.mlDsa65, 'ml-dsa-65'));
  try {
    const hash = pqKeyHash(pubs as [Uint8Array, Uint8Array, Uint8Array]);
    return bytesToHex(hash) === sealed(d, 'pqKeyHash', slot) ? holders.flatMap((h) => [h.ed25519, h.mlDsa65]) : [];
  } catch {
    return [];
  }
}
/**
 * In the gate, a lawyer slot's keys count only if the sealed group key also test-signed their Ed25519 halves
 * (testSigned). One stolen ML-DSA key plus a fresh Ed25519 key is refused (I-S-G2).
 */
function gateKeyIds(i: ReleaseInput, slot: Role): string[] {
  try {
    return testSigned(i, slot) ? boundKeyIds(dataOf(i), i.records.keys, i.records.slotHolders[slot], slot) : [];
  } catch {
    return [];
  }
}
/** Computed once per gate run: the attestation rules all read it. */
const sealedKeysOf = (i: ReleaseInput): SealedKeys => ({
  lawyerKeyIds: { A: gateKeyIds(i, 'LA'), B: gateKeyIds(i, 'LB') },
  registry: registryOf(i.records.keys),
});
/** Validated history by index, including the gate's own ledger. */
const lookupOf = (i: ReleaseInput) => (index: number) => [i.ledger, ...i.ledger.history].find((l) => l.index === index);

// ---------- the 15 rules, in DESIGN 6.17 order ----------

// LOCK_OK: the lock checker (6.9) has no blocking findings. The expected releaser is the sealed one, so a wrong
// submitter trips RELEASER_SEALED alone.
function lockOk(i: ReleaseInput): Result {
  const d = dataOf(i);
  const f = checkLock(i.ledger.account, [...i.ledger.objects], {
    deal: d,
    releaserAccount: d.releaserAccount,
    credentialSubjects: [...i.deal.credentialSubjects],
    escrow: { ...i.deal.escrow, minCancelAfter: i.ledger.closeTime + 86_400 },
    ...(i.deal.allowedTicketSequences ? { allowedTicketSequences: [...i.deal.allowedTicketSequences] } : {}),
  });
  return allOk(f)
    ? OK
    : no(
        blocking(f)
          .map((x) => x.code)
          .join(','),
      );
}

/**
 * CONTRACT_SEAL_OK: the stored mint transaction, fetched by its hash, is validated; its signed blob hashes to that
 * hash, so the memo and URI are the ledger's and not a caller's; the NFTokenID's issuer, decoded locally, is
 * lawyerOpsA; `verifySignedContract` passes with the sealed lawyer keys.
 * Source: https://xrpl.org/docs/references/protocol/data-types/nftoken (NFTokenID layout: flags, fee, issuer, taxon, seq)
 * Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/tx (validated, tx_blob)
 */
function contractSealOk(i: ReleaseInput): Result {
  const d = dataOf(i);
  const m = i.ledger.mintTx;
  if (m?.validated !== true) return no('MINT_NOT_VALIDATED');
  if (m.hash !== i.deal.mintTxHash || hashes.hashSignedTx(m.tx_blob) !== m.hash) return no('MINT_HASH_MISMATCH');
  if (!(m.ledger_index <= i.ledger.index) || m.meta.TransactionResult !== 'tesSUCCESS') return no('MINT_NOT_APPLIED');
  const tx = xrplDecode(m.tx_blob) as LedgerJson;
  if (tx.TransactionType !== 'NFTokenMint' || (tx.Issuer ?? tx.Account) !== d.lawyerOpsA) return no('NOT_OPS_A_MINT');
  if (m.meta.nftoken_id !== i.deal.nftokenId) return no('NFT_ID_MISMATCH');
  const nft = parseNFTokenID(i.deal.nftokenId);
  if (nft.Issuer !== d.lawyerOpsA) return no('NFT_ISSUER_NOT_OPS_A');
  if (nft.Taxon !== tx.NFTokenTaxon || nft.Flags !== ((tx.Flags ?? 0) & 0xffff)) return no('NFT_ID_MISMATCH');
  const memos = ((tx.Memos ?? []) as LedgerJson[]).filter((x) => x.Memo?.MemoType === MINT_MEMO_TYPE);
  if (memos.length !== 1) return no('MEMO_MALFORMED');
  const terms = {
    contractRoot: hexToBytes(d.contractRoot),
    walletAddress: d.walletAddress,
    lawyerPubA: d.lawyerPubA,
    lawyerPubB: d.lawyerPubB,
  };
  return verifySignedContract(terms, String(memos[0]?.Memo.MemoData), String(tx.URI ?? ''));
}

// PASSPORT_A_OK, PASSPORT_B_OK: every rule of 6.15, through task 1.9's verifyAttestation.
const passportOk =
  (s: Side) =>
  (i: ReleaseInput, keys: SealedKeys): Result => {
    const b = i.records.passport[s];
    if (!b) return no('MISSING');
    return verifyAttestation({
      envelope: envelopeOf(b),
      side: s,
      deal: { id: i.deal.id, data: dataOf(i) },
      sealedKeys: keys,
      ledgerLookup: lookupOf(i),
      now: i.ledger.closeTime,
      profile: i.profile,
      zkProof: i.records.zkProof[s],
      ...(i.config.attest ? { config: i.config.attest } : {}),
    });
  };

// BAR_A_OK, BAR_B_OK: the BarDealLink and the BarVerification it names (6.16), checked_at_ledger from validated history.
const barOk =
  (r: Role) =>
  (i: ReleaseInput): Result => {
    const rec = i.records.bar[r];
    if (!rec) return no('MISSING');
    const d = dataOf(i);
    const side = r === 'LA' ? 'A' : 'B';
    const anchor = payloadOf(rec.verification)?.checked_at_ledger as Obj | undefined;
    const at = lookupOf(i)(Number(anchor?.ledger_index));
    const reg = registryOf(i.records.keys);
    const res = verifyBarDealLink({
      linkBytes: rec.link,
      verificationBytes: rec.verification,
      trust: { verify: (env) => verifyHybrid(env, reg, i.ledger.closeTime), verifierKeyIds: i.config.verifierKeyIds },
      checkedAtCloseTime: at?.closeTime ?? Number.NaN,
      nowCloseTime: i.ledger.closeTime,
      sealed: {
        dealId: i.deal.id,
        contractRoot: d.contractRoot,
        role: r,
        lawyerPub: slotPubOf(d, r),
        barCommitment: sealed(d, 'lawyerCommitment', side),
        opsAccount: sealed(d, 'lawyerOps', side),
      },
    });
    if (!res.ok) return res;
    return at?.hash === anchor?.ledger_hash ? OK : no('ANCHOR_MISMATCH');
  };

/**
 * ATTORNEY_CREDENTIAL_A_OK, _B_OK: the operations account holds an accepted LEGX_ATTORNEY credential from the
 * configured verifier issuer, not expired by the validated close_time. Reports how far the best candidate got.
 * Source: https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/credential (lsfAccepted 0x00010000)
 */
const LEGX_ATTORNEY = bytesToHex(utf8ToBytes('LEGX_ATTORNEY')).toUpperCase();
const LSF_ACCEPTED = 0x00010000;
const credentialOk =
  (r: Role) =>
  (i: ReleaseInput): Result => {
    const ops = sealed(dataOf(i), 'lawyerOps', r === 'LA' ? 'A' : 'B');
    const stages: [string, (c: LedgerJson) => boolean][] = [
      ['MISSING', (c) => c.LedgerEntryType === 'Credential' && c.Subject === ops && c.CredentialType === LEGX_ATTORNEY],
      ['WRONG_ISSUER', (c) => c.Issuer === i.config.verifierIssuer],
      ['NOT_ACCEPTED', (c) => (Number(c.Flags) & LSF_ACCEPTED) !== 0],
      ['EXPIRED', (c) => c.Expiration === undefined || Number(c.Expiration) > i.ledger.closeTime],
    ];
    let left = [...i.ledger.credentials];
    for (const [code, pass] of stages) {
      left = left.filter(pass);
      if (left.length === 0) return no(code);
    }
    return OK;
  };

// RELEASER_SEALED: the submitter is the sealed releaserAccount, which is also the one DepositPreauth entry (D23).
function releaserSealed(i: ReleaseInput): Result {
  const d = dataOf(i);
  if (i.submitter !== d.releaserAccount || d.releaserAccount !== d.lawyerOpsB) return no('SUBMITTER_NOT_SEALED');
  const pre = i.ledger.objects.filter((o) => o.LedgerEntryType === 'DepositPreauth' && o.Account === d.walletAddress);
  return pre.length === 1 && pre[0]?.Authorize === d.releaserAccount ? OK : no('PREAUTH_NOT_RELEASER');
}

// OPS_BINDINGS_OK: both ops.bound statements verify, both signatures each (6.14), over the sealed terms only.
const opsBindingsOk = (i: ReleaseInput): Result =>
  each(ROLES, (r) => {
    const e = eventData(i, i.records.opsBound[r], 'ops.bound');
    if (!e || e.role !== r) return no('MISSING');
    const d = dataOf(i);
    const side = r === 'LA' ? 'A' : 'B';
    return verifyOpsBinding(i.ledger.opsAccounts[r], {
      contractRoot: hexToBytes(d.contractRoot),
      opsAccount: sealed(d, 'lawyerOps', side),
      lawyerPub: slotPubOf(d, r),
      lawyerCommitment: hexToBytes(sealed(d, 'lawyerCommitment', side)),
      role: r,
      opsPub: String(e.ops_pub),
      opsSig: String(e.sig_ops),
      lawyerSig: String(e.sig_lawyer),
    });
  });

// ONBOARDING_OK: each client's identity.onboarded attestation, signed by that client's own lawyer, states the sealed
// C_side with the sealed method; the gate trusts that lawyer for opening the commitment (OD-2).
function onboarded(i: ReleaseInput, s: Side, keys: SealedKeys) {
  const b = i.records.onboarding[s];
  if (!b) return no('MISSING');
  return verifyOnboarding({
    envelope: envelopeOf(b),
    side: s,
    deal: { id: i.deal.id, data: dataOf(i) },
    sealedKeys: keys,
    now: i.ledger.closeTime,
    profile: i.profile,
  });
}
const onboardingOk = (i: ReleaseInput, keys: SealedKeys): Result => each(SIDES, (s) => onboarded(i, s, keys));

// IDS_DISTINCT: C_A differs from C_B, and the two onboarding attestations' deal-scoped `distinct_tag` values differ
// (OD-29), whatever the methods: salted commitments alone cannot show that one person is not on both sides.
// An unreadable onboarding record leaves nothing to compare; ONBOARDING_OK blocks it.
function idsDistinct(i: ReleaseInput): Result {
  const d = dataOf(i);
  if (d.commitmentA.toLowerCase() === d.commitmentB.toLowerCase()) return no('COMMITMENTS_EQUAL');
  const [a, b] = SIDES.map((s) => payloadOf(i.records.onboarding[s])?.distinct_tag);
  return typeof a === 'string' && a === b ? no('IDENTIFIERS_EQUAL') : OK;
}

// IDENTITY_POLICY_OK: each side's release method is allowed by the sealed identityPolicy and equals the method of
// its verified onboarding attestation. The release method is read from the stored record, whose bytes PASSPORT_x_OK
// verifies; a missing or failing record leaves nothing to compare, and its own code blocks the gate.
const POLICY_ALLOWS: Readonly<Record<string, readonly string[]>> = {
  zk: ['zkpassport'],
  'zk-or-chip': ['zkpassport', 'nfc-chip'],
  chip: ['nfc-chip'],
};
const identityPolicyOk = (i: ReleaseInput, keys: SealedKeys): Result =>
  each(SIDES, (s) => {
    const release = payloadOf(i.records.passport[s])?.method;
    if (release === undefined) return OK;
    if (!POLICY_ALLOWS[dataOf(i).identityPolicy]?.includes(String(release))) return no('METHOD_NOT_ALLOWED');
    const o = onboarded(i, s, keys);
    return !('method' in o) || o.method === release ? OK : no('METHOD_DIFFERS_FROM_ONBOARDING');
  });

// PQ_BINDINGS_OK: all four bindings: two distinct holders' ML-DSA-65 signatures plus the slot key's cross-signature,
// and each pqKeyHash equals the seal (6.13).
const hexBytes = (x: unknown) => hexToBytes(String(x));
const pqBindingsOk = (i: ReleaseInput): Result =>
  each(SLOTS, (s) => {
    const b = eventData(i, i.records.pqBound[s], 'pq.bound')?.binding as Obj | undefined;
    if (!isObj(b) || b.slot !== s || !Array.isArray(b.holder_sigs)) return no('MISSING');
    const d = dataOf(i);
    const reg = registryOf(i.records.keys);
    const holders = i.records.slotHolders[s].map((h) => ({
      keyId: h.mlDsa65,
      mlDsa65: keyOf(reg, h.mlDsa65, 'ml-dsa-65') ?? new Uint8Array(),
    }));
    return verifyPqBinding(
      {
        dealSeal: hexBytes(b.deal_seal),
        slotPub: hexBytes(b.slot_pub),
        pqKeyHash: hexBytes(b.pq_key_hash),
        holderSigs: (b.holder_sigs as Obj[]).map((h) => ({
          keyId: String(h.key_id),
          sig: fromBase64Strict(String(h.sig)) ?? new Uint8Array(),
        })),
        ...(typeof b.cross_sig === 'string' ? { crossSig: hexBytes(b.cross_sig) } : {}),
      },
      { dealSeal: dealSeal(d), slotPub: hexBytes(slotPubOf(d, s)), pqKeyHash: hexBytes(sealed(d, 'pqKeyHash', s)) },
      holders as [(typeof holders)[0], (typeof holders)[0], (typeof holders)[0]],
      (pub, msg, sig) => verifyEd25519Strict(sig, msg, pub),
    );
  });

/**
 * SLOT_SETUP_OK: each slot's frost.dkg.completed record has the sealed group key; every holder's enrollment key signed
 * the transcript hash (the DKG echo); the three pair test signatures verify under the slot key; and the roles give
 * the sealed slotPolicy (6.4).
 */
const PAIRS = [
  [1, 2],
  [1, 3],
  [2, 3],
] as const;
/**
 * The slot's three pair test signatures verify under its sealed group key, over messages that name the holders'
 * Ed25519 enrollment keys (testSignMessage). So the group key itself binds those keys (I-S-G2, I-E2).
 */
function testSigned(i: ReleaseInput, s: SlotName): boolean {
  const e = eventData(i, i.records.dkgCompleted[s], 'frost.dkg.completed');
  if (!e || !Array.isArray(e.test_sigs)) return false;
  const groupPub = hexBytes(slotPubOf(dataOf(i), s));
  const reg = registryOf(i.records.keys);
  const holders = i.records.slotHolders[s].map((h) => ({
    edPub: Uint8Array.of(0xed, ...(keyOf(reg, h.ed25519, 'ed25519') ?? [])),
  }));
  const ctx = { sessionId: hexBytes(e.session_id), slot: s, holders };
  const pub = { commitments: [groupPub.slice(1)] } as SlotPublic;
  const tests = e.test_sigs as unknown[];
  return PAIRS.every(
    (pair, k) =>
      typeof tests[k] === 'string' &&
      /^[0-9a-fA-F]{128}$/.test(tests[k]) &&
      verifyEd25519Strict(hexBytes(tests[k]), testSignMessage(ctx, pub, pair), groupPub),
  );
}

function slotSetup(i: ReleaseInput, s: SlotName): Result {
  const e = eventData(i, i.records.dkgCompleted[s], 'frost.dkg.completed');
  if (!e || e.slot !== s) return no('MISSING');
  const d = dataOf(i);
  if (e.group_pub !== slotPubOf(d, s)) return no('GROUP_KEY_NOT_SEALED');
  const policy = bytesToHex(slotPolicy(s, e.roles as string[]));
  if (policy !== sealed(d, 'slotPolicy', s) || e.slot_policy !== policy) return no('SLOT_POLICY_MISMATCH');
  const session = hexBytes(e.session_id);
  const transcript = hexBytes(e.transcript_hash);
  const reg = registryOf(i.records.keys);
  const sigs = e.holder_sigs as Obj[];
  const signed = i.records.slotHolders[s].every((h, k) => {
    const pub = keyOf(reg, h.ed25519, 'ed25519');
    const echo = frostMsgBytes({ session, kind: 'dkg-echo', from: k + 1, to: 0, fields: [transcript] });
    return (
      sigs[k]?.key_id === h.ed25519 &&
      pub?.length === 32 &&
      verifyEd25519Strict(hexBytes(sigs[k]?.sig), echo, Uint8Array.of(0xed, ...pub))
    );
  });
  if (!signed) return no('TRANSCRIPT_NOT_SIGNED');
  return testSigned(i, s) ? OK : no('TEST_SIGNATURE_INVALID');
}
const slotSetupOk = (i: ReleaseInput): Result => each(SLOTS, (s) => slotSetup(i, s));

type Rule = { readonly code: GateCode; readonly check: (i: ReleaseInput, keys: SealedKeys) => Result };
const RULES: readonly Rule[] = [
  { code: 'LOCK_OK', check: lockOk },
  { code: 'CONTRACT_SEAL_OK', check: contractSealOk },
  { code: 'PASSPORT_A_OK', check: passportOk('A') },
  { code: 'PASSPORT_B_OK', check: passportOk('B') },
  { code: 'BAR_A_OK', check: barOk('LA') },
  { code: 'BAR_B_OK', check: barOk('LB') },
  { code: 'ATTORNEY_CREDENTIAL_A_OK', check: credentialOk('LA') },
  { code: 'ATTORNEY_CREDENTIAL_B_OK', check: credentialOk('LB') },
  { code: 'RELEASER_SEALED', check: releaserSealed },
  { code: 'OPS_BINDINGS_OK', check: opsBindingsOk },
  { code: 'ONBOARDING_OK', check: onboardingOk },
  { code: 'IDS_DISTINCT', check: idsDistinct },
  { code: 'IDENTITY_POLICY_OK', check: identityPolicyOk },
  { code: 'PQ_BINDINGS_OK', check: pqBindingsOk },
  { code: 'SLOT_SETUP_OK', check: slotSetupOk },
];

/** A rule that throws on hostile input fails closed; the gate itself never throws. */
const safely = (check: Rule['check'], i: ReleaseInput, keys: SealedKeys): Result => {
  try {
    return check(i, keys);
  } catch {
    return no('INPUT_MALFORMED');
  }
};

/**
 * The release gate: one blocking finding per DESIGN 6.17 code, in table order. Pure and deterministic.
 * Source: DESIGN.md 6.17; IMPLEMENTATION.md 1.12
 */
export function checkRelease(i: ReleaseInput): Finding[] {
  let keys: SealedKeys;
  try {
    keys = sealedKeysOf(i);
  } catch {
    keys = { lawyerKeyIds: { A: [], B: [] }, registry: () => undefined };
  }
  const findings: Finding[] = RULES.map(({ code, check }) => {
    const r = safely(check, i, keys);
    return r.ok
      ? { code, level: 'block', ok: true }
      : { code, level: 'block', ok: false, detail: r.code.slice(0, 1024) };
  });
  const noFace = demoNoFaceMatch(i, findings);
  return noFace ? [...findings, { code: 'DEMO_NO_FACE_MATCH', level: 'warn', ok: true, detail: noFace }] : findings;
}

/**
 * OD-34: the sides whose zkpassport release proof records `face_match_passed: false`, as `A`, `B` or `A,B`, when the
 * demo profile accepted it (the attestation check refuses it in production). Only a side that passed is named: a failing
 * PASSPORT_x_OK already blocks the gate.
 */
function demoNoFaceMatch(i: ReleaseInput, findings: readonly Finding[]): string | undefined {
  if (i.profile !== 'demo') return undefined;
  const sides = SIDES.filter((s) => {
    const p = payloadOf(i.records.passport[s]);
    const passed = findings.some((f) => f.code === `PASSPORT_${s}_OK` && f.ok);
    return passed && p?.method === 'zkpassport' && (p.checks as Obj | undefined)?.face_match_passed === false;
  });
  return sides.length > 0 ? sides.join(',') : undefined;
}

// ---------- the release.gate.passed record and the EscrowFinish memo ----------

/** SHA-256 of every record the gate relied on, by name, in a fixed order (DESIGN 6.17). */
function reliedOn(i: ReleaseInput): { name: string; sha256: string }[] {
  const r = i.records;
  const list: [string, Uint8Array | undefined][] = [
    ...SIDES.flatMap((s): [string, Uint8Array | undefined][] => [
      [`passport.verified/${s}`, r.passport[s]],
      [`zk.proof/${s}`, r.zkProof[s]],
      [`identity.onboarded/${s}`, r.onboarding[s]],
    ]),
    ...ROLES.flatMap((role): [string, Uint8Array | undefined][] => [
      [`bar.deal_link/${role}`, r.bar[role]?.link],
      [`bar.verification/${role}`, r.bar[role]?.verification],
      [`ops.bound/${role}`, r.opsBound[role]],
    ]),
    ...SLOTS.flatMap((s): [string, Uint8Array | undefined][] => [
      [`pq.bound/${s}`, r.pqBound[s]],
      [`frost.dkg.completed/${s}`, r.dkgCompleted[s]],
    ]),
  ];
  return list.flatMap(([name, b]) => (b ? [{ name, sha256: leafHashOf(b) }] : []));
}

/** The chain fields of the event lawyer B appends (DESIGN 8.1); the evidence service assigns seq and prev_hash. */
export interface GateEventFields {
  readonly event_id: string;
  readonly seq: number;
  readonly occurred_at: string;
  readonly prev_hash: string;
  readonly payload_commitment: string;
}
/**
 * Signs the gate record with lawyer slot LB (FROST, two shares). It gets the bytes to hand to the share holders'
 * allow-list (`{ kind: 'gate-record', envelope }`, frostRules) and the message to sign, their SHA-256.
 */
export type SlotLbSigner = (envelope: Uint8Array, msg: Uint8Array) => Promise<Uint8Array>;

const SIG_ALGS = ['ed25519', 'ml-dsa-65'];
/**
 * What slot LB signs: the SHA-256 of the record's event envelope without signatures and without `slot_lb_sig`, so
 * the record can carry its own FROST signature and the holders' allow-list still sees a release.gate.passed
 * envelope for this deal (DQ-1.15-c; design question DQ-1.12-1).
 */
const unsignedEnvelope = (statement: Obj): Uint8Array =>
  utf8ToBytes(JSON.stringify({ payloadType: PAYLOAD_TYPE, payload: toBase64(utf8ToBytes(JSON.stringify(statement))) }));
function withoutSlotSig(statement: Obj): Obj {
  const st = structuredClone(statement) as { predicate: { data: { gate: Obj } } };
  delete st.predicate.data.gate.slot_lb_sig;
  return st as unknown as Obj;
}

/**
 * Builds the `release.gate.passed` record (DESIGN 6.17): a hybrid envelope by lawyer B's enrollment keys over an
 * event that lists the gate's ledger, its findings and the SHA-256 of every record it relied on, carrying slot LB's
 * FROST signature over the record hash. Refuses unless every finding passes and the slot signature verifies.
 * Returns the exact envelope bytes and their leaf hash, which goes into the EscrowFinish memo (D22).
 */
export async function buildGatePassedRecord(
  i: ReleaseInput,
  event: GateEventFields,
  lawyerB: SignerPort,
  signSlotLb: SlotLbSigner,
): Promise<{ envelopeBytes: Uint8Array; leafHash: Uint8Array }> {
  const findings = checkRelease(i);
  if (!findings.every((f) => f.ok)) throw new Error('GATE_BLOCKED'); // a warning is `ok: true`, it travels in the record
  const { keyIds } = await lawyerB.publicKeys();
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: `deal:${i.deal.id}`, digest: { sha256: dataOf(i).contractRoot } }],
    predicateType: 'https://legx.dev/event/v1',
    predicate: {
      ...event,
      deal_id: i.deal.id,
      actor: { role: 'lawyerB', key_id: keyIds.ed25519 },
      sig_algs: SIG_ALGS,
      kind: 'release.gate.passed',
      data: {
        gate: {
          deal_id: i.deal.id,
          deal_seal: sealHex(i),
          ledger: { ledger_index: i.ledger.index, ledger_hash: i.ledger.hash },
          findings,
          relied_on: reliedOn(i),
        } as Obj,
      },
    },
  };
  const unsigned = unsignedEnvelope(statement);
  const msg = sha256(unsigned);
  const sig = await signSlotLb(unsigned, msg);
  if (!verifyEd25519Strict(sig, msg, hexToBytes(dataOf(i).lawyerPubB))) throw new Error('SLOT_LB_SIG_INVALID');
  statement.predicate.data.gate.slot_lb_sig = bytesToHex(sig);
  LegxEvent.parse(statement);
  const env = await signHybrid(PAYLOAD_TYPE, utf8ToBytes(JSON.stringify(statement)), lawyerB);
  const envelopeBytes = utf8ToBytes(JSON.stringify(env));
  return { envelopeBytes, leafHash: sha256(envelopeBytes) };
}

/**
 * Checks a stored `release.gate.passed` envelope: hybrid-signed by a lawyer B enrollment key bound to the sealed
 * pqKeyHash_LB (OD-21), a passed gate record for this deal, and slot LB's FROST signature over the record hash.
 */
export function verifyGatePassedRecord(
  envelopeBytes: Uint8Array,
  ctx: {
    readonly deal: { readonly id: string; readonly data: PublicDealData };
    readonly keys: readonly KeyRow[];
    readonly lawyerB: SlotHolders;
    readonly at: number;
  },
): Result {
  try {
    const v = verifyHybrid(envelopeOf(envelopeBytes), registryOf(ctx.keys), ctx.at);
    if (!v.ok) return no(`ENVELOPE_INVALID:${v.code}`);
    const bound = boundKeyIds(ctx.deal.data, ctx.keys, ctx.lawyerB, 'LB');
    if (![v.keyIds.ed25519, v.keyIds.mlDsa65].every((k) => bound.includes(k))) return no('WRONG_SIGNER');
    const statement = json(v.payload) as Obj;
    const parsed = LegxEvent.safeParse(statement);
    if (!parsed.success || parsed.data.predicate.kind !== 'release.gate.passed') return no('NOT_A_GATE_RECORD');
    const gate = parsed.data.predicate.data.gate;
    if (parsed.data.predicate.deal_id !== ctx.deal.id || gate.deal_seal !== bytesToHex(dealSeal(ctx.deal.data))) {
      return no('WRONG_DEAL');
    }
    const msg = sha256(unsignedEnvelope(withoutSlotSig(statement)));
    return verifyEd25519Strict(hexToBytes(gate.slot_lb_sig), msg, hexToBytes(ctx.deal.data.lawyerPubB))
      ? OK
      : no('SLOT_SIG_INVALID');
  } catch {
    return no('MALFORMED');
  }
}

/**
 * The EscrowFinish memo (D22): MemoType = hex(utf8("legx/release-gate/v1")), MemoData = the 32-byte leaf hash of the
 * release.gate.passed envelope, both uppercase hex as on the ledger.
 * Source: https://xrpl.org/docs/references/protocol/transactions/common-fields (Memos, at most 1 KB)
 */
export function gateMemo(leafHash: Uint8Array): { MemoType: string; MemoData: string } {
  if (leafHash.length !== 32) throw new RangeError('leaf hash must be 32 bytes');
  return {
    MemoType: bytesToHex(utf8ToBytes('legx/release-gate/v1')).toUpperCase(),
    MemoData: bytesToHex(leafHash).toUpperCase(),
  };
}
