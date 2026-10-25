// Test world for the release gate (task 1.12): a complete, valid gate input built with the real primitives: four
// FROST slots from our DKG, ML-DSA-65 holder keys, hybrid envelopes, a signed NFTokenMint blob, and the lock wallet.
import type { PublicDealData } from '@legx/contracts/deal';
import type { SignerPort } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import * as xrpl from 'xrpl';
import { distinctTag, presenceMsg } from '../../src/attest.ts';
import { pae } from '../../src/evidence.ts';
import { type SlotName, slotPolicy, slotPubkey } from '../../src/frost.ts';
import { type DkgKey, testSignMessage } from '../../src/frostDkg.ts';
import { lsf } from '../../src/lockcheck.ts';
import { opsBindMsg } from '../../src/opsBinding.ts';
import { mldsaSign, nobleHybridSigner, pqBindMsg, pqKeygen, pqKeyHash, toBase64 } from '../../src/pq.ts';
import type { KeyRow, ReleaseInput, SlotHolders } from '../../src/releaseGate.ts';
import { buildSignedContractSeal, contractSigMsg, MINT_MEMO_TYPE } from '../../src/signedContract.ts';
import { dkgKeys, frostSign } from './frost.ts';

export const ATTEST = 'application/vnd.legx.attest+json;v=1';
export const EVENT = 'application/vnd.legx.event+json;v=1';
const DSSE = 'legx/dsse/v1';
export type Json = Record<string, unknown>;
type Side = 'A' | 'B';
type Role = 'LA' | 'LB';
export const h32 = (n: number) => bytesToHex(new Uint8Array(32).fill(n));
const addr = (n: number) => xrpl.encodeAccountID(new Uint8Array(20).fill(n));
const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();
export const bytes = (x: unknown) => utf8ToBytes(JSON.stringify(x));
const SLOTS = ['A', 'LA', 'B', 'LB'] as const;

// ---------- the four slots (built once: a DKG each, real X-Wing transport) ----------

async function makeSlot(slot: SlotName, n: number) {
  const k = await dkgKeys(slot);
  const keys = k.keys as DkgKey[];
  const pq = k.holders.map((_, j) => pqKeygen(new Uint8Array(32).fill(n + j)));
  const ids = k.holders.map((h, j) => ({
    ed25519: `${slot}/${h.key.role}/ed`,
    mlDsa65: `${slot}/${h.key.role}/pq`,
    j,
  }));
  const rows: KeyRow[] = ids.flatMap(({ ed25519, mlDsa65, j }) => [
    {
      keyId: ed25519,
      alg: 'ed25519',
      publicKey: (k.holders[j] as (typeof k.holders)[0]).key.edPub.slice(1),
      validFrom: 1,
      logged: true,
      pair: `${slot}/${j}`,
    },
    {
      keyId: mlDsa65,
      alg: 'ml-dsa-65',
      publicKey: (pq[j] as { publicKey: Uint8Array }).publicKey,
      validFrom: 1,
      logged: true,
      pair: `${slot}/${j}`,
    },
  ]);
  const sign = (msg: Uint8Array, a = 0, b = 1) =>
    frostSign(k.pub, [(keys[a] as DkgKey).secret, (keys[b] as DkgKey).secret], msg);
  const pubHex = up(slotPubkey(k.pub));
  const roles = k.holders.map((h) => h.key.role);
  const transcript = k.run.echoes[0]?.fields[0] as Uint8Array;
  const dkg: Json = {
    slot,
    session_id: bytesToHex(k.ctx.sessionId),
    group_pub: pubHex,
    slot_policy: bytesToHex(slotPolicy(slot, roles)),
    roles,
    transcript_hash: bytesToHex(transcript),
    holder_sigs: ids.map(({ ed25519, j }) => ({
      key_id: ed25519,
      sig: bytesToHex(k.run.echoes.find((e) => e.from === j + 1)?.sig as Uint8Array),
    })),
    verifying_shares: Object.entries(k.pub.verifyingShares).map(([identifier, s]) => ({
      identifier,
      share: bytesToHex(s),
    })),
    test_sigs: (
      [
        [1, 2],
        [1, 3],
        [2, 3],
      ] as const
    ).map(([a, b]) => bytesToHex(sign(testSignMessage(k.ctx, k.pub, [a, b]), a - 1, b - 1))),
  };
  const holderSigner = (j: number): SignerPort => {
    const h = k.holders[j] as (typeof k.holders)[0];
    const id = ids[j] as (typeof ids)[0];
    return nobleHybridSigner(
      { keyId: id.ed25519 as KeyId, publicKey: h.key.edPub.slice(1), sign: async (m) => ed25519.sign(m, h.secret) },
      { keyId: id.mlDsa65 as KeyId, secretKey: (pq[j] as { secretKey: Uint8Array }).secretKey },
    );
  };
  return {
    slot,
    pubHex,
    roles,
    rows,
    sign,
    dkg,
    holders: ids.map(({ ed25519, mlDsa65 }) => ({ ed25519, mlDsa65 })) as unknown as SlotHolders,
    pq,
    pqKeyHash: bytesToHex(pqKeyHash(pq.map((p) => p.publicKey) as [Uint8Array, Uint8Array, Uint8Array])),
    policy: bytesToHex(slotPolicy(slot, roles)),
    holderSigner,
  };
}
type Slot = Awaited<ReturnType<typeof makeSlot>>;
let slotsP: Promise<Record<SlotName, Slot>> | undefined;
const slots = () => {
  slotsP ??= (async () => {
    const out = {} as Record<SlotName, Slot>;
    let n = 0x60;
    for (const s of SLOTS) {
      out[s] = await makeSlot(s, n);
      n += 3;
    }
    return out;
  })();
  return slotsP;
};

// ---------- fixed parties, keys and ledger ----------

function edAccount(n: number) {
  const sk = new Uint8Array(32).fill(n);
  const pub = `ED${up(ed25519.getPublicKey(sk))}`;
  return { sk, pub, address: xrpl.deriveAddress(pub), wallet: new xrpl.Wallet(pub, `ED${up(sk)}`) };
}
export const OPS = { LA: edAccount(0x11), LB: edAccount(0x12) };
const verifierPq = pqKeygen(new Uint8Array(32).fill(0x70));
const verifierEd = new Uint8Array(32).fill(0x71);
const VERIFIER_KEY_IDS = { ed25519: 'verifier/ed', mlDsa65: 'verifier/pq' };
const VERIFIER_ROWS: KeyRow[] = [
  {
    keyId: 'verifier/ed',
    alg: 'ed25519',
    publicKey: ed25519.getPublicKey(verifierEd),
    validFrom: 1,
    logged: true,
    pair: 'verifier',
  },
  {
    keyId: 'verifier/pq',
    alg: 'ml-dsa-65',
    publicKey: verifierPq.publicKey,
    validFrom: 1,
    logged: true,
    pair: 'verifier',
  },
];
const verifierSigner = nobleHybridSigner(
  {
    keyId: 'verifier/ed' as KeyId,
    publicKey: ed25519.getPublicKey(verifierEd),
    sign: async (m) => ed25519.sign(m, verifierEd),
  },
  { keyId: 'verifier/pq' as KeyId, secretKey: verifierPq.secretKey },
);
export const VERIFIER_ISSUER = addr(0x50);
export const WALLET = addr(0x10);
export const ALICE = addr(0x31);
export const BOB = addr(0x32);
export const DEAL_ID = '0192f1a0-7b3c-7d4e-8f00-0000000000a1';
export const NOW = 800_000_000;
export const LEDGER = { index: 90_000_100, hash: up(new Uint8Array(32).fill(0x99)), closeTime: NOW };
export const ANCHOR = { ledger_index: 90_000_090, ledger_hash: up(new Uint8Array(32).fill(0x77)) };
const BAR_LEDGER = { ledger_index: 89_000_000, ledger_hash: up(new Uint8Array(32).fill(0x78)) };
const HISTORY = [
  { index: ANCHOR.ledger_index, hash: ANCHOR.ledger_hash, closeTime: NOW - 60 },
  { index: BAR_LEDGER.ledger_index, hash: BAR_LEDGER.ledger_hash, closeTime: NOW - 10 * 86_400 },
];
const NONCE = h32(0x33);
export const LEGX_ATTORNEY = up(utf8ToBytes('LEGX_ATTORNEY'));
export const CONDITION = `A0258020${'CC'.repeat(32)}810120`;
export const TRUST = {
  chain_id: 1,
  block_number: 21_000_000,
  block_hash: `0x${h32(0x0b)}`,
  registry_address: `0x${'ab'.repeat(20)}`,
  root: `0x${h32(0x0c)}`,
  circuit_manifest_version: '0.40.1',
  vkey_hashes: [`0x${h32(0x0d)}`],
  identifier_type: 'SALTED',
  dev_mode: false,
};
/**
 * A stored release proof set (zk `proofSetBytes`) as the gate reads it: one `bind` disclosure proof whose public
 * inputs 2 and 3 are the scope hashes of `legx.app` and `legx/v1/<dealId>`, committing `custom_data = hex(msg)`.
 */
export function proofSet(dealId: string, msg: Uint8Array, domain = 'legx.app'): Uint8Array {
  const field = (s: string) => `00${bytesToHex(sha256(utf8ToBytes(s)).slice(0, 31))}`;
  const pis = [h32(0x61), h32(0), field(domain), field(`legx/v1/${dealId}`), h32(0x62), h32(0), h32(0x63), h32(0)];
  const bind = { custom_data: bytesToHex(msg) };
  return utf8ToBytes(
    JSON.stringify([{ name: 'bind', proof: pis.join('') + h32(0x64), committedInputs: { bind: { data: bind } } }]),
  );
}
/** OD-29 tag for a test side: the zkpassport identifier, or a stand-in DG1 per side for nfc-chip. */
const tagOf = (method: string, identifier: string, s: Side) =>
  bytesToHex(
    distinctTag(DEAL_ID, method === 'zkpassport' ? utf8ToBytes(identifier) : sha256(utf8ToBytes(`DG1 of ${s}`))),
  );
export const CHIP_CHECKS = {
  sod_signature_valid: true,
  ds_cert_chains_to_csca: true,
  dg1_hash_in_sod: true,
  document_not_expired: true,
  commitment_opens: true,
  chip_authentication: 'AA',
  chip_auth_available: true,
};
/** Release checks of a side; `proof_sha256` is the world's stored proof set (the world fills it in). */
export const zkReleaseChecks = (s: Side, proof?: Uint8Array) => ({
  proof_verified: true,
  identifier_matches: true,
  bound_value_is_presence_msg: true,
  document_not_expired: true,
  face_match_passed: true,
  proof_sha256: proof ? bytesToHex(sha256(proof)) : h32(s === 'A' ? 0x5c : 0x5d),
  trust: TRUST,
});
export const zkOnboardChecks = (s: Side, identifier: string) => ({
  proof_verified: true,
  bound_value_matches: true,
  expiry_after_cancel_plus_30d: true,
  age_over_18: true,
  scope: `legx/v1/${DEAL_ID}`,
  domain: 'legx.app',
  unique_identifier: identifier,
  proof_sha256: h32(s === 'A' ? 0x5a : 0x5b),
  trust: TRUST,
});

/** An NFTokenID with this issuer, flags and taxon 0 at sequence 1 (scrambled as rippled does). */
export function nftokenId(issuer: string, flags = 8): string {
  const seq = 1n;
  const scrambled = (384160001n * seq + 2459n) % 4294967296n;
  return (
    flags.toString(16).padStart(4, '0') +
    '0000' +
    bytesToHex(xrpl.decodeAccountID(issuer)) +
    scrambled.toString(16).padStart(8, '0') +
    seq.toString(16).padStart(8, '0')
  ).toUpperCase();
}

export interface WorldOptions {
  methodA?: 'zkpassport' | 'nfc-chip';
  methodB?: 'zkpassport' | 'nfc-chip';
  policy?: 'zk' | 'zk-or-chip' | 'chip';
  sameCommitment?: boolean;
  identifiers?: { A: string; B: string };
}

/** A complete valid world: `input` passes every gate code; the helpers re-sign changed records for attack rows. */
export async function makeWorld(o: WorldOptions = {}) {
  const S = await slots();
  const method = { A: o.methodA ?? 'zkpassport', B: o.methodB ?? 'nfc-chip' } as const;
  const identifiers = o.identifiers ?? { A: '1234567890', B: '9876543210' };
  const root = h32(1);
  const contractSigs = {
    sigLA: S.LA.sign(contractSigMsg(hexToBytes(root), WALLET, 'LA')),
    sigLB: S.LB.sign(contractSigMsg(hexToBytes(root), WALLET, 'LB')),
  };
  const terms = {
    contractRoot: hexToBytes(root),
    walletAddress: WALLET,
    lawyerPubA: S.LA.pubHex,
    lawyerPubB: S.LB.pubHex,
  };
  const sc = buildSignedContractSeal(terms, contractSigs);
  const data = {
    contractRoot: root,
    signedContractSeal: bytesToHex(sc.seal),
    walletAddress: WALLET,
    xPubA: S.A.pubHex,
    xPubB: S.B.pubHex,
    commitmentA: h32(5),
    commitmentB: o.sameCommitment ? h32(5) : h32(6),
    idMethodA: method.A,
    idMethodB: method.B,
    identityPolicy: o.policy ?? 'zk-or-chip',
    lawyerPubA: S.LA.pubHex,
    lawyerPubB: S.LB.pubHex,
    lawyerCommitmentA: h32(9),
    lawyerCommitmentB: h32(10),
    lawyerOpsA: OPS.LA.address,
    lawyerOpsB: OPS.LB.address,
    releaserAccount: OPS.LB.address,
    slotPolicyA: S.A.policy,
    slotPolicyLA: S.LA.policy,
    slotPolicyB: S.B.policy,
    slotPolicyLB: S.LB.policy,
    pqKeyHashA: S.A.pqKeyHash,
    pqKeyHashLA: S.LA.pqKeyHash,
    pqKeyHashB: S.B.pqKeyHash,
    pqKeyHashLB: S.LB.pqKeyHash,
    signerAccounts: SLOTS.map((s) => xrpl.deriveAddress(S[s].pubHex)),
    quorum: 4,
    payoutA: `${ALICE}:7`,
    payoutB: BOB,
  } as unknown as PublicDealData;
  const { dealSeal, domain } = await import('../../src/dealcore.ts');
  const seal = dealSeal(data);
  const sealHex = bytesToHex(seal);
  const lawyerSigner = { A: S.LA.holderSigner(0), B: S.LB.holderSigner(0) };
  const presence = (s: Side) => presenceMsg(seal, s, hexToBytes(ANCHOR.ledger_hash), hexToBytes(NONCE));
  const zkProof = { A: proofSet(DEAL_ID, presence('A')), B: proofSet(DEAL_ID, presence('B')) };

  async function envelopeBytes(payloadType: string, body: unknown, signer: SignerPort) {
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
  const event = (kind: string, d: Json, signer: SignerPort = lawyerSigner.A) =>
    envelopeBytes(
      EVENT,
      {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [{ name: `deal:${DEAL_ID}`, digest: { sha256: root } }],
        predicateType: 'https://legx.dev/event/v1',
        predicate: {
          event_id: '0192f1a0-7b3c-7d4e-8f00-000000000001',
          deal_id: DEAL_ID,
          seq: seq++,
          kind,
          actor: { role: 'lawyerA', key_id: 'LA/console/ed' },
          occurred_at: '2026-10-24T12:00:00Z',
          prev_hash: h32(0),
          payload_commitment: h32(0x44),
          sig_algs: ['ed25519', 'ml-dsa-65'],
          data: d,
        },
      },
      signer,
    );

  const passportPayload = (s: Side, over: Json = {}): Json => {
    const m = (over.method as string | undefined) ?? method[s];
    return {
      deal_id: DEAL_ID,
      contract_root: root,
      deal_seal: sealHex,
      side: s,
      commitment: s === 'A' ? data.commitmentA : data.commitmentB,
      ledger_anchor: ANCHOR,
      method: m,
      checks: m === 'zkpassport' ? zkReleaseChecks(s, zkProof[s]) : CHIP_CHECKS,
      presence_sig: bytesToHex(S[s].sign(presence(s))),
      lawyer_nonce: NONCE,
      checked_by_role: `lawyer${s}`,
      sig_algs: ['ed25519', 'ml-dsa-65'],
      ...over,
    };
  };
  const passport = (s: Side, over: Json = {}, by: Side = s) =>
    envelopeBytes(ATTEST, passportPayload(s, over), lawyerSigner[by]);
  const onboardPayload = (s: Side, over: Json = {}): Json => {
    const m = (over.method as string | undefined) ?? method[s];
    return {
      deal_id: DEAL_ID,
      contract_root: root,
      side: s,
      slot_pub: S[s].pubHex,
      commitment: s === 'A' ? data.commitmentA : data.commitmentB,
      disclosure_box_sha256: h32(0x45),
      distinct_tag: tagOf(m, identifiers[s], s),
      method: m,
      checks: m === 'zkpassport' ? zkOnboardChecks(s, identifiers[s]) : CHIP_CHECKS,
      checked_by_role: `lawyer${s}`,
      sig_algs: ['ed25519', 'ml-dsa-65'],
      ...over,
    };
  };
  const onboarding = (s: Side, over: Json = {}, by: Side = s) =>
    envelopeBytes(ATTEST, onboardPayload(s, over), lawyerSigner[by]);

  const side = (r: Role): Side => (r === 'LA' ? 'A' : 'B');
  const verificationPayload = (r: Role, over: Json = {}): Json => ({
    jurisdiction: 'US-CA',
    bar_number_sha256: h32(0x46),
    status: 'active',
    source: { kind: 'manual', url: 'https://example.org/bar', evidence_sha256: h32(0x47) },
    ops_account: OPS[r].address,
    checked_at_ledger: BAR_LEDGER,
    verifier_key_id: 'verifier/ed',
    sig_algs: ['ed25519', 'ml-dsa-65'],
    ...over,
  });
  const bar = async (r: Role, overV: Json = {}, overL: Json = {}) => {
    const verification = await envelopeBytes(ATTEST, verificationPayload(r, overV), verifierSigner);
    const link = await envelopeBytes(
      ATTEST,
      {
        deal_id: DEAL_ID,
        contract_root: root,
        role: r,
        lawyer_pub: S[r].pubHex,
        bar_commitment: r === 'LA' ? data.lawyerCommitmentA : data.lawyerCommitmentB,
        ops_account: OPS[r].address,
        verification_sha256: bytesToHex(sha256(verification)),
        sig_algs: ['ed25519', 'ml-dsa-65'],
        ...overL,
      },
      verifierSigner,
    );
    return { link, verification };
  };

  const opsData = (r: Role): Json => {
    const t = {
      contractRoot: hexToBytes(root),
      opsAccount: OPS[r].address,
      lawyerPub: S[r].pubHex,
      lawyerCommitment: hexToBytes(r === 'LA' ? data.lawyerCommitmentA : data.lawyerCommitmentB),
      role: r,
    };
    const msg = opsBindMsg(t);
    return {
      role: r,
      ops_account: OPS[r].address,
      ops_pub: OPS[r].pub,
      lawyer_pub: S[r].pubHex,
      bar_commitment: bytesToHex(t.lawyerCommitment),
      sig_ops: up(ed25519.sign(msg, OPS[r].sk)),
      sig_lawyer: up(S[r].sign(msg)),
    };
  };
  const pqData = (s: SlotName, holders: [number, number] = [0, 1]): Json => {
    const msg = pqBindMsg(seal, hexToBytes(S[s].pubHex), hexToBytes(S[s].pqKeyHash));
    return {
      binding: {
        slot: s,
        deal_seal: sealHex,
        slot_pub: S[s].pubHex,
        pq_key_hash: S[s].pqKeyHash,
        holder_sigs: holders.map((j) => ({
          key_id: S[s].holders[j]?.mlDsa65,
          sig: toBase64(
            mldsaSign('ml-dsa-65', (S[s].pq[j] as { secretKey: Uint8Array }).secretKey, msg, 'legx/pq-binding/v1'),
          ),
        })),
        cross_sig: bytesToHex(S[s].sign(msg)),
      },
    };
  };

  const nftId = nftokenId(OPS.LA.address);
  const mint = (over: Json = {}) => {
    const tx = OPS.LA.wallet.sign({
      TransactionType: 'NFTokenMint',
      Account: OPS.LA.address,
      NFTokenTaxon: 0,
      Flags: 8,
      URI: sc.uriHex,
      Memos: [{ Memo: { MemoType: MINT_MEMO_TYPE, MemoData: sc.memoHex } }],
      Fee: '12',
      Sequence: 5,
      LastLedgerSequence: LEDGER.index,
      ...over,
    } as xrpl.Transaction);
    return {
      hash: tx.hash,
      validated: true,
      ledger_index: LEDGER.index - 50,
      tx_blob: tx.tx_blob,
      meta: { TransactionResult: 'tesSUCCESS', nftoken_id: nftId },
    };
  };
  const mintTx = mint();

  const ALL_FLAGS =
    lsf.DisableMaster |
    lsf.DepositAuth |
    lsf.DisallowIncomingNFTokenOffer |
    lsf.DisallowIncomingCheck |
    lsf.DisallowIncomingPayChan |
    lsf.DisallowIncomingTrustline;
  const credential = (r: Role, over: Json = {}) => ({
    LedgerEntryType: 'Credential',
    Subject: OPS[r].address,
    Issuer: VERIFIER_ISSUER,
    CredentialType: LEGX_ATTORNEY,
    Flags: lsf.CredentialAccepted,
    Expiration: NOW + 90 * 86_400,
    ...over,
  });

  const input: ReleaseInput = {
    profile: 'production',
    ledger: {
      ...LEDGER,
      account: {
        Account: WALLET,
        Flags: ALL_FLAGS,
        Domain: up(domain(hexToBytes(root), seal)),
        OwnerCount: 2,
      },
      objects: [
        {
          LedgerEntryType: 'SignerList',
          SignerQuorum: 4,
          SignerEntries: data.signerAccounts.map((Account) => ({ SignerEntry: { Account, SignerWeight: 1 } })),
        },
        { LedgerEntryType: 'DepositPreauth', Account: WALLET, Authorize: OPS.LB.address },
        { LedgerEntryType: 'Credential', Issuer: WALLET, Subject: ALICE, Flags: lsf.CredentialAccepted },
        { LedgerEntryType: 'Credential', Issuer: WALLET, Subject: BOB, Flags: lsf.CredentialAccepted },
        {
          LedgerEntryType: 'Escrow',
          Account: ALICE,
          Destination: WALLET,
          Sequence: 7,
          Amount: '5000000000',
          Condition: CONDITION,
          CancelAfter: NOW + 200_000,
        },
      ],
      mintTx,
      credentials: [credential('LA'), credential('LB')],
      opsAccounts: {
        LA: { validated: true, account_data: { Account: OPS.LA.address, Flags: 0 } },
        LB: { validated: true, account_data: { Account: OPS.LB.address, Flags: 0 } },
      },
      history: HISTORY,
    },
    records: {
      passport: { A: await passport('A'), B: await passport('B') },
      zkProof,
      onboarding: { A: await onboarding('A'), B: await onboarding('B') },
      bar: { LA: await bar('LA'), LB: await bar('LB') },
      opsBound: { LA: await event('ops.bound', opsData('LA')), LB: await event('ops.bound', opsData('LB')) },
      pqBound: Object.fromEntries(await Promise.all(SLOTS.map(async (s) => [s, await event('pq.bound', pqData(s))]))),
      dkgCompleted: Object.fromEntries(
        await Promise.all(SLOTS.map(async (s) => [s, await event('frost.dkg.completed', S[s].dkg)])),
      ),
      keys: [...SLOTS.flatMap((s) => S[s].rows), ...VERIFIER_ROWS],
      slotHolders: { A: S.A.holders, LA: S.LA.holders, B: S.B.holders, LB: S.LB.holders },
    },
    deal: {
      id: DEAL_ID,
      data,
      mintTxHash: mintTx.hash,
      nftokenId: nftId,
      credentialSubjects: [ALICE, BOB],
      escrow: { owner: ALICE, sequence: 7, amountDrops: '5000000000', conditionHex: CONDITION },
    },
    submitter: OPS.LB.address,
    config: { verifierIssuer: VERIFIER_ISSUER, verifierKeyIds: VERIFIER_KEY_IDS },
  };
  return {
    input,
    S,
    seal,
    lawyerSigner,
    passport,
    onboarding,
    bar,
    event,
    opsData,
    pqData,
    mint,
    credential,
    side,
    sc,
  };
}
export type World = Awaited<ReturnType<typeof makeWorld>>;

/** A deep, freely mutable copy of a gate input (Uint8Arrays are copied too). */
// biome-ignore lint/suspicious/noExplicitAny: attack rows rewrite arbitrary parts of the input
export const mutable = (i: ReleaseInput): any => structuredClone(i);
