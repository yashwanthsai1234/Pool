// Fuzz targets for the parsers in @legx/core: the escrow condition and fulfillment, the mint memo, the gate memo and the
// gate record, DG1 and the SOD, attestations, DSSE and hybrid envelopes, hybrid checkpoints (the 0x06 lines), FROST round
// messages and complaints, and X-Wing ciphertexts.
// Each `run` calls the parser on one input. It must give a result or a typed error, and anything accepted must round-trip.

import { PassportAttestation, ZkTrustRecord } from '@legx/contracts/records';
import { checkTrustRecord, verifyAttestation, verifyOnboarding } from '@legx/core/attest';
import { makeCondition } from '@legx/core/dealcore';
import type { Envelope } from '@legx/core/evidence';
import { escrowFinishFee } from '@legx/core/fees';
import {
  FrostError,
  type FrostMsg,
  frostMsgBytes,
  type MsgKind,
  openEnrollmentMessage,
  parsePoint,
  parseScalar,
  scalarBytes,
} from '@legx/core/frost';
import { dkgReceiveEcho, dkgReceiveRound1, dkgReceiveRound2, judgeComplaint, readRound1 } from '@legx/core/frostDkg';
import { SIG_POLICY, verifyHybrid } from '@legx/core/hybridEnvelope';
import { parseLds, parseSod } from '@legx/core/passport/sod';
import { fromBase64Strict, openPackage, PACKAGE_SUITES, sealPackage, toBase64, XWING_SUITE } from '@legx/core/pq';
import { checkpointText, noteKeyId, verifyCheckpoint } from '@legx/core/pqCheckpoint';
import { gateMemo, verifyGatePassedRecord } from '@legx/core/releaseGate';
import { decodeMintMemo, encodeMintMemo, MINT_MEMO_TYPE, verifySignedContract } from '@legx/core/signedContract';
import { parseDg1, parseSod as parseSodFixture } from '@legx/fixtures/parse';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import {
  ATTEST_TYPE,
  attestPayload,
  CHECKPOINT_BODY,
  CHECKPOINT_KEYS,
  CHECKPOINT_NOTE,
  complaintFixture,
  DEAL,
  dkgFixture,
  EVENT_TYPE,
  LAWYER,
  ledgerLookup,
  NOW,
  ORIGIN,
  registry,
  type Side,
  sealedKeys,
  signEnvelope,
  signedContract,
  u32,
  xwing,
  ZK_PROOF,
} from '../src/fixtures.ts';
import {
  assert,
  assertEqual,
  attempt,
  attemptAsync,
  hex,
  jsonOf,
  type Target,
  text,
  toBytes,
  unhex,
} from '../src/harness.ts';
import { conditionVectors, contractExamples, demoPassports, readBytes, readText } from '../src/seeds.ts';

const enc = (s: string) => utf8ToBytes(s);
const isRange = (e: unknown) => e instanceof RangeError;
const isFrost = (e: unknown) => e instanceof FrostError;
// The fixture's states are reused for every input, and noble's DKG refuses to advance a package twice. That is the
// harness replaying a valid message on a used state, not a parser fault, so it is not counted.
const isFrostOrReplay = (e: unknown) => isFrost(e) || (e instanceof Error && /package used in round/.test(e.message));
const lazy = <T>(f: () => Promise<T>) => {
  let p: Promise<T> | undefined;
  return () => {
    p ??= f();
    return p;
  };
};

// ---------- condition and fulfillment ----------
// @legx/core has no condition parser: it builds PREIMAGE-SHA-256 conditions (makeCondition) and prices the fulfillment
// (escrowFinishFee). The target checks the builder against the RFC layout, A0 25 80 20 <sha256> 81 01 20 and
// A0 22 80 20 <preimage>, with an independent byte-level check; a parser, when one exists, belongs here.
// Source: https://datatracker.ietf.org/doc/html/draft-thomas-crypto-conditions-04 (section 7, PREIMAGE-SHA-256)
const condition: Target = {
  name: 'condition-fulfillment',
  pkg: 'core',
  seeds: () => [
    ...conditionVectors().flatMap((v) => [unhex(v.fulfillment), unhex(v.condition)]),
    new Uint8Array(32).fill(7),
  ],
  run(input) {
    const made = attempt(
      'makeCondition',
      () => makeCondition(input),
      (e) => e instanceof Error && e.message === 'preimage must be 32 bytes',
    );
    if (!made.ok) {
      assert(input.length !== 32, 'a 32 byte preimage was refused');
    } else {
      const { condition: c, fulfillment: f } = made.value;
      assertEqual(c, `A0258020${bytesToHex(sha256(input)).toUpperCase()}810120`, 'condition layout');
      assertEqual(f, `A0228020${bytesToHex(input).toUpperCase()}`, 'fulfillment layout');
      assertEqual(hexToBytes(f.slice(8)), input, 'the preimage is recoverable from the fulfillment');
    }
    for (const signers of [0, 3]) {
      const fee = attempt('escrowFinishFee', () => escrowFinishFee(10, input.length, signers), isRange);
      if (fee.ok) assert(Number.isInteger(fee.value) && fee.value >= 330, 'fee is an integer of at least 33 base fees');
    }
  },
};

// ---------- mint memo (DESIGN 6.12) ----------
const contract = lazy(signedContract);
const mintMemo: Target = {
  name: 'mint-memo',
  pkg: 'core',
  seeds: async () => {
    const d = await contract();
    return [enc(d.memoHex), unhex(d.memoHex), enc(d.uriHex), unhex(d.uriHex)];
  },
  async run(input) {
    const d = await contract();
    for (const memo of [text(input), hex(input).toUpperCase()]) {
      const r = attempt('decodeMintMemo', () => decodeMintMemo(memo));
      if (!r.ok) continue;
      if (r.value.ok) assertEqual(encodeMintMemo(r.value.value), memo, 'decodeMintMemo round trip');
      else assertEqual(r.value.code, 'MEMO_MALFORMED', 'the only memo error');
    }
    for (const [memo, uri] of [
      [text(input), d.uriHex],
      [d.memoHex, text(input)],
      [hex(input).toUpperCase(), hex(input).toUpperCase()],
    ] as const) {
      const v = attempt('verifySignedContract', () => verifySignedContract(d.terms, memo, uri));
      if (v.ok && v.value.ok)
        assert(memo === d.memoHex && uri === d.uriHex, 'accepted a contract that is not the signed one');
    }
    assert(MINT_MEMO_TYPE.length > 0, 'memo type exists');
  },
};

// ---------- gate memo and the gate record ----------
const gateMemoTarget: Target = {
  name: 'gate-memo',
  pkg: 'core',
  seeds: () => {
    const ex = contractExamples();
    return [new Uint8Array(32).fill(9), ...(ex.get('HybridEnvelope') ?? []), ...(ex.get('Envelope') ?? [])];
  },
  run(input) {
    const memo = attempt('gateMemo', () => gateMemo(input), isRange);
    if (memo.ok) {
      assertEqual(memo.value.MemoData, hex(input).toUpperCase(), 'gate memo carries the leaf hash');
      assertEqual(hexToBytes(memo.value.MemoType), enc('legx/release-gate/v1'), 'gate memo type');
    } else assert(input.length !== 32, 'a 32 byte leaf hash was refused');
    const holder = { ed25519: LAWYER.B.ids[0], mlDsa65: LAWYER.B.ids[1] };
    const r = attempt('verifyGatePassedRecord', () =>
      verifyGatePassedRecord(input, {
        deal: DEAL,
        keys: [],
        lawyerB: [holder, holder, holder],
        at: NOW,
      }),
    );
    if (r.ok) assert(!r.value.ok, 'a gate record was accepted with no registered key');
  },
};

// ---------- DG1 and the SOD ----------
const rebuildDg1 = (mrz: string): Uint8Array => concatBytes(Uint8Array.of(0x61, 0x5b, 0x5f, 0x1f, 0x58), enc(mrz));
const dg1Target: Target = {
  name: 'dg1',
  pkg: 'core',
  seeds: () => demoPassports().map((p) => unhex(p.dg1)),
  run(input) {
    const r = attempt('parseDg1', () => parseDg1(input));
    if (r.ok && r.value.ok) {
      // The MRZ round-trips through the canonical encoding. The parser also accepts a non-minimal BER length
      // (61 81 5b ...), so the input itself need not equal the rebuilt bytes; both must give the same MRZ.
      const again = parseDg1(rebuildDg1(r.value.value));
      assertEqual(again.ok && again.value, r.value.value, 'DG1 round trip');
    }
  },
};
const sodTarget: Target = {
  name: 'sod-lds',
  pkg: 'core',
  seeds: () => demoPassports().flatMap((p) => [unhex(p.sod)]),
  run(input) {
    const sod = attempt('parseSod', () => parseSod(input));
    if (sod.ok && sod.value) {
      const again = parseSod(input);
      assertEqual(again?.eContentType, sod.value.eContentType, 'parseSod is deterministic');
      assertEqual(again?.eContent && hex(again.eContent), hex(sod.value.eContent), 'parseSod is deterministic');
      attempt('parseLds', () => parseLds(sod.value?.eContent as Uint8Array));
    }
    attempt('parseLds', () => parseLds(input));
    attempt('parseSodFixture', () => parseSodFixture(input));
  },
};

// ---------- attestations ----------
const input = (envelope: Envelope, side: Side) => ({
  envelope,
  side,
  deal: DEAL,
  sealedKeys,
  ledgerLookup,
  now: NOW,
  zkProof: ZK_PROOF,
});
const attestation: Target = {
  name: 'attestation',
  pkg: 'core',
  seeds: async () => {
    const [a, b] = await Promise.all([
      signEnvelope(ATTEST_TYPE, toBytes(attestPayload('A')), 'A'),
      signEnvelope(ATTEST_TYPE, toBytes(attestPayload('B')), 'B'),
    ]);
    return [toBytes(a), toBytes(b), toBytes(attestPayload('A')), toBytes(attestPayload('B'))];
  },
  async run(bytes) {
    const doc = jsonOf(bytes);
    if (typeof doc !== 'object' || doc === null) return;
    // An envelope is verified as it is; a bare payload is signed by the right lawyer first, so the rules behind the
    // signature check run too.
    const side: Side = (doc as { side?: unknown }).side === 'B' ? 'B' : 'A';
    const envelope = 'payloadType' in doc ? (doc as Envelope) : await signEnvelope(ATTEST_TYPE, toBytes(doc), side);
    for (const s of ['A', 'B'] as const) {
      const r = attempt('verifyAttestation', () => verifyAttestation(input(envelope, s)));
      if (r.ok && r.value.ok) {
        const payload = jsonOf(fromBase64Strict(envelope.payload) ?? new Uint8Array());
        assert(
          PassportAttestation.safeParse(payload).success,
          'verifyAttestation accepted a payload the contracts schema refuses',
        );
      }
      attempt('verifyOnboarding', () => verifyOnboarding(input(envelope, s)));
    }
  },
};

// ---------- trust record (zk group, here for reuse) ----------
export function checkTrust(doc: unknown): void {
  const prod = attempt('checkTrustRecord', () => checkTrustRecord(doc, 'production'));
  const demo = attempt('checkTrustRecord', () => checkTrustRecord(doc, 'demo'));
  const schema = ZkTrustRecord.safeParse(doc);
  if (!prod.ok || !demo.ok) return;
  // A record with a missing or malformed field is refused in both profiles; one that parses is accepted by the demo
  // profile, and by the production profile only when it is free of the Sepolia chain, a mock identifier and dev mode.
  if (schema.success !== demo.value.ok) {
    const t = typeof doc === 'object' && doc !== null ? (doc as Record<string, unknown>) : {};
    const unsafe = [t.chain_id, t.block_number].some(
      (n) => typeof n === 'number' && Number.isInteger(n) && !Number.isSafeInteger(n),
    );
    if (unsafe)
      assert(false, 'checkTrustRecord accepts an unsafe integer chain_id or block_number that the schema refuses');
    const strings = [t.block_hash, t.registry_address, t.root, t.circuit_manifest_version, t.identifier_type];
    const coerced = [...strings, ...(Array.isArray(t.vkey_hashes) ? t.vkey_hashes : [])].some(
      (v) => typeof v !== 'string',
    );
    if (coerced) assert(false, 'checkTrustRecord accepts a non-string value through String() coercion');
    assert(false, 'checkTrustRecord and the ZkTrustRecord schema disagree');
  }
  if (prod.value.ok) {
    assert(schema.success, 'production accepted a record the schema refuses');
    const t = doc as Record<string, unknown>;
    assert(
      t.chain_id !== 11155111 && t.dev_mode === false && !String(t.identifier_type).endsWith('_MOCK'),
      'production accepted a flagged record',
    );
  } else if (schema.success) {
    const t = doc as Record<string, unknown>;
    const flagged = t.chain_id === 11155111 || t.dev_mode === true || String(t.identifier_type).endsWith('_MOCK');
    assert(flagged, 'production refused a clean record');
  }
  if (schema.success) {
    const again = ZkTrustRecord.safeParse(JSON.parse(JSON.stringify(schema.data)));
    assert(again.success, 'trust record round trip');
    if (again.success) assertEqual(again.data, schema.data, 'trust record round trip');
  }
}

// ---------- DSSE and hybrid envelopes ----------
const hybrid: Target = {
  name: 'hybrid-envelope',
  pkg: 'core',
  seeds: async () => [
    toBytes(await signEnvelope(ATTEST_TYPE, toBytes(attestPayload('A')), 'A')),
    toBytes(await signEnvelope(EVENT_TYPE, toBytes({ predicate: { sig_algs: ['ed25519', 'ml-dsa-65'] } }), 'A')),
    toBytes({ sig_algs: ['ed25519', 'ml-dsa-65'] }),
  ],
  async run(bytes) {
    const doc = jsonOf(bytes);
    if (typeof doc !== 'object' || doc === null) {
      attempt('verifyHybrid', () => verifyHybrid(doc as Envelope, registry, NOW));
      return;
    }
    // A bare body is signed with valid keys for each record type: the envelope is sound and the payload rules decide.
    const types = Object.keys(SIG_POLICY);
    const envelopes =
      'payloadType' in doc
        ? [doc as Envelope]
        : await Promise.all(types.map((t) => signEnvelope(t, toBytes(doc), 'A')));
    for (const env of envelopes) {
      const r = attempt('verifyHybrid', () => verifyHybrid(env, registry, NOW));
      if (!r.ok || !r.value.ok) continue;
      const body = fromBase64Strict(env.payload);
      assertEqual(body && hex(r.value.payload), body && hex(body), 'accepted payload is the decoded payload');
      const parsed = jsonOf(r.value.payload) as Record<string, unknown>;
      const algs = (SIG_POLICY[env.payloadType as keyof typeof SIG_POLICY].sigAlgsOf as (p: unknown) => unknown)(
        parsed,
      );
      assertEqual(algs, ['ed25519', 'ml-dsa-65'], 'accepted an envelope whose sig_algs is not the hybrid list');
      assertEqual(env.signatures.length, 2, 'accepted an envelope without exactly two signatures');
    }
  },
};

// ---------- C2SP checkpoint notes and the 0x06 line ----------
const checkpoint: Target = {
  name: 'checkpoint-note',
  pkg: 'core',
  seeds: () => [enc(CHECKPOINT_NOTE), readBytes('core', 'vectors', 'pq', 'legx-checkpoint-golden.txt')],
  run(bytes) {
    const note = text(bytes);
    const r = attempt('verifyCheckpoint', () => verifyCheckpoint(note, ORIGIN, CHECKPOINT_KEYS));
    if (r.ok && r.value.ok) {
      const body = { origin: r.value.origin, treeSize: r.value.treeSize, rootHash: r.value.rootHash };
      assert(note.startsWith(checkpointText(body)), 'an accepted note starts with the checkpoint body it parsed to');
      assertEqual(r.value.rootHash, CHECKPOINT_BODY.rootHash, 'accepted a note for another root');
    }
  },
};

// The 0x06 line: the same signed body, with the ML-DSA-44 cosignature line made from fuzz bytes.
const noteLines = CHECKPOINT_NOTE.split('\n');
const edLine = noteLines[noteLines.indexOf('') + 1] as string;
const pqLine = noteLines[noteLines.indexOf('') + 2] as string;
const validBlob = fromBase64Strict(pqLine.split(' ')[2] as string) as Uint8Array;
const bodyText = CHECKPOINT_NOTE.slice(0, CHECKPOINT_NOTE.indexOf('\n\n') + 2);
const pqKeyId = noteKeyId(CHECKPOINT_KEYS.pq.name, 0x06, CHECKPOINT_KEYS.pq.publicKey);
const line06: Target = {
  name: 'checkpoint-0x06-line',
  pkg: 'core',
  seeds: () => [validBlob],
  run(bytes) {
    // The first byte picks whether the 4 byte key ID is the right one (so the signature itself is checked).
    const blob = bytes.length > 0 && bytes[0] === 0 ? concatBytes(pqKeyId, bytes.subarray(1)) : bytes;
    const note = `${bodyText}${edLine}\n— ${ORIGIN} ${toBase64(blob)}\n`;
    const r = attempt('verifyCheckpoint', () => verifyCheckpoint(note, ORIGIN, CHECKPOINT_KEYS));
    if (r.ok && r.value.ok)
      assertEqual(hex(blob), hex(validBlob), 'accepted a 0x06 cosignature that is not the signed one');
    const ts = attempt('verifyCheckpoint', () => verifyCheckpoint(note.replace(/\n$/, ''), ORIGIN, CHECKPOINT_KEYS));
    if (ts.ok) assert(!ts.value.ok, 'accepted a note without the final newline');
  },
};

// ---------- FROST round messages ----------
const frostMsgOf = (v: unknown): FrostMsg | undefined => {
  if (typeof v !== 'object' || v === null) return undefined;
  const m = v as Record<string, unknown>;
  const h = (x: unknown) => (typeof x === 'string' && /^([0-9a-f]{2})*$/.test(x) ? unhex(x) : undefined);
  const fields = Array.isArray(m.fields) ? m.fields.map(h) : undefined;
  const session = h(m.session);
  const sig = h(m.sig);
  if (!session || !sig || !fields || fields.some((f) => f === undefined) || typeof m.kind !== 'string')
    return undefined;
  if (typeof m.from !== 'number' || typeof m.to !== 'number') return undefined;
  return { session, kind: m.kind as MsgKind, from: m.from, to: m.to, fields: fields as Uint8Array[], sig };
};
export const frostMsgJson = (m: FrostMsg) => ({
  session: hex(m.session),
  kind: m.kind,
  from: m.from,
  to: m.to,
  fields: m.fields.map(hex),
  sig: hex(m.sig),
});
const KINDS: MsgKind[] = [
  'dkg-r1',
  'dkg-echo',
  'dkg-r2',
  'dkg-complaint',
  'refresh-commit',
  'refresh-share',
  'refresh-deleted',
];

const dkgFx = lazy(dkgFixture);
const frostMessages: Target = {
  name: 'frost-round-messages',
  pkg: 'core',
  seeds: async () => {
    const fx = await dkgFx();
    return [
      ...[fx.round1[0], fx.echoes[0], fx.r2[0]].map((m) => toBytes(frostMsgJson(m as FrostMsg))),
      toBytes(fx.round1.map(frostMsgJson)),
      toBytes(fx.echoes.map(frostMsgJson)),
      toBytes(fx.r2.filter((m) => m.to === 1).map(frostMsgJson)),
      new Uint8Array(32).fill(1),
    ];
  },
  async run(bytes) {
    // Group elements and scalars: accepted bytes are canonical (they encode back to the same bytes).
    if (bytes.length === 32) {
      const p = attempt('parsePoint', () => parsePoint(bytes), isFrost);
      if (p.ok) assertEqual(hex(p.value.toBytes()), hex(bytes), 'a parsed point is canonical');
      const s = attempt('parseScalar', () => parseScalar(bytes, true), isFrost);
      if (s.ok) assertEqual(hex(scalarBytes(s.value)), hex(bytes), 'a parsed scalar is canonical');
    }
    const fx = await dkgFx();
    const doc = jsonOf(bytes);
    const msgs = (Array.isArray(doc) ? doc : [doc]).map(frostMsgOf).filter((m): m is FrostMsg => m !== undefined);
    if (msgs.length === 0) return;
    for (const me of [1, 2, 3]) {
      for (const kind of KINDS) {
        for (const m of msgs) {
          const r = attempt('openEnrollmentMessage', () => openEnrollmentMessage(fx.ctx, m, kind, me), isFrost);
          if (r.ok)
            assertEqual(frostMsgJson(r.value), frostMsgJson(m), 'openEnrollmentMessage returns the message it checked');
        }
      }
      const r1 = attempt('readRound1', () => readRound1(fx.ctx, me, msgs), isFrost);
      if (r1.ok) {
        for (const [from, parsed] of r1.value) {
          const src = msgs.find((m) => m.from === from) as FrostMsg;
          assertEqual(
            [...parsed.commitment, parsed.pok, parsed.kemPub].map(hex),
            src.fields.map(hex),
            'round 1 parse round trip',
          );
        }
      }
      const base = fx.states[me - 1] as (typeof fx.states)[number];
      const fresh = {
        ...base,
        round1: new Map([[me, base.round1.get(me)]]),
        transcript: undefined,
      } as unknown as typeof base;
      attempt('dkgReceiveRound1', () => dkgReceiveRound1(fresh, msgs), isFrost);
      await attemptAsync('dkgReceiveEcho', () => dkgReceiveEcho(base, msgs), isFrostOrReplay);
      await attemptAsync('dkgReceiveRound2', () => dkgReceiveRound2(base, msgs), isFrostOrReplay);
    }
  },
};

// ---------- FROST complaints (P5.2-03) ----------
const complaintFx = lazy(complaintFixture);
const complaints: Target = {
  name: 'frost-complaint',
  pkg: 'core',
  seeds: async () => {
    const fx = await complaintFx();
    return [toBytes(frostMsgJson(fx.complaint))];
  },
  async run(bytes) {
    const fx = await complaintFx();
    const doc = jsonOf(bytes);
    const m = frostMsgOf(doc);
    if (!m) return;
    // The first byte of the JSON cannot be a flag, so the same complaint is judged twice: as sent, and re-signed by
    // the complainer (holder 2) after the change. The second case is a field change with a valid signature.
    const resigned = { ...m, sig: fx.signer2.sign(frostMsgBytesOf(m)) };
    for (const c of [m, resigned]) {
      const r = await attemptAsync('judgeComplaint', () => judgeComplaint(fx.ctx, fx.round1, c, xwing), isFrost);
      if (!r.ok) continue;
      assert(Number.isInteger(r.value.guilty) && r.value.reason.length > 0, 'a verdict names a holder and a reason');
      if (r.value.guilty !== c.from) {
        // The complaint was upheld: the accused is holder 1, and the evidence is exactly the real signed ciphertext.
        const real = fx.complaint;
        assertEqual(r.value.guilty, 1, 'only holder 1 sent a bad share');
        assertEqual(c.kind, 'dkg-complaint', 'an upheld complaint is a complaint');
        assertEqual(c.from, 2, 'the complainer is the holder who received the bad share');
        assertEqual(c.fields.map(hex), real.fields.map(hex), 'an upheld complaint carries the real evidence');
        assertEqual(frostMsgJson(frostMsgOf(frostMsgJson(c)) as FrostMsg), frostMsgJson(c), 'complaint round trip');
      }
    }
  },
};
const frostMsgBytesOf = (m: FrostMsg) => frostMsgBytes(m);

// ---------- X-Wing ciphertexts ----------
const XWING_ENC = 1120; // X-Wing ciphertext length (draft-connolly-cfrg-xwing-kem)
const XWING_AAD = enc('fuzz-aad');
const XWING_SK = ml_kem768_x25519.keygen(new Uint8Array(32).fill(5)).secretKey;
const XWING_PK = ml_kem768_x25519.getPublicKey(XWING_SK);
const sealed = lazy(async () => {
  const p = await sealPackage('share', XWING_PK, enc('a share'), XWING_AAD);
  return { enc: p.enc, ct: p.ct, all: concatBytes(p.enc, p.ct) };
});
const xwingTarget: Target = {
  name: 'xwing-ciphertext',
  pkg: 'core',
  seeds: async () => [(await sealed()).all],
  async run(bytes) {
    const good = await sealed();
    // The first 1,120 bytes are the KEM ciphertext, the rest is the AEAD ciphertext.
    const pkg = { suite: XWING_SUITE, enc: bytes.slice(0, XWING_ENC), ct: bytes.slice(XWING_ENC) };
    const r = await attemptAsync('openPackage', () => openPackage('share', pkg, XWING_SK, XWING_AAD, PACKAGE_SUITES));
    assert(r.ok, 'openPackage threw');
    if (r.ok && r.value.ok) assertEqual(hex(bytes), hex(good.all), 'a bad X-Wing ciphertext was accepted');
    // Random bytes in other places: a wrong suite name, kind or associated data never opens.
    const other = await attemptAsync('openPackage', () => openPackage('backup', pkg, XWING_SK, XWING_AAD));
    if (other.ok && other.value.ok) assertEqual(hex(bytes), hex(good.all), 'accepted under another package kind');
    const suite = await attemptAsync('openPackage', () =>
      openPackage('share', { ...pkg, suite: text(bytes.subarray(0, 8)) }, XWING_SK, XWING_AAD),
    );
    if (suite.ok && suite.value.ok) assert(false, 'accepted under an unknown suite');
  },
};

export const coreTargets: Target[] = [
  condition,
  mintMemo,
  gateMemoTarget,
  dg1Target,
  sodTarget,
  attestation,
  hybrid,
  checkpoint,
  line06,
  frostMessages,
  complaints,
  xwingTarget,
];
export { readText, u32 };
