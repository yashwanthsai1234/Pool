// T-I-12 and P2.9-01 to P2.9-10 (IMPLEMENTATION 2.9): the zero-knowledge identity flow on a real standalone ledger,
// in the demo profile. Proofs are FRESH (vendored headless prover), bound to the real presenceMsg, and verified by the
// real SDK in devMode through @legx/zk-verifier. Needs the network: Sepolia RPC for the registry roots and ZKPassport's
// circuit CDN (see README.md in this folder).
// Source: IMPLEMENTATION.md 2.9; DESIGN.md 6.2, 6.10, 6.15, 6.17, 12.2 (T-I-12)
import { readdirSync, readFileSync } from 'node:fs';
import { GATE_CODES } from '@legx/contracts/records';
import { checkTrustRecord, presenceMsg } from '@legx/core/attest';
import { fromBase64Strict } from '@legx/core/pq';
import { checkRelease, type ReleaseInput } from '@legx/core/releaseGate';
import {
  checkAgainstSeal,
  checkZkResult,
  identityChangeOutcome,
  identityChangePlan,
  releaseBoundValue,
  trustRecordOf,
  zkIdentityCommitment,
} from '@legx/core/zkIdentity';
import { replayZkVerifier } from '@legx/zk/port';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { advanceLedgers } from '../../src/ledger.ts';
import { type Chain, type Json, ledgerRef, openChain } from '../roles.ts';
import { openBoxes, runZkFlow, type ZkFlowState } from './zkFlow.ts';
import { MOCK_ALICE, openProver, type Prover, portRequest } from './zkTools.ts';

const RECORDED = new URL('../../../zk/fixtures/sets/', import.meta.url);
const NETWORK_FIELDS = ['blockNumber', 'blockHash'] as const;

let chain: Chain;
let prover: Prover;
beforeAll(async () => {
  chain = await openChain();
  prover = await openProver();
});
afterAll(async () => {
  await chain.close();
});

const payloadOf = (envelope: Uint8Array): Json => {
  const e = JSON.parse(new TextDecoder().decode(envelope)) as { payload: string };
  return JSON.parse(new TextDecoder().decode(fromBase64Strict(e.payload) as Uint8Array)) as Json;
};
const failing = (f: ReturnType<typeof checkRelease>) => f.filter((x) => !x.ok).map((x) => x.code);
/** A port outcome: the verdict, or the error that refused it. */
const outcome = (p: Promise<{ verified: boolean }>) =>
  p.then(
    (r) => (r.verified ? 'verified' : 'not verified'),
    (e: { code?: string; reason?: string }) => `refused ${e.code ?? ''} ${e.reason ?? ''}`.trim(),
  );

interface Attacks {
  scopeChanged: string;
  bindChanged: string;
  scopeCheck: string | undefined;
  bindCheck: string | undefined;
  escrowStays: boolean;
  oldHashCheck: string | undefined;
  falseBoundGate: string[];
}

describe('T-I-12 the full flow with zero-knowledge identity (identity policy "zk", demo profile)', () => {
  let f: ZkFlowState;
  const attacks: Partial<Attacks> = {};
  const ledger = { text: '', memoTypes: new Set<string>() };

  beforeAll(async () => {
    f = await runZkFlow(chain, {
      prover,
      policy: 'zk',
      methods: { A: 'zkpassport', B: 'zkpassport' },
      through: 'close',
      afterFinish: async (s) => {
        const seen: Json[] = [];
        for (const hash of s.txHashes)
          seen.push((await s.c.client.request({ command: 'tx', transaction: hash })).result as unknown as Json);
        seen.push(...s.ledgerSnapshots.shell);
        ledger.text = JSON.stringify(seen);
        for (const tx of seen)
          for (const m of (tx.tx_json as { Memos?: { Memo: { MemoType: string } }[] } | undefined)?.Memos ?? [])
            ledger.memoTypes.add(new TextDecoder().decode(hexToBytes(m.Memo.MemoType)));
      },
      beforeFinish: async (s) => {
        const a = s.sides.A.release;
        if (!a) throw new Error('side A has no release');
        const rel = a.set;
        // P2.9-04: a copy with another scope, and a copy with another bound presenceMsg
        attacks.scopeChanged = await outcome(
          prover.adapter.verify(portRequest(rel, { scope: `legx/v1/${s.sides.B.release!.set.request.scope}` })),
        );
        const query = structuredClone(rel.request.originalQuery) as { bind: { custom_data: string } };
        query.bind.custom_data = bytesToHex(randomBytes(32));
        attacks.bindChanged = await outcome(prover.adapter.verify(portRequest(rel, { originalQuery: query as never })));
        const copy = (over: object) => {
          const v = { ...a.verification, ...over };
          return checkZkResult(v, rel.request.originalQuery, {
            stage: 'release',
            dealId: s.dealId,
            profile: 'demo',
            boundValue: releaseBoundValue(a.msg),
            identity: { zkSalt32: s.sides.A.salt, commitment: bytesToHex(s.alice.commitment) },
            faceMatchOptional: true,
          });
        };
        const scoped = copy({ scope: `legx/v1/${s.sides.B.release!.set.request.scope}` });
        attacks.scopeCheck = scoped.ok ? undefined : scoped.code;
        const bound = checkZkResult(a.verification, query as never, {
          stage: 'release',
          dealId: s.dealId,
          profile: 'demo',
          boundValue: releaseBoundValue(a.msg),
          identity: { zkSalt32: s.sides.A.salt, commitment: bytesToHex(s.alice.commitment) },
          faceMatchOptional: true,
        });
        attacks.bindCheck = bound.ok ? undefined : bound.code;
        const escrow = await s.c.client.request({
          command: 'ledger_entry',
          escrow: { owner: s.alice.wallet.classicAddress, seq: s.escrowSequence },
          ledger_index: 'validated',
        });
        attacks.escrowStays = (escrow.result.node as unknown as Json).LedgerEntryType === 'Escrow';

        // a release proof bound to an OLD ledger hash: ledgers close, the lawyer asks for the fresh hash and nonce
        await advanceLedgers(s.c.client, 3);
        const fresh = await ledgerRef(s.c);
        const msg2 = presenceMsg(s.seal, 'A', hexToBytes(fresh.hash), randomBytes(32));
        const old = checkZkResult(a.verification, rel.request.originalQuery, {
          stage: 'release',
          dealId: s.dealId,
          profile: 'demo',
          boundValue: releaseBoundValue(msg2),
          identity: { zkSalt32: s.sides.A.salt, commitment: bytesToHex(s.alice.commitment) },
          faceMatchOptional: true,
        });
        attacks.oldHashCheck = old.ok ? undefined : old.code;
        // a lawyer who honestly records the failed check: the gate refuses
        const body = payloadOf(s.input.records.passport.A as Uint8Array);
        const honest = await s.ev.attestation(
          { ...body, checks: { ...(body.checks as Json), bound_value_is_presence_msg: false } },
          s.lawyerA.slot.holderSigner(0),
        );
        const tampered = structuredClone(s.input) as { records: ReleaseInput['records'] };
        tampered.records.passport.A = honest;
        attacks.falseBoundGate = failing(checkRelease(tampered as unknown as ReleaseInput));
      },
    });
  });

  it('every step is tesSUCCESS and the gate passes with every DESIGN 6.17 code in the demo profile', () => {
    expect(f.input.profile).toBe('demo');
    expect(f.c.log.filter((l) => l.result !== 'tesSUCCESS')).toEqual([]);
    expect(f.findings.filter((x) => x.level === 'block').map((x) => x.code)).toEqual([...GATE_CODES]);
    expect(f.findings.filter((x) => !x.ok)).toEqual([]);
    // OD-34: the headless flow records face_match_passed false; the demo gate passes and says so in a warning.
    expect(f.findings.filter((x) => x.level === 'warn')).toEqual([
      { code: 'DEMO_NO_FACE_MATCH', level: 'warn', ok: true, detail: 'A,B' },
    ]);
    for (const s of ['A', 'B'] as const)
      expect((payloadOf(f.input.records.passport[s] as Uint8Array).checks as Json).face_match_passed).toBe(false);
    expect(f.balances && f.balances.bobAfter - f.balances.bobBefore).toBe(BigInt(f.input.deal.escrow.amountDrops));
    expect(f.balances && f.balances.aliceAfter > f.balances.aliceBefore).toBe(true);
  });

  it('attestations carry method "zkpassport" and a trust record; C_side is the salted zero-knowledge commitment', () => {
    expect(f.data.idMethodA).toBe('zkpassport');
    expect(f.data.idMethodB).toBe('zkpassport');
    for (const s of ['A', 'B'] as const) {
      const side = f.sides[s];
      const commitment = bytesToHex(zkIdentityCommitment(side.salt, side.identifier as string));
      expect(s === 'A' ? f.data.commitmentA : f.data.commitmentB).toBe(commitment);
      for (const rec of [f.input.records.onboarding[s], f.input.records.passport[s]] as Uint8Array[]) {
        const p = payloadOf(rec);
        expect(p.method).toBe('zkpassport');
        expect(p.commitment).toBe(commitment);
        const trust = (p.checks as { trust: Json }).trust;
        expect(trust).toMatchObject({ chain_id: 11155111, identifier_type: 'NON_SALTED_MOCK', dev_mode: true });
        const stage = rec === f.input.records.onboarding[s] ? side.onboarding! : side.release!;
        expect(trust).toEqual(trustRecordOf(stage.verification));
      }
    }
  });

  it('the domain in every request, scope and result is legx.app / legx/v1/<dealId>', () => {
    for (const s of ['A', 'B'] as const) {
      for (const part of [f.sides[s].onboarding!, f.sides[s].release!]) {
        expect(part.set.request.domain).toBe('legx.app');
        expect(part.verification.domain).toBe('legx.app');
        expect(part.set.request.scope).toBe(`legx/v1/${f.dealId}`);
        expect(part.verification.scope).toBe(`legx/v1/${f.dealId}`);
      }
    }
  });

  it('P2.9-05 the identifier is stable between onboarding and release, and differs between the parties', () => {
    for (const s of ['A', 'B'] as const) {
      const side = f.sides[s];
      expect(side.release!.verification.uniqueIdentifier).toBe(side.onboarding!.verification.uniqueIdentifier);
      expect(side.release!.verification.uniqueIdentifier).toBe(side.identifier);
    }
    expect(f.sides.A.identifier).not.toBe(f.sides.B.identifier);
    // Bob's release proof does not satisfy Alice's sealed commitment (same scope, another person: another identifier)
    const r = checkZkResult(f.sides.B.release!.verification, f.sides.B.release!.set.request.originalQuery, {
      stage: 'release',
      dealId: f.dealId,
      profile: 'demo',
      boundValue: releaseBoundValue(f.sides.B.release!.msg),
      identity: { zkSalt32: f.sides.A.salt, commitment: bytesToHex(f.alice.commitment) },
      faceMatchOptional: true,
    });
    expect(r).toEqual({ ok: false, code: 'IDENTIFIER_MISMATCH' });
  });

  it('P2.9-04 a release proof with another scope or another bound presenceMsg is rejected; the escrow stays', () => {
    expect(attacks.scopeChanged).toBe('not verified');
    expect(attacks.bindChanged).toBe('not verified');
    expect(attacks.scopeCheck).toBe('WRONG_SCOPE');
    expect(attacks.bindCheck).toBe('BOUND_VALUE_MISMATCH');
    expect(attacks.escrowStays).toBe(true);
  });

  it('a release proof bound to an old ledger hash fails; recorded as a failed check, the gate refuses', () => {
    expect(attacks.oldHashCheck).toBe('BOUND_VALUE_MISMATCH');
    expect(attacks.falseBoundGate).toEqual(['PASSPORT_A_OK']);
  });

  it('P2.9-03 and P2.9-09 the same records and proofs fail in the production profile (DEVMODE_REFUSED)', async () => {
    const refused = await outcome(prover.productionAdapter.verify(portRequest(f.sides.A.release!.set)));
    expect(refused).toBe('refused ZK_REFUSED DEVMODE_REFUSED');
    const prod = checkRelease({ ...f.input, profile: 'production' });
    expect(failing(prod)).toEqual(['PASSPORT_A_OK', 'PASSPORT_B_OK', 'ONBOARDING_OK']);
    for (const x of prod.filter((y) => !y.ok)) expect(x.detail).toMatch(/DEVMODE_REFUSED$/);
    for (const s of ['A', 'B'] as const) {
      const trust = trustRecordOf(f.sides[s].release!.verification);
      expect(trust).toMatchObject({ chain_id: 11155111, identifier_type: 'NON_SALTED_MOCK', dev_mode: true });
      expect(checkTrustRecord(trust, 'production')).toEqual({ ok: false, code: 'DEVMODE_REFUSED' });
      expect(checkTrustRecord({ ...trust, dev_mode: false }, 'production')).toEqual({
        ok: false,
        code: 'SEPOLIA_REFUSED',
      });
      expect(checkTrustRecord({ ...trust, dev_mode: false, chain_id: 1 }, 'production')).toEqual({
        ok: false,
        code: 'MOCK_IDENTIFIER_REFUSED',
      });
      expect(checkTrustRecord(trust, 'demo')).toEqual({ ok: true });
    }
  });

  it('P2.9-02 the replay adapter throws for a proof with no recorded result and never answers valid', async () => {
    const recorded = ['alice-onboarding', 'alice-release'].map(
      (n) => JSON.parse(readFileSync(new URL(`${n}.json`, RECORDED), 'utf8')).verification,
    );
    const replay = replayZkVerifier(recorded);
    await expect(replay.verify(portRequest(f.sides.A.release!.set))).rejects.toThrow('ZK_RESULT_MISSING');
    await expect(replay.verify(portRequest(f.sides.B.onboarding!.set))).rejects.toThrow('ZK_RESULT_MISSING');
  });

  it('P2.9-07 the ledger memos and the escrow contain no passport data', () => {
    const forbidden = new Set<string>();
    // Values shorter than five characters are skipped (a three-letter name appears by chance inside a base58 address
    // or a hex blob). Plain text is matched case-sensitively; the hex of every value is matched in both cases.
    const add = (s: string) => {
      if (s.length < 5) return;
      forbidden.add(s);
      const h = bytesToHex(utf8ToBytes(s));
      forbidden.add(h);
      forbidden.add(h.toUpperCase());
    };
    for (const s of ['A', 'B'] as const) {
      const side = f.sides[s];
      add(side.identifier as string);
      add(bytesToHex(side.salt));
      const d = side.onboarding!.roleDisclosure;
      for (const v of [d.firstname, d.lastname, d.birthdate, d.nationality]) add(v);
    }
    add('A1111111');
    add('B2222222');
    const text = ledger.text;
    expect(text.length).toBeGreaterThan(10_000);
    for (const s of forbidden) expect(text.includes(s), `passport value on the ledger: ${s}`).toBe(false);
    expect([...ledger.memoTypes].sort()).toEqual(['legx/contract-sigs/v1', 'legx/release-gate/v1']);
    // C_side is inside the sealed deal data only; the ledger holds just the seal hash (Domain)
    for (const c of [f.alice.commitment, f.bob.commitment])
      expect([bytesToHex(c), bytesToHex(c).toUpperCase()].some((h) => text.includes(h))).toBe(false);
  });

  it("the salt and the disclosed facts open for the client's own lawyer only", async () => {
    for (const s of ['A', 'B'] as const) {
      const o = await openBoxes(f, s);
      expect(o.salt).toEqual({ ok: true, zkSalt32: f.sides[s].salt });
      expect(o.disclosure.ok && o.disclosure.facts.firstname).toBe(s === 'A' ? 'ALICE' : 'BOB');
      expect(o.other).toEqual({ ok: false, code: 'OPEN_FAILED' });
    }
  });

  it('P2.9-10 switching the identity method mid-deal needs a 4-of-4 seal update', () => {
    const chipC = bytesToHex(randomBytes(32));
    const presented = { method: 'nfc-chip', commitment: chipC } as const;
    expect(checkAgainstSeal(f.data, 'A', presented)).toEqual({ ok: false, code: 'METHOD_MISMATCH' });
    expect(() => identityChangePlan(f.data, 'A', presented)).toThrow(); // policy "zk" does not allow the chip
    const mixed = { ...f.data, identityPolicy: 'zk-or-chip' as const };
    const plan = identityChangePlan(mixed, 'A', presented);
    expect(plan.signers).toEqual(['A', 'LA', 'B', 'LB']);
    expect(plan.threshold).toBe(4);
    expect(plan.newSeal).not.toBe(plan.oldSeal);
    expect(identityChangeOutcome({ A: 'signed', LA: 'signed', B: 'signed', LB: 'refused' }).state).toBe('refused');
    expect(identityChangeOutcome({ A: 'signed', LA: 'signed', B: 'signed', LB: 'signed' }).state).toBe('applied');
  });
});

describe('P2.9-08 two parties use the same mock passport', () => {
  it('the gate fails only IDS_DISTINCT (equal identifiers, different salts)', async () => {
    const f = await runZkFlow(chain, {
      prover,
      policy: 'zk',
      methods: { A: 'zkpassport', B: 'zkpassport' },
      persons: { A: MOCK_ALICE, B: MOCK_ALICE },
      through: 'gate',
    });
    expect(f.sides.A.identifier).toBe(f.sides.B.identifier);
    expect(f.data.commitmentA).not.toBe(f.data.commitmentB);
    expect(f.findings.filter((x) => !x.ok)).toEqual([
      { code: 'IDS_DISTINCT', level: 'block', ok: false, detail: 'IDENTIFIERS_EQUAL' },
    ]);
  });
});

describe('P2.9-06 identity policy "zk-or-chip" with one mock passport and one chip fixture', () => {
  it('the flow completes; each attestation shows its own method', async () => {
    const f = await runZkFlow(chain, {
      prover,
      policy: 'zk-or-chip',
      methods: { A: 'zkpassport', B: 'nfc-chip' },
      through: 'close',
    });
    expect(f.c.log.filter((l) => l.result !== 'tesSUCCESS')).toEqual([]);
    expect(f.findings.every((x) => x.ok)).toBe(true);
    expect(f.findings.filter((x) => x.level === 'block').map((x) => x.code)).toEqual([...GATE_CODES]);
    expect(f.findings.filter((x) => x.level === 'warn').map((x) => x.detail)).toEqual(['A']); // only the zkpassport side
    for (const [s, method] of [
      ['A', 'zkpassport'],
      ['B', 'nfc-chip'],
    ] as const) {
      expect(payloadOf(f.input.records.onboarding[s] as Uint8Array).method).toBe(method);
      expect(payloadOf(f.input.records.passport[s] as Uint8Array).method).toBe(method);
    }
    expect(f.input.records.zkProof.B).toBeUndefined();
    expect(f.balances && f.balances.bobAfter > f.balances.bobBefore).toBe(true);
  });
});

describe('P2.9-01 every recorded proof, through the real SDK in devMode against Sepolia (verifierMode local)', () => {
  it('each verdict equals the recorded verdict and the recorded trust record', async () => {
    const files = readdirSync(RECORDED).filter((n) => n.endsWith('.json'));
    expect(files.length).toBeGreaterThanOrEqual(7);
    const real = Date;
    try {
      for (const name of files) {
        const rec = JSON.parse(readFileSync(new URL(name, RECORDED), 'utf8'));
        // the SDK's expiry check counts whole days from the clock: replay each set at its recording day
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(new real(rec.recordedAt));
        const live = await prover.adapter.verifyDetailed(portRequest(rec)).then(
          (v) => v.verification,
          (e: { reason?: string }) => {
            // the services adapter never verifies a proof made under another domain (DESIGN 6.10)
            expect([name, rec.request.domain, e.reason]).toEqual([name, 'other.app', 'WRONG_DOMAIN']);
            return undefined;
          },
        );
        vi.useRealTimers();
        const recorded = rec.verification;
        if (rec.request.domain !== 'legx.app') {
          expect(live, name).toBeUndefined();
          continue;
        }
        expect(live?.verified ?? false, name).toBe(recorded.verified);
        if (!recorded.verified) continue;
        expect(live?.uniqueIdentifier, name).toBe(recorded.uniqueIdentifier);
        const strip = (t: Record<string, unknown>) => {
          const o = { ...t };
          for (const k of NETWORK_FIELDS) delete o[k];
          return o;
        };
        expect(strip(live?.trust as never), name).toEqual(strip(recorded.trust));
      }
    } finally {
      vi.useRealTimers();
    }
  });
});
