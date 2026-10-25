// Task 1.17: checks of the recorded ZKPassport results (IMPLEMENTATION T-U-28, T-U-32a/d/e, P1.17-10, -16, -17).
// The results are the mock-passport recordings in packages/zk/fixtures/; core never loads the SDK.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ZkVerification } from '@legx/contracts/records';
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { checkTrustRecord } from '../src/attest.ts';
import { bytesToHex, tupleHash } from '../src/dealcore.ts';
import {
  checkReleaseQuery,
  checkZkResult,
  onboardingBoundValue,
  releaseBoundValue,
  trustRecordOf,
  type ZkExpectation,
  type ZkResultCode,
  zkCheckpointInput,
  zkIdentityCommitment,
  zkScope,
} from '../src/zkIdentity.ts';
import { zkFiles, zkSet } from './helpers/zkFixtures.ts';

const onboarding = zkSet('alice-onboarding');
const release = zkSet('alice-release');
const IN = onboarding.inputs;
const SALT = new Uint8Array(32).fill(0x61);
const N = onboarding.verification.uniqueIdentifier as string;
const C = bytesToHex(zkIdentityCommitment(SALT, N));

const presence = (dealSeal: string, ledgerHash = IN.ledgerHash) =>
  tupleHash('legx/passport-presence/v1', [
    hexToBytes(dealSeal),
    utf8ToBytes('A'),
    hexToBytes(ledgerHash),
    hexToBytes(IN.lawyerNonce),
  ]);

const ONBOARD: ZkExpectation = {
  stage: 'onboarding',
  dealId: IN.deal1,
  boundValue: onboardingBoundValue(hexToBytes(IN.contractRoot), hexToBytes(IN.slotPub)),
  profile: 'demo',
  cancelAfter: IN.cancelAfter,
};
// The headless prover cannot make a face match (no app attestation), so the recorded release has none and the
// expectation turns it off; the face match rule itself is tested below.
const RELEASE: ZkExpectation = {
  stage: 'release',
  dealId: IN.deal1,
  boundValue: releaseBoundValue(presence(IN.dealSeal1)),
  profile: 'demo',
  identity: { zkSalt32: SALT, commitment: C },
  faceMatchOptional: true,
};

const check = (
  s: { verification: ZkVerification; request: { originalQuery: Record<string, unknown> } },
  x: ZkExpectation,
) => checkZkResult(s.verification, s.request.originalQuery, x);
const withResult = (s: typeof release, r: Partial<ZkVerification>, t: Partial<ZkVerification['trust']> = {}) => ({
  ...s,
  verification: { ...s.verification, ...r, trust: { ...s.verification.trust, ...t } },
});
const code = (r: ReturnType<typeof checkZkResult>) => (r.ok ? 'ok' : r.code);

describe('T-U-28a a good onboarding and release pair', () => {
  it('both pass with the same identifier, and C_side from that identifier equals the sealed value', () => {
    const a = check(onboarding, ONBOARD);
    const b = check(release, RELEASE);
    expect(a).toEqual({ ok: true, identifier: N });
    expect(b).toEqual({ ok: true, identifier: N });
    expect(bytesToHex(zkIdentityCommitment(SALT, (b as { identifier: string }).identifier))).toBe(C);
  });

  it('the recorded bound values are the ones our recipes give', () => {
    expect(onboarding.verification.committedInputs.custom_data).toBe(ONBOARD.boundValue);
    expect(release.verification.committedInputs.custom_data).toBe(RELEASE.boundValue);
  });
});

describe('T-U-28b one failure per reason, each with exactly its own code', () => {
  const production = (t: Partial<ZkVerification['trust']>, type: ZkVerification['uniqueIdentifierType']) =>
    code(check(withResult(release, { uniqueIdentifierType: type }, t), { ...RELEASE, profile: 'production' }));
  const cases: [ZkResultCode, () => string][] = [
    ['WRONG_SCOPE', () => code(check(release, { ...RELEASE, dealId: IN.deal2 }))],
    ['WRONG_DOMAIN', () => code(check(zkSet('alice-other-domain'), RELEASE))],
    [
      'BOUND_VALUE_MISMATCH',
      () => code(check(release, { ...RELEASE, boundValue: releaseBoundValue(presence(IN.dealSeal2)) })),
    ],
    [
      'BOUND_TOO_LONG',
      () => {
        const long = 'a'.repeat(507);
        const s = withResult(release, { committedInputs: { custom_data: long } });
        return code(
          check(
            { ...s, request: { originalQuery: { bind: { custom_data: long } } } },
            { ...RELEASE, boundValue: long },
          ),
        );
      },
    ],
    ['IDENTIFIER_MISMATCH', () => code(check(zkSet('bob-release'), RELEASE))],
    ['DOCUMENT_EXPIRED', () => code(check(zkSet('expired'), RELEASE))],
    ['EXPIRY_TOO_EARLY', () => code(check(onboarding, { ...ONBOARD, cancelAfter: IN.cancelAfter + 1 }))],
    ['FACE_MATCH_FAILED', () => code(check(zkSet('alice-release-facematch'), RELEASE))],
    ['DEVMODE_REFUSED', () => production({ chainId: 1, devMode: true }, 'NON_SALTED')],
    ['SEPOLIA_REFUSED', () => production({ devMode: false }, 'NON_SALTED')],
    ['MOCK_IDENTIFIER_REFUSED', () => production({ chainId: 1, devMode: false }, 'NON_SALTED_MOCK')],
    [
      'QUERY_ERRORS',
      () => code(check(withResult(release, { queryResultErrors: { age: { gte: 'Age is not >= 18' } } }), RELEASE)),
    ],
    ['PROOF_NOT_VERIFIED', () => code(check(withResult(release, { verified: false }), RELEASE))],
  ];
  it.each(cases)('%s', (expected, run) => expect(run()).toBe(expected));

  it('a missing face match on release fails unless the deal data turns it off', () => {
    expect(code(check(release, { ...RELEASE, faceMatchOptional: false }))).toBe('FACE_MATCH_FAILED');
  });

  it('the same recordings (Sepolia, mock identifier, devMode) are refused in the production profile', () => {
    expect(code(check(release, { ...RELEASE, profile: 'production' }))).toBe('DEVMODE_REFUSED');
    expect(code(check(onboarding, { ...ONBOARD, profile: 'production' }))).toBe('DEVMODE_REFUSED');
  });

  it('replay: a release result from deal X presented in deal Y fails WRONG_SCOPE', () => {
    expect(code(check(zkSet('alice-deal2'), RELEASE))).toBe('WRONG_SCOPE');
  });

  it('replay inside a deal: a release result for an old ledger hash fails BOUND_VALUE_MISMATCH', () => {
    const fresh = releaseBoundValue(presence(IN.dealSeal1, '77'.repeat(32)));
    expect(code(check(release, { ...RELEASE, boundValue: fresh }))).toBe('BOUND_VALUE_MISMATCH');
  });

  it('a bound value in the stored query that differs from the committed one fails BOUND_VALUE_MISMATCH', () => {
    const s = {
      ...release,
      request: { originalQuery: { ...release.request.originalQuery, bind: { custom_data: 'ab' } } },
    };
    expect(code(check(s, RELEASE))).toBe('BOUND_VALUE_MISMATCH');
  });

  it('a missing result is ZK_RESULT_MISSING; a verified result without an identifier is ZK_RECORD_INCOMPLETE', () => {
    expect(code(checkZkResult(undefined, release.request.originalQuery, RELEASE))).toBe('ZK_RESULT_MISSING');
    expect(code(checkZkResult(release.verification, undefined, RELEASE))).toBe('ZK_RESULT_MISSING');
    expect(code(check(withResult(release, { uniqueIdentifier: null }), RELEASE))).toBe('ZK_RECORD_INCOMPLETE');
  });

  it('a stage without its expectation is a programming error', () => {
    expect(() => check(onboarding, { ...ONBOARD, cancelAfter: undefined })).toThrow(/cancelAfter/);
    expect(() => check(release, { ...RELEASE, identity: undefined })).toThrow(/identity/);
  });
});

describe('EXPIRY_TOO_EARLY boundary (DESIGN 6.10: the document must not expire before CancelAfter + 30 days)', () => {
  // gt("expiry_date", X) proves expiry > X, so the tightest bound a document expiring at E can prove is E - 1 s.
  const CA = IN.cancelAfter;
  const DAYS30 = 30 * 86400;
  const withBound = (x: number) => ({
    ...onboarding,
    request: {
      originalQuery: { ...onboarding.request.originalQuery, expiry_date: { gt: new Date(x * 1000).toISOString() } },
    },
  });
  it('a document expiring at CancelAfter + 30 days + 1 s passes; one expiring exactly at CancelAfter + 30 days fails', () => {
    expect(code(check(withBound(CA + DAYS30 + 1 - 1), ONBOARD))).toBe('ok');
    expect(code(check(withBound(CA + DAYS30 - 1), ONBOARD))).toBe('EXPIRY_TOO_EARLY');
  });
  it('a missing or unreadable expiry condition fails', () => {
    const { expiry_date: _dropped, ...noExpiry } = onboarding.request.originalQuery;
    expect(code(check({ ...onboarding, request: { originalQuery: noExpiry } }, ONBOARD))).toBe('EXPIRY_TOO_EARLY');
    expect(
      code(check({ ...onboarding, request: { originalQuery: { ...noExpiry, expiry_date: { gt: 'soon' } } } }, ONBOARD)),
    ).toBe('EXPIRY_TOO_EARLY');
  });
});

describe('property: a good synthetic result passes, and one wrong field fails with exactly one code', () => {
  const arb = fc.record({
    dealId: fc.uuid({ version: 7 }),
    bound: fc.stringMatching(/^[0-9a-f]{64}$/),
    id: fc.stringMatching(/^[1-9][0-9]{0,76}$/),
    salt: fc.uint8Array({ minLength: 32, maxLength: 32 }),
  });
  const build = (a: { dealId: string; bound: string; id: string; salt: Uint8Array }) => {
    const verification: ZkVerification = {
      ...release.verification,
      scope: zkScope(a.dealId),
      uniqueIdentifier: a.id,
      committedInputs: { custom_data: a.bound },
    };
    const x: ZkExpectation = {
      ...RELEASE,
      dealId: a.dealId,
      boundValue: a.bound,
      identity: { zkSalt32: a.salt, commitment: bytesToHex(zkIdentityCommitment(a.salt, a.id)) },
    };
    return { verification, query: { bind: { custom_data: a.bound } }, x };
  };
  it('holds for random scopes, bound values and identifiers', () => {
    fc.assert(
      fc.property(arb, fc.integer({ min: 0, max: 3 }), (a, which) => {
        const { verification, query, x } = build(a);
        expect(checkZkResult(verification, query, x)).toEqual({ ok: true, identifier: a.id });
        const wrong: [Partial<ZkVerification>, ZkResultCode][] = [
          [{ scope: `${verification.scope}x` }, 'WRONG_SCOPE'],
          [{ domain: 'legx.app.' }, 'WRONG_DOMAIN'],
          [{ committedInputs: { custom_data: `${a.bound.slice(1)}0` } }, 'BOUND_VALUE_MISMATCH'],
          [{ uniqueIdentifier: `${a.id}1` }, 'IDENTIFIER_MISMATCH'],
        ];
        const [mutation, expected] = wrong[which] as [Partial<ZkVerification>, ZkResultCode];
        expect(checkZkResult({ ...verification, ...mutation }, query, x)).toEqual({ ok: false, code: expected });
      }),
    );
  });
});

describe('P1.17-10 an expired mock passport', () => {
  it('the recorded result is not verified, has query errors, and checks as DOCUMENT_EXPIRED', () => {
    const expired = zkSet('expired').verification;
    expect(expired.verified).toBe(false);
    expect(Object.keys(expired.queryResultErrors).length).toBeGreaterThan(0);
    expect(code(checkZkResult(expired, release.request.originalQuery, RELEASE))).toBe('DOCUMENT_EXPIRED');
  });
});

describe('P1.17-16 the release request against the onboarding one', () => {
  const q = (s: { request: { originalQuery: Record<string, unknown> } }) => s.request.originalQuery;
  it('the recorded release request repeats the onboarding facts; the strict face match is required by default', () => {
    expect(checkReleaseQuery(q(onboarding), q(zkSet('alice-release-facematch')))).toEqual({ ok: true });
    expect(checkReleaseQuery(q(onboarding), q(release))).toEqual({ ok: false, code: 'FACE_MATCH_FAILED' });
    expect(checkReleaseQuery(q(onboarding), q(release), true)).toEqual({ ok: true });
  });
  it('different facts fail', () => {
    const older = { ...q(zkSet('alice-release-facematch')), age: { gte: 21 } };
    expect(checkReleaseQuery(q(onboarding), older)).toEqual({ ok: false, code: 'RELEASE_FACTS_DIFFER' });
  });
});

describe('P1.17-17 the scope is not in the SDK result; the record holds the one we requested', () => {
  it('a record with no stored scope is ZK_RECORD_INCOMPLETE; another scope is WRONG_SCOPE', () => {
    expect(code(check(withResult(release, { scope: '' }), RELEASE))).toBe('ZK_RECORD_INCOMPLETE');
    expect(code(check(withResult(release, { scope: zkScope(IN.deal2) }), RELEASE))).toBe('WRONG_SCOPE');
  });
});

describe('T-U-32a the trust record of every recorded verified result', () => {
  const verified = ['alice-onboarding', 'alice-release', 'alice-deal2', 'bob-release'].map(zkSet);
  const NINE = [
    'chain_id',
    'block_number',
    'block_hash',
    'registry_address',
    'root',
    'circuit_manifest_version',
    'vkey_hashes',
    'identifier_type',
    'dev_mode',
  ];
  it('holds all nine fields', () => {
    for (const s of verified) {
      const t = trustRecordOf(s.verification);
      expect(Object.keys(t).sort()).toEqual([...NINE].sort());
      for (const k of NINE) expect(t[k as keyof typeof t], k).not.toBeNull();
    }
  });
  const missing: [string, Partial<ZkVerification['trust']> | null][] = [
    ['chainId', { chainId: undefined as never }],
    ['blockNumber', { blockNumber: undefined as never }],
    ['blockHash', { blockHash: '' as never }],
    ['registryAddress', { registryAddress: undefined as never }],
    ['root', { root: '0x12' as never }],
    ['circuitManifestVersion', { circuitManifestVersion: '' }],
    ['vkeyHashes', { vkeyHashes: [] as never }],
    ['devMode', { devMode: undefined as never }],
    ['identifierType', null],
  ];
  it.each(missing)('without %s: TRUST_RECORD_INCOMPLETE', (_name, t) => {
    const s = t ? withResult(release, {}, t) : withResult(release, { uniqueIdentifierType: null });
    expect(code(check(s, RELEASE))).toBe('TRUST_RECORD_INCOMPLETE');
  });
});

describe('T-U-32d the recorded roots and files go into the next evidence checkpoint input', () => {
  const files = zkFiles();
  it('the input holds the trust record and every recorded file; changing a file changes its leaf and the root', () => {
    const base = zkCheckpointInput(release.verification.trust, files);
    expect(base.leaves.map((l) => l.name)).toEqual(['trust', ...[...files.keys()].map((k) => `file/${k}`)].sort());
    const [name, bytes] = [...files][0] as [string, Uint8Array];
    const changed = new Map(files).set(
      name,
      Uint8Array.from(bytes, (b, i) => (i === 10 ? b ^ 1 : b)),
    );
    const after = zkCheckpointInput(release.verification.trust, changed);
    expect(after.root).not.toBe(base.root);
    expect(after.leaves.filter((l, i) => l.sha256 !== base.leaves[i]?.sha256).map((l) => l.name)).toEqual([
      `file/${name}`,
    ]);
  });
  it('a changed root in the trust record changes the checkpoint root', () => {
    const t = { ...release.verification.trust, root: `0x${'00'.repeat(32)}` as never };
    expect(zkCheckpointInput(t, files).root).not.toBe(zkCheckpointInput(release.verification.trust, files).root);
  });
  it('the input is independent of file order', () => {
    const reversed = new Map([...files].reverse());
    expect(zkCheckpointInput(release.verification.trust, reversed)).toEqual(
      zkCheckpointInput(release.verification.trust, files),
    );
  });
});

describe('T-U-32e production refusals on the recorded trust records', () => {
  it('every recorded verified result is refused in production and accepted in the demo profile', () => {
    const dir = join(import.meta.dirname, '../../zk/fixtures/sets');
    const results = readdirSync(dir).map(
      (f) => JSON.parse(readFileSync(join(dir, f), 'utf8')).verification as ZkVerification,
    );
    for (const v of results.filter((r) => r.verified)) {
      expect(checkTrustRecord(trustRecordOf(v), 'production')).toEqual({ ok: false, code: 'DEVMODE_REFUSED' });
      expect(checkTrustRecord(trustRecordOf(v), 'demo')).toEqual({ ok: true });
    }
  });
});

describe('T-U-28c the real (non-mock) identifier formula', () => {
  it.todo(
    'one recorded real-passport run: same passport and scope twice, and a second scope (needs a phone and a passport)',
  );
});
