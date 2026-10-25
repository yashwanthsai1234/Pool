// Fuzz targets for @legx/zk and the ZK records: the recorded result (ZkVerification), the verifier request, the trust
// record (P5.2-04), and the replay verifier. Seeds are the recorded mock-passport sets in packages/zk/fixtures/sets.
import { ZkVerification, ZkVerifyRequest } from '@legx/contracts/records';
import { checkZkResult, trustRecordOf } from '@legx/core/zkIdentity';
import { replayZkVerifier } from '@legx/zk/port';
import { proofSetBytes } from '@legx/zk/verify';
import { TRUST } from '../src/fixtures.ts';
import { assert, assertEqual, attempt, attemptAsync, jsonOf, type Target, toBytes } from '../src/harness.ts';
import { listDir, readJson } from '../src/seeds.ts';
import { checkTrust } from './core.ts';

interface RecordedSet {
  request: {
    stage: 'onboarding' | 'release';
    domain: string;
    scope: string;
    devMode: boolean;
    originalQuery: Record<string, unknown>;
  };
  proofs: { proof: string }[];
  queryResult: Record<string, unknown>;
  verification: ZkVerification;
}
const sets = () => listDir('zk', 'fixtures', 'sets').map((f) => readJson<RecordedSet>('zk', 'fixtures', 'sets', f));

const trustRecord: Target = {
  name: 'zk-trust-record',
  pkg: 'zk',
  seeds: () => [
    ...sets().map((s) => toBytes(trustRecordOf(s.verification))),
    toBytes(TRUST),
    toBytes({ ...TRUST, chain_id: 11155111 }),
    toBytes({ ...TRUST, identifier_type: 'SALTED_MOCK' }),
    toBytes({ ...TRUST, dev_mode: true }),
  ],
  run(input) {
    checkTrust(jsonOf(input));
  },
};

const EXPECT = (stage: 'onboarding' | 'release') => ({
  stage,
  dealId: '0192f0a0-0000-7000-8000-000000000001',
  boundValue: 'x',
  profile: 'production' as const,
  cancelAfter: 1,
  identity: { zkSalt32: new Uint8Array(32), commitment: '00'.repeat(32) },
});

const result: Target = {
  name: 'zk-result',
  pkg: 'zk',
  seeds: () => [
    ...sets().map((s) => toBytes(s.verification)),
    ...sets().map((s) =>
      toBytes({ ...s, proofs: s.proofs.map((p) => ({ ...p, proof: p.proof.slice(0, 64) })), verification: undefined }),
    ),
  ],
  async run(input) {
    const doc = jsonOf(input);
    const v = ZkVerification.safeParse(doc);
    if (v.success) {
      const again = ZkVerification.safeParse(JSON.parse(JSON.stringify(v.data)));
      assert(again.success, 'ZkVerification round trip');
      if (again.success) assertEqual(again.data, v.data, 'ZkVerification round trip');
      for (const stage of ['onboarding', 'release'] as const) {
        const r = attempt('checkZkResult', () => checkZkResult(v.data, {}, EXPECT(stage)));
        if (r.ok && r.value.ok) {
          assert(v.data.verified && v.data.domain === 'legx.app', 'accepted an unverified or foreign-domain result');
          assert(!v.data.trust.devMode && v.data.trust.chainId !== 11155111, 'production accepted a flagged result');
        }
      }
    }
    // The request: a parsed request is looked up in a replay verifier that has no record, so it must refuse with the
    // typed ZK_RESULT_MISSING and never accept.
    const req = ZkVerifyRequest.safeParse(doc);
    if (req.success) {
      attempt('proofSetBytes', () => proofSetBytes(req.data.proofs as never));
      const r = await attemptAsync(
        'replayZkVerifier',
        () => replayZkVerifier([]).verify(req.data),
        (e) => e instanceof Error && e.message === 'ZK_RESULT_MISSING',
      );
      assert(!r.ok, 'the replay verifier answered with no recording');
    }
  },
};

export const zkTargets: Target[] = [trustRecord, result];
