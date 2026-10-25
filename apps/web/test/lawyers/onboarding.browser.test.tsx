// OD-32: the client's own lawyer verifies the onboarding proof in the console, opens the disclosure box with its own key, and only
// then signs `identity.onboarded`. The verdict is core's `checkZkResult`; the attestation passes core's `verifyOnboarding` before it
// is recorded. Anything that fails signs and records nothing.
import type { ZkVerification, ZkVerifyRequest } from '@legx/contracts/records';
import { bytesToHex, hexToBytes } from '@legx/core/dealcore';
import { PACKAGE_SUITES, toBase64, XWING_SUITE } from '@legx/core/pq';
import {
  onboardingBoundValue,
  openDisclosure,
  sealDisclosure,
  zkIdentityCommitment,
  zkScope,
} from '@legx/core/zkIdentity';
import { describe, expect, it } from 'vitest';
import aliceOnboarding from '../../../../packages/zk/fixtures/sets/alice-onboarding.json';
import { createLawyerConsole } from '../../src/routes/lawyers/-console/index.ts';
import { DEAL_ID, makeConsole } from './harness.ts';

const xwing = PACKAGE_SUITES[XWING_SUITE] as NonNullable<(typeof PACKAGE_SUITES)[string]>;
const SALT = new Uint8Array(32).fill(0x61);
const FACTS = { firstname: 'Ada', lastname: 'Lovelace', birthdate: '1815-12-10', nationality: 'GBR' };
const CANCEL_AFTER = 1_893_456_000;
const fixture = aliceOnboarding.verification as unknown as ZkVerification;

async function setup(
  over: { verdict?: Error; unverified?: boolean; salt?: Uint8Array; secret?: 'other'; reverify?: boolean } = {},
) {
  const base = await makeConsole({ role: 'LA' });
  const data = base.deps.deal.data;
  const lawyer = await xwing.keygen();
  const other = await xwing.keygen();
  const bound = onboardingBoundValue(hexToBytes(data.contractRoot), hexToBytes(data.xPubA));
  const verification = {
    ...fixture,
    scope: zkScope(DEAL_ID),
    committedInputs: { custom_data: bound },
  } as unknown as ZkVerification;
  const sealed = {
    ...data,
    commitmentA: bytesToHex(zkIdentityCommitment(SALT, verification.uniqueIdentifier as string)),
  };
  const verdict = over.verdict ?? (over.unverified ? { ...verification, verified: false } : verification);
  const deps = {
    ...base.deps,
    deal: { ...base.deps.deal, profile: 'demo' as const, data: sealed as typeof data },
    identity: {
      ...base.deps.identity,
      salt: async () => over.salt ?? SALT,
      zkVerify: async () => {
        if (verdict instanceof Error) throw verdict;
        return verdict;
      },
    },
    onboarding: {
      openDisclosure: (box: Parameters<typeof openDisclosure>[0], dealId: string, side: string) =>
        openDisclosure(box, (over.secret === 'other' ? other : lawyer).secretKey, dealId, side),
    },
  };
  const request = {
    stage: 'onboarding',
    domain: 'legx.app',
    scope: zkScope(DEAL_ID),
    devMode: true,
    proofs: [],
    originalQuery: {
      bind: { custom_data: bound },
      expiry_date: { gt: new Date((CANCEL_AFTER + 31 * 86400) * 1000).toISOString() },
    },
    queryResult: {},
  } as unknown as ZkVerifyRequest;
  const run = {
    request,
    box: await sealDisclosure(FACTS, lawyer.publicKey, DEAL_ID, 'A'),
    cancelAfter: CANCEL_AFTER,
    ...(over.reverify === undefined ? {} : { reverify: async () => over.reverify as boolean }),
  };
  return { c: createLawyerConsole(deps as never), deps, run, spies: base.spies };
}

describe('OD-32 onboarding in the lawyer console', () => {
  it('verifies, opens the box, signs identity.onboarded and records it once', async () => {
    const s = await setup();
    const bytes = await s.c.onboarding.verifyAndSign(s.run);
    expect(s.spies.appended).toHaveLength(1);
    const event = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(atob(JSON.parse(new TextDecoder().decode(s.spies.appended[0])).payload), (ch) =>
          ch.charCodeAt(0),
        ),
      ),
    ).predicate;
    expect(event.kind).toBe('identity.onboarded');
    expect(event.data).toEqual({ side: 'A', attestation: toBase64(bytes) });
    const att = JSON.parse(new TextDecoder().decode(bytes));
    expect(att.payloadType).toBe('application/vnd.legx.attest+json;v=1');
    expect(att.signatures).toHaveLength(2);
  });

  it.each([
    ['the proof does not verify', { unverified: true }, 'PROOF_NOT_VERIFIED'],
    ['the server cannot check', { verdict: new Error('503') }, 'CANNOT_CHECK_NOW'],
    ['the box is for another lawyer', { secret: 'other' as const }, 'BOX_OPEN_FAILED'],
    ['the local re-verification fails', { reverify: false }, 'LOCAL_REVERIFY_FAILED'],
    ['the person is not the one the seal commits to', { salt: new Uint8Array(32).fill(1) }, 'COMMITMENT_MISMATCH'],
  ])('signs and records nothing when %s', async (_n, over, code) => {
    const s = await setup(over);
    await expect(s.c.onboarding.verifyAndSign(s.run)).rejects.toMatchObject({ code });
    expect(s.spies.appended).toHaveLength(0);
  });

  it('refuses when the console has no disclosure key', async () => {
    const s = await setup();
    const c = createLawyerConsole({ ...s.deps, onboarding: undefined } as never);
    await expect(c.onboarding.verifyAndSign(s.run)).rejects.toMatchObject({ code: 'NO_DISCLOSURE_KEY' });
  });
});
