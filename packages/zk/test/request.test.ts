// Task 1.17: ZKPassport request builders (DESIGN 6.10; IMPLEMENTATION P1.17-08, -15, -16).
// The builders run against the real SDK 0.19.2 query builder (`createQuery()`, no bridge, no network), which pins
// the [CHECK] API names: gt("expiry_date", date) and facematch("strict").
import { onboardingBoundValue, releaseBoundValue } from '@legx/core/zkIdentity';
import { describe, expect, it } from 'vitest';
import {
  bindCustomData,
  offlineQuery,
  onboardingQuery,
  releaseQuery,
  requestConfig,
  ZkRequestError,
} from '../src/request.ts';

const DEAL = '0192f0a0-0000-7000-8000-000000000001';
const ROOT = new Uint8Array(32).fill(0x22);
const SLOT = new Uint8Array([0xed, ...new Uint8Array(32).fill(0x33)]);
const PRESENCE = new Uint8Array(32).fill(0x44);
const CANCEL_AFTER = Date.UTC(2030, 0, 1) / 1000;
const FACTS = { minAge: 18 };
const builder = () => offlineQuery();

const code = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    return e instanceof ZkRequestError ? e.code : String(e);
  }
  return 'no error';
};

describe('P1.17-15 the domain is the config constant legx.app', () => {
  it('ignores the page origin; the config snapshot shows the domain and the deal scope', () => {
    expect(requestConfig({ dealId: DEAL, devMode: false, pageOrigin: 'https://abc123.trycloudflare.com' })).toEqual({
      domain: 'legx.app',
      scope: `legx/v1/${DEAL}`,
      devMode: false,
      verifierMode: 'local',
      validity: 86400,
    });
  });

  it('refuses an empty or a different domain with WRONG_DOMAIN', () => {
    for (const domain of ['', 'abc123.trycloudflare.com', 'https://legx.app', 'LEGX.APP', 'legx.app.'])
      expect(code(() => requestConfig({ dealId: DEAL, devMode: false, domain }))).toBe('WRONG_DOMAIN');
    expect(requestConfig({ dealId: DEAL, devMode: true, domain: 'legx.app' }).domain).toBe('legx.app');
  });
});

describe('onboarding request (DESIGN 6.10)', () => {
  it('asks for age, the four disclosed facts, an expiry after CancelAfter + 30 days, and binds contractRoot and slotPub', () => {
    const { query } = onboardingQuery(builder(), {
      facts: FACTS,
      contractRoot: ROOT,
      slotPub: SLOT,
      cancelAfter: CANCEL_AFTER,
    }).done();
    expect(JSON.parse(JSON.stringify(query))).toEqual({
      age: { gte: 18 },
      firstname: { disclose: true },
      lastname: { disclose: true },
      birthdate: { disclose: true },
      nationality: { disclose: true },
      expiry_date: { gt: '2030-01-31T00:00:00.000Z' },
      bind: { custom_data: onboardingBoundValue(ROOT, SLOT) },
    });
  });

  it('adds a nationality condition when the contract asks for one', () => {
    const { query } = onboardingQuery(builder(), {
      facts: { minAge: 21, nationalityIn: ['FRA', 'DEU'] },
      contractRoot: ROOT,
      slotPub: SLOT,
      cancelAfter: CANCEL_AFTER,
    }).done();
    expect(query.age).toEqual({ gte: 21 });
    expect(query.nationality).toEqual({ in: ['FRA', 'DEU'], disclose: true });
  });
});

describe('P1.17-16 release request', () => {
  it('repeats the onboarding facts, turns on the strict face match by default and binds presenceMsg', () => {
    const facts = { minAge: 21, nationalityIn: ['FRA'] };
    const { query } = releaseQuery(builder(), { facts, presenceMsg: PRESENCE }).done();
    expect(JSON.parse(JSON.stringify(query))).toEqual({
      age: { gte: 21 },
      nationality: { in: ['FRA'] },
      facematch: { mode: 'strict' },
      bind: { custom_data: releaseBoundValue(PRESENCE) },
    });
  });

  it('refuses the face match off unless the deal data allows it (O12)', () => {
    expect(code(() => releaseQuery(builder(), { facts: FACTS, presenceMsg: PRESENCE, faceMatch: false }))).toBe(
      'FACE_MATCH_REQUIRED',
    );
    const { query } = releaseQuery(builder(), {
      facts: FACTS,
      presenceMsg: PRESENCE,
      faceMatch: false,
      dealAllowsNoFaceMatch: true,
    }).done();
    expect(query.facematch).toBeUndefined();
  });
});

describe('P1.17-08 the bound length is checked before a QR code exists', () => {
  it('an over-long bound value never reaches the builder; 506 bytes do', () => {
    const refusing = { bind: () => expect.fail('bind must not be called') } as never;
    expect(code(() => bindCustomData(refusing, 'a'.repeat(507)))).toBe('BOUND_TOO_LONG');
    expect(bindCustomData(builder(), 'a'.repeat(506)).done().query.bind).toEqual({ custom_data: 'a'.repeat(506) });
  });
});
