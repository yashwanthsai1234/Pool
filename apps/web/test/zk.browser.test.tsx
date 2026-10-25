// Task 4.8: the ZKPassport flow in the browser (P4.8-*). The SDK is a scripted double (callbacks in a set order);
// the server's ZK route (501 today) is answered by MSW and every request to it is logged.
import { ApiAuth } from '@legx/contracts/api';
import { ZK_DOMAIN, type ZkVerification } from '@legx/contracts/records';
import { bytesToHex } from '@legx/core/dealcore';
import { PACKAGE_SUITES, XWING_SUITE } from '@legx/core/pq';
import { onboardingBoundValue, openDisclosure, openSalt, zkIdentityCommitment } from '@legx/core/zkIdentity';
import jsQR from 'jsqr';
import { HttpResponse, http } from 'msw';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import aliceOnboarding from '../../../packages/zk/fixtures/sets/alice-onboarding.json';
import aliceRelease from '../../../packages/zk/fixtures/sets/alice-release.json';
import { createApiClient } from '../src/lib/api.ts';
import { API_BASE } from '../src/lib/paths.ts';
import { startMocks } from '../src/mocks/browser.ts';
import { examplesOf } from '../src/mocks/examples.ts';
import { restHandlers } from '../src/mocks/handlers.ts';
import { type ZkState, zkReducer } from '../src/zk/flow.ts';
import { verifyOnboardingInConsole } from '../src/zk/onboarding.ts';
import { LawyerNonces } from '../src/zk/policy.ts';
import { buildZkRequest, type OnboardingInput, type ReleaseInput } from '../src/zk/request.ts';
import { replayConfig, reverifyInBrowser } from '../src/zk/reverify.ts';
import { scriptedSdk, scriptFromRecording, type ZkOutcome, type ZkScript } from '../src/zk/sdk.ts';
import { PassportProof, QrCode } from '../src/zk/ui.tsx';
import {
  checkForConsole,
  makeSealedSalt,
  sealOnboardingFacts,
  splitDisclosure,
  submissionOf,
  trustRows,
  verifyOnServer,
} from '../src/zk/verify.ts';

const xwing = PACKAGE_SUITES[XWING_SUITE] as NonNullable<(typeof PACKAGE_SUITES)[string]>;
const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
const IN = aliceRelease.inputs;
const SALT = new Uint8Array(32).fill(0x61);
const NOW = 1_800_000_000;
const recordedOutcome = (set: typeof aliceRelease): ZkOutcome => {
  const result = scriptFromRecording(set as never).events.find((e) => e.type === 'result');
  return (result as { outcome: ZkOutcome }).outcome;
};
const facts = { minAge: 18 } as const;
const common = { profile: 'demo', devMode: true, dealId: IN.deal1, facts } as const;
const onboarding = (sdk: ReturnType<typeof scriptedSdk>, extra: Partial<OnboardingInput> = {}): OnboardingInput => ({
  ...common,
  sdk,
  stage: 'onboarding',
  contractRoot: hex(IN.contractRoot),
  slotPub: hex(IN.slotPub),
  cancelAfter: IN.cancelAfter,
  ...extra,
});
const release = (sdk: ReturnType<typeof scriptedSdk>, extra: Partial<ReleaseInput> = {}): ReleaseInput => ({
  ...common,
  sdk,
  stage: 'release',
  side: 'A',
  dealSeal: hex(IN.dealSeal1),
  ledgerHash: hex(IN.ledgerHash),
  ledgerCloseTime: NOW - 60,
  nowLedgerTime: NOW,
  lawyerNonce: hex(IN.lawyerNonce),
  ...extra,
});
const script = (events: ZkScript['events'] = [], url = 'https://zkpassport.id/r?id=1'): ZkScript => ({ url, events });

const logged: { dealId: string; body: unknown }[] = [];
const AUTH = ApiAuth.parse(examplesOf('ApiAuth')[0]);
const client = createApiClient({ signRequest: async () => AUTH });
beforeAll(async () => {
  await startMocks(
    http.post(`*${API_BASE}/deals/:dealId/zk/verify`, async ({ request, params }) => {
      logged.push({ dealId: String(params.dealId), body: await request.json() });
      return HttpResponse.json({ code: 'NOT_IMPLEMENTED', message: 'zk route is 501 until 3.7' }, { status: 501 });
    }),
    ...restHandlers(),
  );
});
afterEach(() => {
  logged.length = 0;
});

describe('P4.8-01, -18 the request', () => {
  it('passes domain legx.app, the deal scope, local verification and exactly the checks the deal needs', async () => {
    let seen: unknown;
    const sdk = scriptedSdk(script(), (settings, calls) => (seen = { settings, calls }));
    const r = await buildZkRequest(onboarding(sdk, { facts: { minAge: 18, nationalityIn: ['DEU'] } }));
    expect(seen).toMatchObject({
      settings: { domain: ZK_DOMAIN, scope: `legx/v1/${IN.deal1}`, devMode: true, verifierMode: 'local' },
    });
    const calls = (seen as { calls: [string, unknown[]][] }).calls;
    expect(calls.map(([n]) => n)).toEqual(['gte', 'in', 'disclose', 'disclose', 'disclose', 'disclose', 'gt', 'bind']);
    expect(calls.at(-1)?.[1]).toEqual(['custom_data', r.boundValue]);
    const gt = calls[6]?.[1] as [string, Date];
    expect(gt[1].getTime() / 1000).toBe(IN.cancelAfter + 30 * 86400);
  });

  it('never takes the domain from the page origin', async () => {
    let seen: { settings: { domain: string } } | undefined;
    await buildZkRequest(onboarding(scriptedSdk(script(), (s) => (seen = { settings: s }))));
    expect(seen?.settings.domain).not.toBe(location.hostname);
    expect(seen?.settings.domain).toBe('legx.app');
  });

  it('a 507-byte bound value is refused by our code and the SDK is never asked', async () => {
    let asked = false;
    const sdk = scriptedSdk(script(), () => (asked = true));
    // the bound value is always a 64-hex hash; a long one can only come from a caller that bypasses the recipes
    const long = { ...onboarding(sdk), contractRoot: new Uint8Array(32) };
    const { checkBindLength } = await import('@legx/core/zkIdentity');
    expect(checkBindLength('a'.repeat(507))).toEqual({ ok: false, code: 'BOUND_TOO_LONG' });
    expect(checkBindLength('a'.repeat(506))).toEqual({ ok: true });
    await buildZkRequest(long);
    expect(asked).toBe(true); // a real 64-hex value passes the check
  });
});

describe('P4.8-02 QR code and link', () => {
  it('the QR decodes to the URL, the link has the same URL, both fit 360 px', async () => {
    const url = 'https://zkpassport.id/r?d=legx.app&s=legx/v1/x&id=abc123';
    const screen = await render(
      <div style={{ width: 360 }}>
        <QrCode value={url} />
      </div>,
    );
    const svg = screen.container.querySelector('svg') as SVGSVGElement;
    expect(svg.getBoundingClientRect().width).toBeLessThanOrEqual(360);
    // rasterize from the rects themselves (WebKit refuses to decode an SVG blob as an image)
    const [, , size = 0] = (svg.getAttribute('viewBox') ?? '').split(' ').map(Number);
    const scale = 8;
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = size * scale;
    const ctx = canvas.getContext('2d') as CanvasRenderingContext2D;
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#000';
    for (const r of svg.querySelectorAll('rect[fill="#000"]'))
      ctx.fillRect(Number(r.getAttribute('x')) * scale, Number(r.getAttribute('y')) * scale, scale, scale);
    const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
    expect(jsQR(data.data, canvas.width, canvas.height)?.data).toBe(url);
  });

  it('the panel shows the link with the same URL', async () => {
    const sdk = scriptedSdk(script([], 'https://zkpassport.id/r?id=77'));
    await render(<PassportProof build={() => buildZkRequest(onboarding(sdk))} onDone={() => {}} identityPolicy="zk" />);
    await page.getByRole('button', { name: 'Start passport proof' }).click();
    await expect.element(page.getByTestId('zk-link')).toHaveAttribute('href', 'https://zkpassport.id/r?id=77');
    await expect.element(page.getByTestId('zk-qr')).toBeVisible();
  });
});

describe('P4.8-03, -11 callbacks and timeouts', () => {
  const texts = async (events: ZkScript['events'], timeoutMs?: number) => {
    const sdk = scriptedSdk(script(events));
    let done = 0;
    await render(
      <PassportProof
        build={() => buildZkRequest(onboarding(sdk))}
        onDone={() => done++}
        identityPolicy="zk"
        {...(timeoutMs ? { timeoutMs } : {})}
      />,
    );
    await page.getByRole('button', { name: 'Start passport proof' }).click();
    return () => done;
  };

  it('each state has its own text; the result shows "Passport proof done" and calls onDone', async () => {
    const done = await texts([
      { type: 'received' },
      { type: 'generating' },
      { type: 'generated' },
      { type: 'result', outcome: recordedOutcome(aliceOnboarding as never) },
    ]);
    await expect.element(page.getByText('Passport proof done.')).toBeVisible();
    await expect.poll(done).toBeGreaterThan(0);
  });

  it('reject and error offer Try again', async () => {
    await texts([{ type: 'reject' }]);
    await expect.element(page.getByText('You declined the request in the app.')).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Try again' })).toBeVisible();
  });

  it('an error shows its own text and Try again', async () => {
    await texts([{ type: 'error', message: 'bridge down' }]);
    await expect.element(page.getByText(/Something went wrong/)).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Try again' })).toBeVisible();
  });

  it('a phone that never answers times out with Try again and never reports done', async () => {
    const done = await texts([{ type: 'received' }, { type: 'generating' }], 2000); // I-W-17: 300 ms raced the first assertion under load
    await expect.element(page.getByText('Your phone is making the proof.', { exact: false })).toBeVisible();
    await expect.element(page.getByText('The phone app did not answer in time.')).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Try again' })).toBeVisible();
    expect(done()).toBe(0);
  });

  it('callbacks in a wrong order never reach done without proving first', () => {
    const outcome = recordedOutcome(aliceOnboarding as never);
    const run = (events: Parameters<typeof zkReducer>[1][]) => events.reduce<ZkState>(zkReducer, { step: 'idle' });
    expect(run([{ type: 'result', outcome }]).step).toBe('idle');
    expect(
      run([
        { type: 'start', url: 'u' },
        { type: 'result', outcome },
      ]).step,
    ).toBe('waiting');
    expect(run([{ type: 'start', url: 'u' }, { type: 'generated' }]).step).toBe('waiting');
    const done = run([{ type: 'start', url: 'u' }, { type: 'generating' }, { type: 'result', outcome }]);
    expect(done.step).toBe('done');
    expect(zkReducer(done, { type: 'reject' }).step).toBe('done');
    expect(zkReducer(done, { type: 'error', message: 'x' }).step).toBe('done');
  });
});

describe('P4.8-04, -12, -14, -15 onboarding facts and salt', () => {
  const outcome = recordedOutcome(aliceOnboarding as never);

  it('the ZK route request holds public proofs only: no disclosed name, birth date or nationality (spy)', () => {
    const req = submissionOf('onboarding', IN.deal1, true, outcome);
    expect(req.domain).toBe(ZK_DOMAIN);
    expect(req.scope).toBe(`legx/v1/${IN.deal1}`);
    const { facts } = splitDisclosure(outcome.queryResult);
    expect(Object.keys(facts).length).toBeGreaterThan(0);
    const wire = JSON.stringify(req);
    for (const v of Object.values(facts)) expect(wire).not.toContain(JSON.stringify(v).slice(1, -1));
    expect(wire).not.toMatch(/mrz|photo|dg1/i);
    for (const p of req.proofs) expect(p.committedInputs ?? {}).not.toHaveProperty('disclose_bytes');
  });

  it("the disclosed facts and the salt open only for the client's own lawyer, with the right salt giving C_side", async () => {
    const lawyer = await xwing.keygen();
    const other = await xwing.keygen();
    const box = await sealOnboardingFacts(outcome, lawyer.publicKey, IN.deal1, 'A');
    const opened = await openDisclosure(box, lawyer.secretKey, IN.deal1, 'A');
    expect(opened.ok && opened.facts).toEqual(splitDisclosure(outcome.queryResult).facts);
    expect(await openDisclosure(box, other.secretKey, IN.deal1, 'A')).toMatchObject({ ok: false });
    const { zkSalt32, sealed } = await makeSealedSalt(lawyer.publicKey, IN.deal1, 'A');
    const salt = await openSalt(sealed, lawyer.secretKey, IN.deal1, 'A');
    const n = aliceOnboarding.verification.uniqueIdentifier as string;
    expect(salt.ok && bytesToHex(zkIdentityCommitment(salt.zkSalt32, n))).toBe(
      bytesToHex(zkIdentityCommitment(zkSalt32, n)),
    );
    expect(JSON.stringify(submissionOf('onboarding', IN.deal1, true, outcome))).not.toContain(bytesToHex(zkSalt32));
    expect(await openSalt(sealed, other.secretKey, IN.deal1, 'A')).toMatchObject({ ok: false });
  });
});

describe('P4.8-05 to -07, -16, -17, -19, -20 release and the console', () => {
  const rel = recordedOutcome(aliceRelease as never);
  const verification = aliceRelease.verification as ZkVerification;
  const nonces = () => {
    const n = new LawyerNonces(() => hex(IN.lawyerNonce));
    n.issue();
    return n;
  };
  const expectation = (profile: 'demo' | 'production' = 'demo') => ({
    stage: 'release' as const,
    dealId: IN.deal1,
    boundValue: '',
    profile,
    identity: {
      zkSalt32: SALT,
      commitment: bytesToHex(zkIdentityCommitment(SALT, verification.uniqueIdentifier as string)),
    },
    faceMatchOptional: true,
  });
  const consoleCheck = (
    n: LawyerNonces,
    over: Partial<ReleaseInput> = {},
    profile: 'demo' | 'production' = 'demo',
    v = verification,
  ) =>
    checkForConsole({
      verification: v,
      originalQuery: rel.originalQuery,
      expectation: expectation(profile),
      release: { input: release(scriptedSdk(script()), over), nonces: n },
    });

  it('P4.8-05 the bound value is presenceMsg; a stale ledger hash stops the request before the SDK', async () => {
    const r = await buildZkRequest(release(scriptedSdk(script())));
    expect(r.boundValue).toBe(verification.committedInputs.custom_data);
    let asked = false;
    const stale = release(
      scriptedSdk(script(), () => (asked = true)),
      { ledgerCloseTime: NOW - 3601 },
    );
    await expect(buildZkRequest(stale)).rejects.toMatchObject({ code: 'LEDGER_STALE' });
    expect(asked).toBe(false);
  });

  it('P4.8-16 the release asks for the strict face match; turning it off needs the deal data', async () => {
    let calls: [string, unknown[]][] = [];
    await buildZkRequest(release(scriptedSdk(script(), (_s, c) => (calls = c as never))));
    expect(calls.map(([n]) => n)).toContain('facematch');
    expect(calls.find(([n]) => n === 'facematch')?.[1]).toEqual(['strict']);
    await expect(buildZkRequest(release(scriptedSdk(script()), { faceMatch: false }))).rejects.toMatchObject({
      code: 'FACE_MATCH_REQUIRED',
    });
  });

  it('P4.8-07 the console lists each check; a good recorded release passes, a tampered one FAILs', () => {
    const good = consoleCheck(nonces());
    expect(good.ok).toBe(true);
    expect(good.checks.every((c) => c.status === 'PASS')).toBe(true);
    const tampered = consoleCheck(nonces(), {}, 'demo', { ...verification, verified: false });
    expect(tampered.ok).toBe(false);
    expect(tampered.checks.find((c) => c.name === 'Proof verified')?.status).toBe('FAIL');
  });

  it('P4.8-06 another identifier is rejected as ZK_IDENTIFIER_MISMATCH', () => {
    const other = { ...verification, uniqueIdentifier: 'f'.repeat(verification.uniqueIdentifier?.length ?? 64) };
    expect(consoleCheck(nonces(), {}, 'demo', other as ZkVerification).code).toBe('ZK_IDENTIFIER_MISMATCH');
  });

  it('P4.8-17 a replayed release proof is refused: the nonce is single use, and an unknown nonce is refused', () => {
    const n = nonces();
    expect(consoleCheck(n).ok).toBe(true);
    const again = consoleCheck(n);
    expect(again.ok).toBe(false);
    expect(again.code).toBe('NONCE_REUSED');
    expect(again.checks.find((c) => c.name === 'Lawyer nonce unused')?.status).toBe('FAIL');
    expect(consoleCheck(new LawyerNonces()).code).toBe('NONCE_UNKNOWN');
  });

  it("P4.8-17 the nonce in the bound value is the lawyer's: a proof bound to another nonce is refused", () => {
    const n = new LawyerNonces(() => new Uint8Array(32).fill(7));
    n.issue();
    expect(consoleCheck(n, { lawyerNonce: new Uint8Array(32).fill(7) }).code).toBe('BOUND_VALUE_MISMATCH');
  });

  it('P4.8-20 an anchor older than 1 hour is refused by default, older than 24 hours for any setting', () => {
    expect(consoleCheck(nonces(), { ledgerCloseTime: NOW - 3601 }).code).toBe('LEDGER_STALE');
    expect(consoleCheck(nonces(), { ledgerCloseTime: NOW - 3601, maxAgeSeconds: 86400 }).code).not.toBe('LEDGER_STALE');
    expect(consoleCheck(nonces(), { ledgerCloseTime: NOW - 86401, maxAgeSeconds: 86400 }).code).toBe('LEDGER_TOO_OLD');
  });

  it('P4.8-09, -19 production refuses the recorded devMode, Sepolia and mock proof; the demo accepts it', () => {
    expect(consoleCheck(nonces(), {}, 'production').ok).toBe(false);
    expect(['DEVMODE_REFUSED', 'SEPOLIA_REFUSED', 'MOCK_IDENTIFIER_REFUSED']).toContain(
      consoleCheck(nonces(), {}, 'production').code,
    );
    const prod = trustRows(verification, 'production');
    const status = (label: string) => prod.find((r) => r.label === label)?.status;
    expect([status('Chain'), status('Identifier type'), status('Dev mode')]).toEqual(['FAIL', 'FAIL', 'FAIL']);
    expect(trustRows(verification, 'demo').every((r) => r.status === 'PASS')).toBe(true);
    expect(prod.map((r) => r.label)).toEqual([
      'Chain',
      'Registry root',
      'Circuit manifest version',
      'Verification key hashes',
      'Identifier type',
      'Dev mode',
    ]);
  });

  it('P4.8-09 devMode outside the demo profile: the app refuses before the SDK is asked', async () => {
    let asked = false;
    const sdk = scriptedSdk(script(), () => (asked = true));
    await expect(buildZkRequest({ ...release(sdk), profile: 'production' })).rejects.toMatchObject({
      code: 'DEVMODE_OUTSIDE_DEMO',
    });
    expect(asked).toBe(false);
    await expect(buildZkRequest({ ...release(sdk), profile: 'production', devMode: false })).resolves.toBeDefined();
  });
});

describe('P4.8-07, -12 the ZK route (501, mocked with MSW)', () => {
  it('posts the public request and logs it; a 501 is "cannot check now", never a pass', async () => {
    const req = submissionOf('release', IN.deal1, true, recordedOutcome(aliceRelease as never));
    const r = await verifyOnServer(client, IN.deal1, 'A', req, SALT);
    expect(r).toEqual({ ok: false, code: 'CANNOT_CHECK_NOW' });
    expect(logged).toHaveLength(1);
    expect(logged[0]?.dealId).toBe(IN.deal1);
    expect(JSON.stringify(logged[0]?.body)).not.toMatch(/firstname|lastname|mrz|photo/i);
  });

  it('a network failure is also "cannot check now"', async () => {
    const offline = createApiClient({
      signRequest: async () => AUTH,
      fetch: async () => Promise.reject(new Error('down')),
    });
    const req = submissionOf('release', IN.deal1, true, recordedOutcome(aliceRelease as never));
    expect(await verifyOnServer(offline, IN.deal1, 'A', req, SALT)).toEqual({ ok: false, code: 'CANNOT_CHECK_NOW' });
  });
});

describe('P4.8-10 the chip fallback button', () => {
  const shows = async (policy: 'zk' | 'zk-or-chip' | 'chip') => {
    const sdk = scriptedSdk(script());
    const screen = await render(
      <PassportProof
        build={() => buildZkRequest(onboarding(sdk))}
        onDone={() => {}}
        identityPolicy={policy}
        onUseChip={() => {}}
      />,
    );
    return {
      chip: screen.container.textContent?.includes('Use my passport chip instead'),
      zk: screen.container.textContent?.includes('Start passport proof'),
    };
  };
  it('is shown only for zk-or-chip; the zero-knowledge screen is hidden for chip', async () => {
    expect(await shows('zk')).toEqual({ chip: false, zk: true });
    expect(await shows('zk-or-chip')).toEqual({ chip: true, zk: true });
    expect(await shows('chip')).toEqual({ chip: false, zk: false });
  });
});

describe('P4.8-13 flow on this engine', () => {
  it('onboarding and release both complete with the recorded demo scripts', async () => {
    for (const [set, input] of [
      [aliceOnboarding, (s: ReturnType<typeof scriptedSdk>) => onboarding(s)],
      [aliceRelease, (s: ReturnType<typeof scriptedSdk>) => release(s)],
    ] as const) {
      const sdk = scriptedSdk(scriptFromRecording(set as never));
      let done = 0;
      const screen = await render(
        <PassportProof build={() => buildZkRequest(input(sdk))} onDone={() => done++} identityPolicy="zk" />,
      );
      await page.getByRole('button', { name: 'Start passport proof' }).click();
      await expect.element(page.getByText('Passport proof done.')).toBeVisible();
      await expect.poll(() => done).toBeGreaterThan(0);
      screen.unmount();
    }
  });
});

describe('OD-32 onboarding verification runs in the console', () => {
  const outcome = recordedOutcome(aliceOnboarding as never);
  const verification = aliceOnboarding.verification as ZkVerification;
  const input = async (lawyerPub: Uint8Array) => ({
    dealId: IN.deal1,
    side: 'A' as const,
    profile: 'demo' as const,
    request: submissionOf('onboarding', IN.deal1, true, outcome),
    boundValue: onboardingBoundValue(hex(IN.contractRoot), hex(IN.slotPub)),
    cancelAfter: IN.cancelAfter,
    box: await sealOnboardingFacts(outcome, lawyerPub, IN.deal1, 'A'),
  });
  const deps = (secret: Uint8Array, verdict: ZkVerification | Error = verification) => ({
    verifyPublic: async () => {
      if (verdict instanceof Error) throw verdict;
      return verdict;
    },
    openBox: (box: Parameters<typeof openDisclosure>[0], dealId: string, side: string) =>
      openDisclosure(box, secret, dealId, side),
  });

  it("opens the client's disclosure box with the lawyer's key and returns the facts and the identifier", async () => {
    const lawyer = await xwing.keygen();
    const r = await verifyOnboardingInConsole(deps(lawyer.secretKey), await input(lawyer.publicKey));
    expect(r.ok && r.facts).toEqual(splitDisclosure(outcome.queryResult).facts);
    expect(r.ok && r.identifier).toBe(verification.uniqueIdentifier);
  });

  it('the server route sees the public proofs only: the facts never leave the console', async () => {
    const lawyer = await xwing.keygen();
    const seen: unknown[] = [];
    const i = await input(lawyer.publicKey);
    await verifyOnboardingInConsole(
      {
        ...deps(lawyer.secretKey),
        verifyPublic: async (req) => {
          seen.push(req);
          return verification;
        },
      },
      i,
    );
    for (const v of Object.values(splitDisclosure(outcome.queryResult).facts))
      expect(JSON.stringify(seen)).not.toContain(JSON.stringify(v).slice(1, -1));
  });

  it('refuses when the box does not open (another lawyer), when the proof fails, and when the server cannot check', async () => {
    const lawyer = await xwing.keygen();
    const other = await xwing.keygen();
    const i = await input(lawyer.publicKey);
    expect(await verifyOnboardingInConsole(deps(other.secretKey), i)).toEqual({ ok: false, code: 'BOX_OPEN_FAILED' });
    expect(
      await verifyOnboardingInConsole(deps(lawyer.secretKey, { ...verification, verified: false }), i),
    ).toMatchObject({ ok: false, code: 'PROOF_NOT_VERIFIED' });
    expect(await verifyOnboardingInConsole(deps(lawyer.secretKey, new Error('503')), i)).toEqual({
      ok: false,
      code: 'CANNOT_CHECK_NOW',
    });
  });

  it('refuses a box whose digest differs from the one the attestation will name', async () => {
    const lawyer = await xwing.keygen();
    const i = await input(lawyer.publicKey);
    expect(await verifyOnboardingInConsole(deps(lawyer.secretKey), { ...i, boxSha256: '00'.repeat(32) })).toEqual({
      ok: false,
      code: 'BOX_DIGEST_MISMATCH',
    });
  });
});

describe('P4.8-08 local re-verification in the browser (bb.js runs single-threaded without SharedArrayBuffer)', () => {
  const bodyFiles = import.meta.glob('../../../packages/zk/fixtures/files/*.json', {
    query: '?raw',
    import: 'default',
  }) as Record<string, () => Promise<string>>;
  const recording = async (set: typeof aliceOnboarding) => {
    const bodies = new Map<string, string>();
    for (const [path, load] of Object.entries(bodyFiles)) {
      const m = /(manifest|circuit)-(.+)\.json$/.exec(path);
      if (m && `${m[1]}/${m[2]}` in set.loaders.files) bodies.set(`${m[1]}/${m[2]}`, await load());
    }
    return bodies;
  };
  const proofSet = (set: typeof aliceOnboarding) => ({
    request: set.request,
    proofs: set.proofs,
    queryResult: set.queryResult,
  });
  const NOW = Date.now();
  // The points bb.js reads (BN254 g1 8 MB, Grumpkin g1 16 MB; ~/.bb-crs after any bb.js run) are not committed: copy them to
  // build/tmp/F4/ under their CRS names to run these tests offline (g2.dat is 128 bytes and is in test/fixtures).
  // Source: https://crs.aztec-labs.com/ (g1_compressed.dat, grumpkin_g1_v2.dat, g2.dat)
  const crsFiles = import.meta.glob('../../../build/tmp/F4/*.dat', { query: '?url', import: 'default' }) as Record<
    string,
    () => Promise<string>
  >;
  const g2File = import.meta.glob('./fixtures/bn254_g2.dat', { query: '?url', import: 'default' }) as Record<
    string,
    () => Promise<string>
  >;
  const have = (name: string) => Object.keys(crsFiles).some((k) => k.endsWith(`/${name}`));
  const crsLoader = have('bn254_g1_compressed.dat') && have('grumpkin_g1_v2.dat');
  const bytesAt = async (load: () => Promise<string>) =>
    new Uint8Array(await (await fetch(await load())).arrayBuffer());
  const crs = async () => {
    const at = (name: string) =>
      Object.entries(crsFiles).find(([k]) => k.endsWith(`/${name}`))?.[1] as () => Promise<string>;
    return new Map([
      ['g1_compressed.dat', await bytesAt(at('bn254_g1_compressed.dat'))],
      ['grumpkin_g1_v2.dat', await bytesAt(at('grumpkin_g1_v2.dat'))],
      ['g2.dat', await bytesAt(Object.values(g2File)[0] as () => Promise<string>)],
    ]);
  };

  const reverifyIt = crsLoader ? it : it.skip; // skipped, not failed, without the CRS file (see above)

  reverifyIt(
    're-verifies a recorded onboarding set with the SDK, every loader served from the recording',
    async () => {
      const set = proofSet(aliceOnboarding) as never;
      const r = await reverifyInBrowser(
        set,
        replayConfig(set, aliceOnboarding.loaders as never, await recording(aliceOnboarding), NOW, await crs()),
      );
      expect(r).toMatchObject({ ok: true });
    },
    120_000,
  );

  reverifyIt(
    'a changed proof byte does not verify, and no network is touched',
    async () => {
      const set = structuredClone(aliceOnboarding);
      const p = set.proofs[0] as { proof: string };
      p.proof = `${p.proof.slice(0, 700)}${p.proof[700] === '0' ? '1' : '0'}${p.proof.slice(701)}`;
      const before = globalThis.fetch;
      const r = await reverifyInBrowser(
        proofSet(set) as never,
        replayConfig(proofSet(set) as never, set.loaders as never, await recording(set), NOW, await crs()),
      );
      expect(r).toEqual({ ok: false, code: 'PROOF_NOT_VERIFIED' });
      expect(globalThis.fetch).toBe(before); // the temporary fetch is always restored
    },
    120_000,
  );

  it('a local failure blocks the onboarding check even when the adapter says PASS', async () => {
    const lawyer = await xwing.keygen();
    const outcome = recordedOutcome(aliceOnboarding as never);
    const base = {
      dealId: IN.deal1,
      side: 'A' as const,
      profile: 'demo' as const,
      request: submissionOf('onboarding', IN.deal1, true, outcome),
      boundValue: onboardingBoundValue(hex(IN.contractRoot), hex(IN.slotPub)),
      cancelAfter: IN.cancelAfter,
      box: await sealOnboardingFacts(outcome, lawyer.publicKey, IN.deal1, 'A'),
    };
    const adapter = {
      verifyPublic: async () => aliceOnboarding.verification as ZkVerification,
      openBox: (box: Parameters<typeof openDisclosure>[0], d: string, s: string) =>
        openDisclosure(box, lawyer.secretKey, d, s),
    };
    expect(await verifyOnboardingInConsole({ ...adapter, reverify: async () => true }, base)).toMatchObject({
      ok: true,
    });
    expect(await verifyOnboardingInConsole({ ...adapter, reverify: async () => false }, base)).toEqual({
      ok: false,
      code: 'LOCAL_REVERIFY_FAILED',
    });
  });
});
