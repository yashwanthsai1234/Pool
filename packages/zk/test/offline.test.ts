// Task 1.17: offline re-verification of the recorded mock-passport proofs through the real SDK, with fetch and
// TCP sockets stubbed to throw (IMPLEMENTATION T-U-32b, c, e and P1.17-18, P1.17-10; DESIGN 6.10).
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import { join } from 'node:path';
import { ZkVerification } from '@legx/contracts/records';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { installedVersions, PINNED } from '../src/sdk.ts';
import { type FileBodies, reverifyOffline } from '../src/verify.ts';
import { bodiesOf, FIXTURES, loadSet, type RecordedSet, SET_NAMES, type SetName } from './fixtures.ts';

const blocked: string[] = [];
const realFetch = globalThis.fetch;
const realConnect = net.Socket.prototype.connect;

beforeAll(() => {
  globalThis.fetch = (async (input: unknown) => {
    blocked.push(String(input));
    throw new Error('network blocked');
  }) as typeof fetch;
  // bb.js talks to its native prover over a Unix socket (`path`); any TCP connection is refused.
  net.Socket.prototype.connect = function (this: net.Socket, ...args: unknown[]) {
    const opts = args[0] as { path?: string } | unknown[];
    const path = Array.isArray(opts) ? (opts[0] as { path?: string })?.path : opts?.path;
    if (typeof path !== 'string') throw new Error('TCP blocked');
    return (realConnect as (...a: unknown[]) => net.Socket).apply(this, args);
  } as typeof net.Socket.prototype.connect;
});
afterAll(() => {
  globalThis.fetch = realFetch;
  net.Socket.prototype.connect = realConnect;
  expect(blocked).toEqual([]);
});

const sets = Object.fromEntries(SET_NAMES.map((n) => [n, loadSet(n)])) as Record<SetName, RecordedSet>;
const reverify = (
  s: RecordedSet,
  o: {
    verification?: ZkVerification;
    bodies?: FileBodies;
    profile?: 'production' | 'demo';
    proofs?: RecordedSet['proofs'];
  } = {},
) =>
  reverifyOffline(
    { request: s.request, proofs: o.proofs ?? s.proofs, queryResult: s.queryResult },
    o.verification ?? s.verification,
    s.loaders,
    o.bodies ?? bodiesOf(s),
    o.profile ?? 'demo',
  );
const withTrust = (s: RecordedSet, t: Partial<ZkVerification['trust']>, rest: Partial<ZkVerification> = {}) => ({
  ...s.verification,
  ...rest,
  trust: { ...s.verification.trust, ...t },
});

describe('fixture integrity', () => {
  it('every recorded file has the hash in SHA256SUMS (a change needs a new recording)', () => {
    const lines = readFileSync(join(FIXTURES, 'SHA256SUMS'), 'utf8').trim().split('\n');
    expect(lines.length).toBeGreaterThanOrEqual(SET_NAMES.length + 2);
    for (const line of lines) {
      const [sum, file] = line.split('  ') as [string, string];
      expect(
        createHash('sha256')
          .update(readFileSync(join(FIXTURES, file)))
          .digest('hex'),
        file,
      ).toBe(sum);
    }
  });

  it('every recorded result parses as the ZkVerifierPort result of @legx/contracts', () => {
    for (const s of Object.values(sets)) expect(ZkVerification.safeParse(s.verification).success, s.name).toBe(true);
  });

  it('the installed SDK, utils and registry are the versions every recording names', () => {
    expect(installedVersions()).toEqual(PINNED);
    for (const s of Object.values(sets)) expect(s.versions).toEqual(PINNED);
  });
});

describe('T-U-32b offline re-verification from the recorded registry answer and circuit files', () => {
  const good: SetName[] = ['alice-onboarding', 'alice-release', 'alice-deal2', 'bob-release', 'alice-other-domain'];

  it.each(good)('%s: verified, with the recorded identifier', async (name) => {
    const r = await reverify(sets[name]);
    expect(r).toEqual({ ok: true, verified: true, uniqueIdentifier: sets[name].verification.uniqueIdentifier });
  });

  it.each(['alice-release-facematch', 'expired'] as const)('%s: keeps its recorded failure', async (name) => {
    expect(sets[name].verification.verified).toBe(false);
    expect(await reverify(sets[name])).toEqual({ ok: false, code: 'PROOF_NOT_VERIFIED' });
  });
});

describe('concurrency', () => {
  it('parallel re-verifications all pass, and the network stub is back in place afterwards', async () => {
    const before = globalThis.fetch;
    const names = ['alice-release', 'bob-release', 'alice-deal2'] as const;
    const results = await Promise.all(names.map((n) => reverify(sets[n])));
    expect(results.map((r) => r.ok)).toEqual([true, true, true]);
    expect(globalThis.fetch).toBe(before);
  });
});

describe('T-U-32c a mismatch fails offline', () => {
  const s = sets['alice-release'];
  const flip = (h: string) => `${h.slice(0, -1)}${h.endsWith('0') ? '1' : '0'}`;

  it('a changed registry root', async () => {
    expect(
      await reverify(s, { verification: withTrust(s, { root: flip(s.verification.trust.root) as never }) }),
    ).toEqual({
      ok: false,
      code: 'TRUST_MISMATCH:root',
    });
  });

  it('a changed verification-key hash', async () => {
    const vkeyHashes = [
      flip(s.verification.trust.vkeyHashes[0] as string),
      ...s.verification.trust.vkeyHashes.slice(1),
    ];
    expect(await reverify(s, { verification: withTrust(s, { vkeyHashes: vkeyHashes as never }) })).toEqual({
      ok: false,
      code: 'TRUST_MISMATCH:vkey_hashes',
    });
  });

  it('a changed circuit file', async () => {
    const bodies = bodiesOf(s);
    const key = Object.keys(s.loaders.files).find((k) => k.startsWith('circuit/')) as string;
    bodies.set(key, (bodies.get(key) as string).replace('"', ' "'));
    expect(await reverify(s, { bodies })).toEqual({ ok: false, code: 'TRUST_MISMATCH:circuit_files' });
  });

  it('another manifest version', async () => {
    expect(await reverify(s, { verification: withTrust(s, { circuitManifestVersion: '0.21.2' }) })).toEqual({
      ok: false,
      code: 'TRUST_MISMATCH:circuit_manifest_version',
    });
  });

  it('another chain, block or registry address', async () => {
    const t = s.verification.trust;
    expect(
      await reverify(s, { verification: withTrust(s, { chainId: 1 }, { uniqueIdentifierType: 'NON_SALTED' }) }),
    ).toMatchObject({ code: 'TRUST_MISMATCH:chain_id' });
    expect(await reverify(s, { verification: withTrust(s, { blockNumber: t.blockNumber + 1 }) })).toMatchObject({
      code: 'TRUST_MISMATCH:block',
    });
    expect(await reverify(s, { verification: withTrust(s, { blockHash: flip(t.blockHash) as never }) })).toMatchObject({
      code: 'TRUST_MISMATCH:block',
    });
    expect(
      await reverify(s, { verification: withTrust(s, { registryAddress: flip(t.registryAddress) as never }) }),
    ).toMatchObject({ code: 'TRUST_MISMATCH:registry_address' });
  });

  it('a proof set stored without the SDK committedInputs does not verify (request to task 1.2)', async () => {
    const proofs = s.proofs.map(({ committedInputs: _dropped, ...p }) => p);
    expect(await reverify(s, { proofs })).toEqual({ ok: false, code: 'PROOF_NOT_VERIFIED' });
  });

  it('one changed proof byte', async () => {
    const proofs = s.proofs.map((p) => ({ ...p }));
    const bind = proofs.find((p) => p.name === 'bind') as { proof: string };
    const at = bind.proof.length - 200;
    bind.proof = `${bind.proof.slice(0, at)}${bind.proof[at] === '0' ? '1' : '0'}${bind.proof.slice(at + 1)}`;
    expect(await reverify(s, { proofs })).toEqual({ ok: false, code: 'PROOF_NOT_VERIFIED' });
  });
});

describe('T-U-32e production refusals repeat at re-verification time', () => {
  const s = sets['alice-release'];

  it('the recorded Sepolia dev-mode mock proof is refused in production and accepted in the demo profile', async () => {
    expect(await reverify(s, { profile: 'production' })).toEqual({ ok: false, code: 'DEVMODE_REFUSED' });
    expect(await reverify(s, { profile: 'demo' })).toMatchObject({ ok: true });
  });

  it.each([
    ['DEVMODE_REFUSED', { chainId: 1 }, 'NON_SALTED'],
    ['SEPOLIA_REFUSED', { devMode: false }, 'NON_SALTED'],
    ['MOCK_IDENTIFIER_REFUSED', { chainId: 1, devMode: false }, 'NON_SALTED_MOCK'],
  ] as const)('one refused field at a time: %s', async (code, t, type) => {
    const verification = withTrust(s, t, { uniqueIdentifierType: type });
    expect(await reverify(s, { verification, profile: 'production' })).toEqual({ ok: false, code });
  });
});

describe('P1.17-18 mock identifiers, verified again offline', { timeout: 60_000 }, () => {
  it('repeat for the same passport, domain and scope, and differ for a second passport, scope or domain', async () => {
    const id = async (n: SetName) => ((await reverify(sets[n])) as { uniqueIdentifier: string }).uniqueIdentifier;
    const base = await id('alice-onboarding');
    expect(base).toMatch(/^[0-9]+$/);
    expect(await id('alice-release')).toBe(base);
    expect(new Set([base, await id('bob-release'), await id('alice-deal2'), await id('alice-other-domain')]).size).toBe(
      4,
    );
  });

  it('the identifier type is the mock type, and the domain and scope are the ones our request code stored', () => {
    for (const n of ['alice-onboarding', 'alice-release', 'alice-deal2', 'bob-release'] as const) {
      expect(sets[n].verification.uniqueIdentifierType).toBe('NON_SALTED_MOCK');
      expect(sets[n].verification.domain).toBe('legx.app');
      expect(sets[n].verification.scope).toBe(sets[n].request.scope);
    }
    expect(sets['alice-deal2'].verification.scope).toBe(`legx/v1/${sets['alice-deal2'].inputs.deal2}`);
    expect(sets['alice-other-domain'].verification.domain).toBe('other.app');
  });
});
