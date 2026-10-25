// Task 3.11 (IMPLEMENTATION P3.11-06 to -08, -13 to -16): the trust record in zk_proof, the recorded files in the
// object store, offline re-verification from them, and the no-passport-data scan. Database: PGlite (Postgres 18).

import { openPglite } from '@legx/db/pglite';
import { ZkProofRecord } from '@legx/db/repos/identity';
import { bytesToHex } from '@noble/hashes/utils.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { reverifyStored, verifyAndStore } from '../src/store.ts';
import { adapter, expectation, loadSet, memoryStore, noSleep, request, SALT, useFakeNetwork } from './helpers.ts';

vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });
let env: ReturnType<typeof useFakeNetwork>;
beforeEach(() => {
  env = useFakeNetwork();
});
afterEach(() => env.restore());

const onboarding = loadSet('alice-onboarding');
const release = loadSet('alice-release');
const bob = loadSet('bob-release');

async function setup() {
  const db = openPglite();
  await db.migrate();
  for (const id of [onboarding.inputs.deal1, onboarding.inputs.deal2])
    await db.repos.deals.insert({
      deal_id: id,
      state: 'DRAFT',
      network: 'standalone',
      contract_root: onboarding.inputs.contractRoot,
      payout_a: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
      payout_b: 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn',
      amount_drops: '1000000',
    });
  return { db, objects: memoryStore(), adapter: adapter({}, noSleep) };
}
const run = (d: Awaited<ReturnType<typeof setup>>, s = release, side: 'A' | 'B' = 'A', over = {}) =>
  verifyAndStore(d, {
    dealId: s.inputs.deal1,
    side,
    request: request(s),
    expect: expectation(s),
    salt: SALT,
    ...over,
  });
const rows = (d: Awaited<ReturnType<typeof setup>>) => d.db.repos.zkProofs.list(onboarding.inputs.deal1);

describe('P3.11-06/14 the trust record', () => {
  it('stores the roots, circuit manifest, key hashes, identifier type, devMode and the loader file hashes', async () => {
    const d = await setup();
    await run(d);
    const [row] = await rows(d);
    const t = row?.registry_roots;
    expect(t).toMatchObject({ chain_id: 11155111, identifier_type: 'NON_SALTED_MOCK', dev_mode: true });
    for (const v of [t?.block_hash, t?.registry_address, t?.root, t?.circuit_manifest_version]) expect(v).toBeTruthy();
    expect(t?.vkey_hashes.length).toBeGreaterThan(0);
    const files = t?.loader_files ?? {};
    expect(Object.keys(files)).toContain('loaders');
    expect(Object.keys(files).some((k) => k.startsWith('manifest/'))).toBe(true);
    expect(Object.keys(files).filter((k) => k.startsWith('circuit/')).length).toBeGreaterThan(0);
  });

  it('the loader files are kept in the object store under their SHA-256, as the object store records it', async () => {
    const d = await setup();
    await run(d);
    const [row] = await rows(d);
    for (const hash of Object.values(row?.registry_roots.loader_files ?? {})) {
      const bytes = [...d.objects.objects.entries()].find(([k]) => k.endsWith(`/${hash}`))?.[1];
      expect(bytes).toBeDefined();
    }
  });

  it('a record with a missing field fails the store', async () => {
    const d = await setup();
    await run(d);
    const [row] = await rows(d);
    for (const key of Object.keys(row?.registry_roots ?? {}).filter((k) => k !== 'loader_files')) {
      const { [key]: _gone, ...rest } = { ...row?.registry_roots } as Record<string, unknown>;
      expect(ZkProofRecord.safeParse({ ...row, registry_roots: rest }).success, key).toBe(false);
    }
  });

  it('nothing is stored when the CDN is down', async () => {
    const d = await setup();
    env.net.behaviour.set('circuits2.zkpassport.id', 'down');
    await expect(run(d)).rejects.toMatchObject({ code: 'ZK_CDN_UNAVAILABLE' });
    expect(await rows(d)).toEqual([]);
    expect(d.objects.objects.size).toBe(0);
  });

  it('a forged proof is not stored', async () => {
    const d = await setup();
    const proofs = release.proofs.map((p) => ({ ...p }));
    const bind = proofs.find((p) => p.name === 'bind') as { proof: string };
    bind.proof = `${bind.proof.slice(0, 50)}${bind.proof[50] === 'a' ? 'b' : 'a'}${bind.proof.slice(51)}`;
    await expect(run(d, release, 'A', { request: request(release, { proofs } as never) })).rejects.toMatchObject({
      code: 'ZK_NOT_VERIFIED',
    });
    expect(await rows(d)).toEqual([]);
  });
});

describe('P3.11-07/08 scope, bound value and the identifier', () => {
  it('a proof for another deal scope, or one bound to another value, is refused with the core reason', async () => {
    const d = await setup();
    await expect(
      run(d, release, 'A', {
        dealId: release.inputs.deal2,
        expect: { ...expectation(release), dealId: release.inputs.deal2 },
      }),
    ).rejects.toMatchObject({ reason: 'WRONG_SCOPE' });
    await expect(
      run(d, release, 'A', {
        expect: { ...expectation(release), boundValue: onboarding.verification.committedInputs.custom_data },
      }),
    ).rejects.toMatchObject({ reason: 'BOUND_VALUE_MISMATCH' });
    expect(await rows(d)).toEqual([]);
  });

  it('the same passport gives the same identifier at onboarding and release, another passport another one', async () => {
    const d = await setup();
    await run(d, onboarding);
    await run(d, release);
    await run(d, bob, 'B', {
      expect: { ...expectation(bob), identity: { zkSalt32: SALT, commitment: bytesToHex(new Uint8Array(32)) } },
    }).catch(() => undefined);
    const [a] = await d.db.repos.zkProofs.list(onboarding.inputs.deal1);
    const stored = await rows(d);
    expect(stored.map((r) => r.identifier_hash)).toHaveLength(2);
    expect(stored[0]?.identifier_hash).toBe(stored[1]?.identifier_hash);
    expect(a?.identifier_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(bob.verification.uniqueIdentifier).not.toBe(release.verification.uniqueIdentifier);
  });

  it('a wrong salt cannot open the sealed commitment', async () => {
    const d = await setup();
    const wrong = new Uint8Array(32).fill(7);
    await expect(
      run(d, release, 'A', { expect: expectation(release, SALT), salt: wrong, request: request(release) }),
    ).resolves.toBeDefined();
    const bad = {
      ...expectation(release),
      identity: { zkSalt32: wrong, commitment: (expectation(release).identity as { commitment: string }).commitment },
    };
    await expect(run(d, release, 'A', { expect: bad })).rejects.toMatchObject({ reason: 'IDENTIFIER_MISMATCH' });
  });
});

describe('P3.11-13 no passport data or salt in logs, the table or the object store', () => {
  it('a full onboarding and release verify leaves none of it behind', async () => {
    const out: string[] = [];
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void out.push(a.map(String).join(' '))),
    );
    const d = await setup();
    await run(d, onboarding);
    await run(d, release);
    for (const s of spies) s.mockRestore();
    const stored = JSON.stringify(await rows(d), (_k, v) =>
      v instanceof Uint8Array ? Buffer.from(v).toString('latin1') : v,
    );
    const objects = [...d.objects.objects.values()].map((b) => Buffer.from(b).toString('latin1')).join('\n');
    // Short words match only as whole words: inside base64 or hex data they occur by chance.
    const words = ['ALICE', 'ONE', 'ZKR', '1990-01-01'].map(
      (w) => new RegExp(`(?<![A-Za-z0-9+/])${w}(?![A-Za-z0-9+/])`),
    );
    for (const text of [out.join('\n'), stored, objects]) {
      for (const w of words) expect(text).not.toMatch(w);
      expect(text).not.toContain(bytesToHex(SALT));
    }
    // the disclose proof is stored without its committed inputs, which hold the disclosed bytes
    const proof = JSON.parse(Buffer.from((await rows(d))[0]?.proof as Uint8Array).toString()) as {
      name: string;
      committedInputs?: object;
    }[];
    expect(proof.find((p) => p.name === 'disclose_bytes')?.committedInputs).toEqual({});
  });
});

describe('P3.11-15/16 offline re-verification from the stored record', () => {
  async function stored(s = release) {
    const d = await setup();
    const { verification } = await run(d, s);
    const [row] = await rows(d);
    return { d, row: { verification, loader_files: row?.registry_roots.loader_files ?? {} } };
  }
  const offline = () => {
    globalThis.fetch = (async () => {
      throw new Error('network blocked');
    }) as typeof fetch;
  };
  const setOf = (s: typeof release) => ({
    request: { ...s.request, validity: 86400 },
    proofs: s.proofs,
    queryResult: s.queryResult,
  });

  it('re-verifies with the network blocked; one stored file changed makes it fail', async () => {
    const { d, row } = await stored();
    offline();
    expect(await reverifyStored(d.objects, row, setOf(release), 'demo', Date.now())).toEqual({ ok: true });
    const key = [...d.objects.objects.keys()].find((k) => k.startsWith('zk/files/')) as string;
    const tampered = new Uint8Array(d.objects.objects.get(key) as Uint8Array);
    tampered[10] = (tampered[10] as number) ^ 1;
    d.objects.objects.set(key, tampered);
    expect(await reverifyStored(d.objects, row, setOf(release), 'demo')).toEqual({ ok: false, code: 'FILE_MISSING' });
  });

  it('the production profile refuses the recorded Sepolia, mock and devMode record with a clear reason', async () => {
    const { d, row } = await stored();
    offline();
    expect(await reverifyStored(d.objects, row, setOf(release), 'production')).toEqual({
      ok: false,
      code: 'DEVMODE_REFUSED',
    });
    const noDev = {
      ...row,
      verification: { ...row.verification, trust: { ...row.verification.trust, devMode: false } },
    };
    expect(await reverifyStored(d.objects, noDev, setOf(release), 'production')).toEqual({
      ok: false,
      code: 'SEPOLIA_REFUSED',
    });
    const mainnet = {
      ...noDev,
      verification: { ...noDev.verification, trust: { ...noDev.verification.trust, chainId: 1 } },
    };
    expect(await reverifyStored(d.objects, mainnet, setOf(release), 'production')).toEqual({
      ok: false,
      code: 'MOCK_IDENTIFIER_REFUSED',
    });
  });
});
