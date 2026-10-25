// P3.12-04 (no half-signed envelope), P3.12-08 (ML-DSA key rotation), P3.12-09 (FileSigner), P3.12-13 (algorithms fixed
// per record type in code). Source: IMPLEMENTATION 3.12; DESIGN 6.13.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { HybridSignature, SignerPort } from '@legx/contracts/ports';
import { KeyId } from '@legx/contracts/values';
import { ATTEST_PAYLOAD_TYPE, PAYLOAD_TYPE } from '@legx/core/evidence';
import { type KeyRegistry, signHybrid, verifyHybrid } from '@legx/core/hybridEnvelope';
import { fileSigner, generateNodeSignerKeys, kmsSigner, nodeSigner } from '@legx/signer';
import { describe, expect, it } from 'vitest';
import { createFakeKms, FAKE_ED_KEY, FAKE_PQ_KEY } from '../../../../packages/signer/test/helpers/fakeKms.ts';
import { registryFromRows } from '../../src/keys.ts';
import { createKeyring, HybridSigningFailed, resilientSigner } from '../../src/pq/index.ts';
import { inputFor, makeParty, makeService, makeWorld, type World } from '../helpers/world.ts';

/** A world whose service key is `signer` (the stock world fixes its own service key in the registry). */
async function worldSignedBy(signer: SignerPort): Promise<World> {
  const keys = await signer.publicKeys();
  let w: World | undefined;
  w = await makeWorld({
    signer,
    registry: async (dealId) =>
      registryFromRows(await (w as World).db.repos.enrollmentKeys.listForDeal(dealId), { keys, validFrom: 0 }),
  });
  return w;
}

const noSleep = async () => {};
const id = (s: string) => KeyId.parse(s);

/** A KMS client that fails the ML-DSA Sign call on demand: the Ed25519 half succeeds, the other half does not. */
function flakyKms() {
  const kms = createFakeKms();
  const state = { failPq: 0 };
  const client = {
    send: (async (cmd: object) => {
      if (
        state.failPq > 0 &&
        (cmd as { input: { KeyId?: string } }).input.KeyId === FAKE_PQ_KEY &&
        cmd.constructor.name === 'SignCommand'
      ) {
        state.failPq--;
        throw Object.assign(new Error('KMSInternalException: try again'), { name: 'KMSInternalException' });
      }
      return kms.send(cmd as never);
    }) as typeof kms.send,
  };
  const signer = kmsSigner({
    client,
    kmsKeys: { ed25519: FAKE_ED_KEY, mlDsa65: FAKE_PQ_KEY },
    keyIds: { ed25519: id('svc/evidence'), mlDsa65: id('svc/evidence:pq') },
  });
  return { state, signer, kms };
}

describe('P3.12-04 the hybrid signer never yields half a signature', () => {
  it('one KMS half fails: the error is clear and nothing is stored', async () => {
    const f = flakyKms();
    const w = await worldSignedBy(resilientSigner(f.signer, { attempts: 1, sleep: noSleep }));
    const before = await w.events.head(w.dealId);
    f.state.failPq = 1;
    const err = await w.events
      .appendOwn(w.dealId, () => inputFor(w, 'dispute.opened', { role: 'coordinator', keyId: '' }))
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(HybridSigningFailed);
    expect((err as Error).message).toMatch(/hybrid signing failed after 1 attempt\(s\): KMSInternalException/);
    expect(await w.events.head(w.dealId)).toEqual(before);
    expect(await w.events.list(w.dealId, -1, 10)).toHaveLength(0);
  });

  it('a transient failure is retried: the append succeeds once, with a complete pair', async () => {
    const f = flakyKms();
    let calls = 0;
    const counting: SignerPort = {
      publicKeys: () => f.signer.publicKeys(),
      signHybrid: (m, c) => {
        calls++;
        return f.signer.signHybrid(m, c);
      },
    };
    const w = await worldSignedBy(resilientSigner(counting, { attempts: 3, sleep: noSleep }));
    f.state.failPq = 2;
    await f.signer.publicKeys();
    const keys = await f.signer.publicKeys();
    const seq = await w.events.appendOwn(w.dealId, () =>
      inputFor(w, 'dispute.opened', { role: 'coordinator', keyId: '' }),
    );
    expect(seq.seq).toBe(0);
    expect(calls).toBe(3);
    const stored = await w.events.list(w.dealId, -1, 10);
    expect(stored).toHaveLength(1);
    const env = JSON.parse(new TextDecoder().decode(stored[0]?.envelope));
    expect(env.signatures.map((s: { keyid: string }) => s.keyid)).toEqual([keys.keyIds.ed25519, keys.keyIds.mlDsa65]);
  });

  it('backs off between tries and gives up after the limit with the last cause attached', async () => {
    const waits: number[] = [];
    const dead: SignerPort = {
      publicKeys: async () => await flakyKms().signer.publicKeys(),
      signHybrid: async () => {
        throw new Error('KMS down');
      },
    };
    const s = resilientSigner(dead, { attempts: 4, sleep: async (ms) => void waits.push(ms) });
    const e = (await s.signHybrid(new Uint8Array(1), 'legx/dsse/v1').catch((x: unknown) => x)) as HybridSigningFailed;
    expect(e).toBeInstanceOf(HybridSigningFailed);
    expect(e.attempts).toBe(4);
    expect((e.cause as Error).message).toBe('KMS down');
    expect(waits).toEqual([100, 200, 400]);
  });

  it('an inner signer that returns one half (or a short one) is refused, never passed on', async () => {
    const real = nodeSigner(generateNodeSignerKeys(id('a'), id('b')));
    const good = await real.signHybrid(new Uint8Array(3), 'legx/dsse/v1');
    for (const bad of [
      { ...good, mlDsa65: new Uint8Array(0) },
      { ...good, ed25519: undefined },
      { ...good, mlDsa65: good.mlDsa65.subarray(1) },
    ]) {
      const inner: SignerPort = {
        publicKeys: () => real.publicKeys(),
        signHybrid: async () => bad as unknown as HybridSignature,
      };
      await expect(
        resilientSigner(inner, { attempts: 2, sleep: noSleep }).signHybrid(new Uint8Array(3), 'legx/dsse/v1'),
      ).rejects.toThrow(/incomplete signature pair/);
    }
  });
});

describe('P3.12-08 ML-DSA key rotation', () => {
  it('new envelopes use the new key, old ones still verify, and the rotation is a recorded, verifiable event', async () => {
    const first = nodeSigner(generateNodeSignerKeys(id('svc/1'), id('svc/1:pq')));
    const second = nodeSigner(generateNodeSignerKeys(id('svc/2'), id('svc/2:pq')));
    const ring = await createKeyring(first, 0);
    const body = (n: number) =>
      new TextEncoder().encode(JSON.stringify({ predicate: { sig_algs: ['ed25519', 'ml-dsa-65'], n } }));
    const old = await signHybrid(PAYLOAD_TYPE, body(1), ring.signer);
    const recorded: Uint8Array[] = [];
    const record = await ring.rotate(second, 1000, async (b) => void recorded.push(b));
    expect(recorded).toEqual([record]);
    const fresh = await signHybrid(PAYLOAD_TYPE, body(2), ring.signer);

    const reg = ring.registry();
    expect(fresh.signatures.map((s) => s.keyid)).toEqual(['svc/2', 'svc/2:pq']);
    expect(verifyHybrid(old, reg, 500).ok).toBe(true); // signed before the rotation, checked at its own time
    expect(verifyHybrid(fresh, reg, 1500).ok).toBe(true);
    expect(verifyHybrid(old, reg, 1500)).toEqual({ ok: false, code: 'KEY_EXPIRED' }); // the old key signs nothing new
    expect(verifyHybrid(fresh, reg, 500)).toEqual({ ok: false, code: 'KEY_EXPIRED' });

    // The rotation event: one attestation by the old pair, one by the new pair, over the same payload.
    const { old: o, new: n } = JSON.parse(new TextDecoder().decode(record));
    expect(o.payload).toBe(n.payload);
    expect(verifyHybrid(o, reg, 1000).ok).toBe(true);
    expect(verifyHybrid(n, reg, 1000).ok).toBe(true);
    const said = JSON.parse(Buffer.from(o.payload, 'base64').toString());
    expect(said).toMatchObject({ type: 'legx/service-key-rotation/v1', effective_at: 1000 });
    expect(said.old.mldsa65_key_id).toBe('svc/1:pq');
    expect(said.new.mldsa65_key_id).toBe('svc/2:pq');
    expect(o.payloadType).toBe(ATTEST_PAYLOAD_TYPE);
    expect(ring.generations().map((g) => [g.validFrom, g.validTo])).toEqual([
      [0, 1000],
      [1000, undefined],
    ]);
  });

  it('a rotation that cannot be recorded changes nothing; reusing a key ID is refused; two rotations chain', async () => {
    const mk = (n: number) => nodeSigner(generateNodeSignerKeys(id(`k${n}`), id(`k${n}:pq`)));
    const ring = await createKeyring(mk(1), 0);
    await expect(ring.rotate(mk(2), 10, async () => Promise.reject(new Error('WORM down')))).rejects.toThrow(
      'WORM down',
    );
    expect(ring.generations()).toHaveLength(1);
    expect((await ring.signer.publicKeys()).keyIds.ed25519).toBe('k1');
    await expect(ring.rotate(mk(1), 10, async () => {})).rejects.toThrow(/already in use/);
    await ring.rotate(mk(2), 10, async () => {});
    await ring.rotate(mk(3), 20, async () => {});
    expect((await ring.signer.publicKeys()).keyIds.mlDsa65).toBe('k3:pq');
    const reg = ring.registry();
    const env = await signHybrid(
      PAYLOAD_TYPE,
      new TextEncoder().encode(JSON.stringify({ predicate: { sig_algs: ['ed25519', 'ml-dsa-65'] } })),
      ring.signer,
    );
    expect(verifyHybrid(env, reg, 25).ok).toBe(true);
    expect(ring.generations().map((g) => g.validTo)).toEqual([10, 20, undefined]);
  });

  it('a base registry (enrollment keys) is consulted first', async () => {
    const ring = await createKeyring(makeService('x').signer, 0);
    const base: KeyRegistry = (k) =>
      k === 'only-in-base'
        ? { alg: 'ed25519', publicKey: new Uint8Array(32), validFrom: 0, logged: true, pair: 'base' }
        : undefined;
    expect(ring.registry(base)('only-in-base')).toBeDefined();
    expect(ring.registry(base)('x')).toBeDefined();
    expect(ring.registry(base)('nope')).toBeUndefined();
  });
});

describe('P3.12-09 FileSigner (demo) behind the same hybrid path', () => {
  const dir = () => mkdtempSync(join(tmpdir(), 'legx-312-'));
  it('signs and verifies through the resilient wrapper and the real events module', async () => {
    const signer = resilientSigner(fileSigner(join(dir(), 'k.json'), { LEGX_PROFILE: 'demo' }));
    const keys = await signer.publicKeys();
    const w = await worldSignedBy(signer);
    const r = await w.events.appendOwn(w.dealId, () =>
      inputFor(w, 'dispute.opened', { role: 'coordinator', keyId: '' }),
    );
    expect(r.seq).toBe(0);
    expect(keys.ed25519).toHaveLength(32);
    expect(keys.mlDsa65).toHaveLength(1952);
  });
  it('refuses to start outside the demo profile (P3.6-02)', () => {
    for (const env of [{}, { LEGX_PROFILE: 'production' }, { LEGX_PROFILE: 'Demo' }]) {
      expect(() => fileSigner(join(dir(), 'k.json'), env)).toThrow(/demo-only/);
    }
  });
});

describe('P3.12-13 required algorithms are fixed in the verifier, per record type', () => {
  const party = makeParty('p13');
  const withAlgs = (algs: unknown) => new TextEncoder().encode(JSON.stringify({ predicate: { sig_algs: algs } }));
  const registry = async () => {
    const k = await party.signer.publicKeys();
    return (kid: string) =>
      kid === k.keyIds.ed25519
        ? { alg: 'ed25519' as const, publicKey: k.ed25519, validFrom: 0, logged: true, pair: 'p13' }
        : kid === k.keyIds.mlDsa65
          ? { alg: 'ml-dsa-65' as const, publicKey: k.mlDsa65, validFrom: 0, logged: true, pair: 'p13' }
          : undefined;
  };

  it('a record listing only ed25519, or an extra algorithm, is refused by the signer and by the verifier', async () => {
    for (const algs of [['ed25519'], ['ed25519', 'ml-dsa-65', 'slh-dsa'], ['ml-dsa-65', 'ed25519']]) {
      await expect(signHybrid(PAYLOAD_TYPE, withAlgs(algs), party.signer)).rejects.toThrow('SIG_ALGS_MISMATCH');
      // Forge the envelope anyway (sign the PAE by hand): the verifier's own table still refuses it.
      const body = withAlgs(algs);
      const good = await signHybrid(PAYLOAD_TYPE, withAlgs(['ed25519', 'ml-dsa-65']), party.signer);
      const forged = { ...good, payload: Buffer.from(body).toString('base64') };
      const v = verifyHybrid(forged, await registry(), 0);
      expect(v.ok).toBe(false);
    }
  });

  it('dropping the ML-DSA signature and rewriting sig_algs to match fails: the table, not the record, decides', async () => {
    const good = await signHybrid(PAYLOAD_TYPE, withAlgs(['ed25519', 'ml-dsa-65']), party.signer);
    const stripped = {
      ...good,
      signatures: good.signatures.slice(0, 1),
      payload: Buffer.from(withAlgs(['ed25519'])).toString('base64'),
    };
    expect(verifyHybrid(stripped, await registry(), 0)).toEqual({ ok: false, code: 'PQ_SIGNATURE_MISSING' });
  });

  it('an envelope of an unknown record type is refused', async () => {
    const good = await signHybrid(PAYLOAD_TYPE, withAlgs(['ed25519', 'ml-dsa-65']), party.signer);
    expect(verifyHybrid({ ...good, payloadType: 'application/x-unknown' }, await registry(), 0)).toEqual({
      ok: false,
      code: 'PAYLOAD_TYPE_UNKNOWN',
    });
  });
});
