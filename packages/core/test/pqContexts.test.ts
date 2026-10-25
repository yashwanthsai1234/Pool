// P1.16-15: every ML-DSA sign and verify in core passes an explicit context, and only the allowed ones are used.
// noble is replaced by spies that record each call. Node's ML-DSA is never called from core (servers: task 3.12).
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { KeyId } from '@legx/contracts/values';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';

const calls: { alg: string; op: string; context: string | undefined }[] = [];
vi.mock('@noble/post-quantum/ml-dsa.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('@noble/post-quantum/ml-dsa.js')>();
  const spy = (alg: string, a: typeof real.ml_dsa65) => ({
    ...a,
    sign: (msg: Uint8Array, sk: Uint8Array, opts?: { context?: Uint8Array }) => {
      calls.push({ alg, op: 'sign', context: opts?.context && new TextDecoder().decode(opts.context) });
      return a.sign(msg, sk, opts);
    },
    verify: (sig: Uint8Array, msg: Uint8Array, pk: Uint8Array, opts?: { context?: Uint8Array }) => {
      calls.push({ alg, op: 'verify', context: opts?.context && new TextDecoder().decode(opts.context) });
      return a.verify(sig, msg, pk, opts);
    },
  });
  return { ...real, ml_dsa44: spy('ml-dsa-44', real.ml_dsa44), ml_dsa65: spy('ml-dsa-65', real.ml_dsa65) };
});

const { ml_dsa44 } = await import('@noble/post-quantum/ml-dsa.js');
const { signHybrid, verifyHybrid } = await import('../src/hybridEnvelope.ts');
const pq = await import('../src/pq.ts');
const cpMod = await import('../src/pqCheckpoint.ts');

describe('P1.16-15 explicit ML-DSA contexts', () => {
  it('a full run of envelopes, bindings, checkpoints and renewals uses only the allowed contexts', async () => {
    const seed = (n: number) => new Uint8Array(32).fill(n);
    const k = pq.pqKeygen(seed(1));
    const edSk = seed(2);
    const signer = pq.nobleHybridSigner(
      { keyId: 'e' as KeyId, publicKey: ed25519.getPublicKey(edSk), sign: async (m) => ed25519.sign(m, edSk) },
      { keyId: 'p' as KeyId, secretKey: k.secretKey },
    );
    const body = utf8ToBytes(JSON.stringify({ sig_algs: ['ed25519', 'ml-dsa-65'] }));
    const env = await signHybrid('application/vnd.legx.attest+json;v=1', body, signer);
    const reg = (id: string) =>
      id === 'e'
        ? { alg: 'ed25519' as const, publicKey: ed25519.getPublicKey(edSk), validFrom: 0, logged: true, pair: 'p' }
        : { alg: 'ml-dsa-65' as const, publicKey: k.publicKey, validFrom: 0, logged: true, pair: 'p' };
    expect(verifyHybrid(env, reg, 1).ok).toBe(true);

    const holders = [3, 4, 5].map((n) => pq.pqKeygen(seed(n)));
    const hk = holders.map((h, i) => ({ keyId: `h${i}`, mlDsa65: h.publicKey })) as unknown as Parameters<
      typeof pq.verifyPqBinding
    >[2];
    const slotSk = seed(6);
    const slotPub = new Uint8Array([0xed, ...ed25519.getPublicKey(slotSk)]);
    const keyHash = pq.pqKeyHash([hk[0].mlDsa65, hk[1].mlDsa65, hk[2].mlDsa65]);
    const msg = pq.pqBindMsg(seed(7), slotPub, keyHash);
    const sigs = await Promise.all(
      holders.slice(0, 2).map((h, i) => pq.signPqBinding(msg, pq.nobleMlDsaSigner(`h${i}`, h.secretKey))),
    );
    const expected = { dealSeal: seed(7), slotPub, pqKeyHash: keyHash };
    const verifySlot = (p: Uint8Array, m: Uint8Array, s: Uint8Array) => ed25519.verify(s, m, p.subarray(1));
    expect(
      pq.verifyPqBinding(
        { ...expected, holderSigs: sigs, crossSig: ed25519.sign(msg, slotSk) },
        expected,
        hk,
        verifySlot,
      ),
    ).toEqual({ ok: true });

    const lk = ml_dsa44.keygen(seed(8));
    const keys = {
      ed: { name: 'o', publicKey: ed25519.getPublicKey(edSk) },
      pq: { name: 'o', publicKey: lk.publicKey },
    };
    const note = cpMod.signCheckpoint(
      { origin: 'o', treeSize: 1, rootHash: sha256(body) },
      { name: 'o', seed: edSk },
      { name: 'o', secretKey: lk.secretKey },
      1,
    );
    expect(cpMod.verifyCheckpoint(note, 'o', keys).ok).toBe(true);
    const rsig = await pq
      .nobleMlDsaSigner('r', k.secretKey)
      .sign(cpMod.renewalMsg(new Uint8Array(32), note), 'legx/checkpoint/v1');
    const st = cpMod.renewalStatement(new Uint8Array(32), note, rsig);
    expect(cpMod.verifyRenewalChain([st], [note], k.publicKey)).toEqual({ ok: true });

    expect(calls).toHaveLength(10); // 5 signs (envelope, 2 holders, checkpoint, renewal) and their 5 verifies
    for (const c of calls) {
      expect(c.context, JSON.stringify(c)).toBeDefined();
      if (c.alg === 'ml-dsa-44')
        expect(c.context).toBe(''); // C2SP 0x06 (P1.16-13)
      else expect(['legx/dsse/v1', 'legx/pq-binding/v1', 'legx/checkpoint/v1']).toContain(c.context);
    }
    expect(new Set(calls.map((c) => c.context))).toEqual(
      new Set(['legx/dsse/v1', 'legx/pq-binding/v1', 'legx/checkpoint/v1', '']),
    );
  });

  it('no source file calls noble ML-DSA directly except the wrapper in pq.ts, and none uses Node ML-DSA', () => {
    const src = join(dirname(fileURLToPath(import.meta.url)), '../src');
    for (const f of readdirSync(src).filter((x) => x.endsWith('.ts'))) {
      const text = readFileSync(join(src, f), 'utf8');
      expect(text, f).not.toMatch(/ml_dsa(44|65|87)\s*\.\s*(sign|verify|internal)/);
      expect(text, f).not.toMatch(/['"]ml-dsa-\d\d['"][^;]*\bcrypto\.(sign|verify)|createPublicKey/);
    }
    const pqText = readFileSync(join(src, 'pq.ts'), 'utf8');
    expect(pqText.match(/ALGS\[alg\]\.sign\(/g)).toHaveLength(1);
    expect(pqText.match(/\ba\.verify\(/g)).toHaveLength(1);
  });
});
