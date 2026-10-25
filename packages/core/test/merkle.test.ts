// T-U-12 consistency vectors (transparency-dev/merkle testdata) and P1.13-03 (inclusion and consistency, sizes 1 to 64).
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, inclusionPath, mth, verifyInclusion } from '../src/dealcore.ts';
import { consistencyProof, verifyConsistency } from '../src/merkle.ts';
import { readJson, VECTORS } from './helpers/vectors.ts';

const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
// The testdata trees are prefixes of the eight RFC 6962 reference leaves (transparency-dev/merkle testonly).
const LEAVES = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map(
  hexToBytes,
);
const leavesOf = (n: number) => Array.from({ length: n }, (_, i) => new Uint8Array([i, i >> 8, 7]));

describe('T-U-12 transparency-dev consistency vectors', () => {
  type Vec = {
    size1: number;
    size2: number;
    root1: string;
    root2: string;
    proof: string[] | null;
    desc: string;
    wantErr: boolean;
  };
  const files = readdirSync(join(VECTORS, 'merkle', 'consistency'), { recursive: true, encoding: 'utf8' }).filter((f) =>
    f.endsWith('.json'),
  );
  const cases = files.map((f) => ({ f, ...readJson<Vec>('merkle', 'consistency', f) }));

  it('has the 98 vectors of the pinned commit', () => expect(cases.length).toBe(98));

  it('verifyConsistency accepts every happy-path vector and rejects every wantErr vector', () => {
    for (const c of cases) {
      const ok = verifyConsistency(c.size1, c.size2, b64(c.root1), b64(c.root2), (c.proof ?? []).map(b64));
      expect(ok, `${c.f} (${c.desc})`).toBe(!c.wantErr);
    }
  });

  it('our generator reproduces the proof of every happy-path vector (the additional/ ones carry made-up roots)', () => {
    const happy = cases.filter((c) => !c.wantErr && !c.f.startsWith('additional') && c.size2 <= 8);
    expect(happy.length).toBeGreaterThan(4);
    for (const c of happy) {
      const tree = LEAVES.slice(0, c.size2);
      expect(consistencyProof(c.size1, tree).map(bytesToHex), c.f).toEqual(
        (c.proof ?? []).map((p) => bytesToHex(b64(p))),
      );
      expect(bytesToHex(mth(tree.slice(0, c.size1))), c.f).toBe(bytesToHex(b64(c.root1)));
    }
  });
});

describe('P1.13-03 inclusion and consistency proofs for sizes 1 to 64', () => {
  it('every inclusion proof verifies, and a wrong index or leaf fails', () => {
    for (let n = 1; n <= 64; n++) {
      const leaves = leavesOf(n);
      const root = mth(leaves);
      for (let i = 0; i < n; i++) {
        const path = inclusionPath(i, leaves);
        expect(verifyInclusion(leaves[i]!, i, n, path, root), `n=${n} i=${i}`).toBe(true);
        expect(
          verifyInclusion(leaves[i]!, (i + 1) % n === i ? n : (i + 1) % n, n, path, root),
          `wrong index n=${n} i=${i}`,
        ).toBe(false);
        expect(verifyInclusion(new Uint8Array([9, 9]), i, n, path, root)).toBe(false);
      }
    }
  });

  it('every consistency proof between two sizes up to 64 verifies, and swapped roots or a bad proof fail', () => {
    const all = leavesOf(64);
    for (let n = 1; n <= 64; n++) {
      const rootN = mth(all.slice(0, n));
      for (let m = 1; m <= n; m++) {
        const proof = consistencyProof(m, all.slice(0, n));
        const rootM = mth(all.slice(0, m));
        expect(verifyConsistency(m, n, rootM, rootN, proof), `${m}->${n}`).toBe(true);
        if (m < n) {
          expect(verifyConsistency(m, n, rootN, rootM, proof), `swapped ${m}->${n}`).toBe(false);
          expect(verifyConsistency(m, n, rootM, rootN, [...proof, rootM]), `extra ${m}->${n}`).toBe(false);
          expect(verifyConsistency(m, n, rootM, rootN, proof.slice(1)), `short ${m}->${n}`).toBe(false);
        }
      }
    }
  });

  it('a rewritten history is not consistent (a changed old leaf)', () => {
    fc.assert(
      fc.property(fc.integer({ min: 2, max: 40 }), fc.integer({ min: 1, max: 40 }), fc.nat(), (n, extra, pick) => {
        const old = leavesOf(n);
        const m = n,
          size2 = n + extra;
        const evil = leavesOf(size2);
        evil[pick % n] = new Uint8Array([0xff]);
        const proof = consistencyProof(m, evil);
        expect(verifyConsistency(m, size2, mth(old), mth(evil), proof)).toBe(false);
      }),
      { numRuns: 100 },
    );
  });

  it('refuses malformed input without throwing', () => {
    const t = leavesOf(5);
    expect(() => consistencyProof(6, t)).toThrow();
    expect(() => consistencyProof(-1, t)).toThrow();
    expect(verifyConsistency(3, 2, mth(t), mth(t), [])).toBe(false);
    expect(verifyConsistency(1.5, 5, mth(t), mth(t), [])).toBe(false);
    expect(verifyConsistency(0, 5, mth([]), mth(t), [])).toBe(false);
  });
});
