// P1.13-02 checkpoint as a C2SP signed note from the in-process log; P1.13-03 receipts; cross-check with
// @cloudflare/signed-note-wasm. The hybrid signing itself is task 1.16 (`pqCheckpoint.ts`).
// Source: https://c2sp.org/tlog-checkpoint, https://c2sp.org/signed-note, https://github.com/C2SP/C2SP/blob/main/tlog-proof.md
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Ed25519NoteVerifier, initSync, MlDsa44NoteVerifier, Note, VerifierList } from '@cloudflare/signed-note-wasm';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { describe, expect, it } from 'vitest';
import { createLog, type LogSigning, verifyReceipt } from '../src/checkpoint.ts';
import { mth, utf8ToBytes } from '../src/dealcore.ts';
import { verifyConsistency } from '../src/merkle.ts';
import { type CheckpointKeys, verifyCheckpoint, vkey } from '../src/pqCheckpoint.ts';

initSync({
  module: readFileSync(createRequire(import.meta.url).resolve('@cloudflare/signed-note-wasm/signed_note_wasm_bg.wasm')),
});

const ORIGIN = 'legx.dev/log/test';
const edSeed = new Uint8Array(32).fill(31);
const pq = ml_dsa44.keygen(new Uint8Array(32).fill(32));
const signing: LogSigning = {
  origin: ORIGIN,
  ed: { name: ORIGIN, seed: edSeed },
  pq: { name: ORIGIN, secretKey: pq.secretKey },
  closeTime: () => 814_000_000,
};
const keys: CheckpointKeys = {
  ed: { name: ORIGIN, publicKey: ed25519.getPublicKey(edSeed) },
  pq: { name: ORIGIN, publicKey: pq.publicKey },
};
const hexBytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

async function filled(n: number) {
  const log = createLog(signing);
  const leaves = Array.from({ length: n }, (_, i) => utf8ToBytes(`envelope-${i}`));
  for (const l of leaves) await log.add(l);
  return { log, leaves };
}

describe('P1.13-02 checkpoint as a signed note', { timeout: 60_000 }, () => {
  it('carries origin, size and root, and verifies through the hybrid verifier', async () => {
    const { log, leaves } = await filled(13);
    const cp = await log.checkpoint();
    expect(cp).toMatchObject({ origin: ORIGIN, treeSize: 13 });
    expect(cp.rootHash).toBe(Buffer.from(mth(leaves)).toString('hex'));
    expect(cp.note.split('\n').slice(0, 3)).toEqual([ORIGIN, '13', Buffer.from(mth(leaves)).toString('base64')]);
    expect(verifyCheckpoint(cp.note, ORIGIN, keys)).toMatchObject({ ok: true, treeSize: 13 });
  });

  it('every single byte changed in the note fails (sampled over the whole note)', async () => {
    const { log } = await filled(5);
    const note = (await log.checkpoint()).note;
    for (let i = 0; i < note.length; i += 7) {
      const bad = note.slice(0, i) + String.fromCharCode(note.charCodeAt(i) ^ 1) + note.slice(i + 1);
      expect(verifyCheckpoint(bad, ORIGIN, keys).ok, `byte ${i}`).toBe(false);
    }
    expect(verifyCheckpoint(note, 'other.dev/log', keys).ok).toBe(false);
  });

  it('@cloudflare/signed-note-wasm parses the note and verifies both lines', async () => {
    const { log } = await filled(9);
    const cp = await log.checkpoint();
    const list = new VerifierList();
    list.addEd25519(new Ed25519NoteVerifier(vkey(ORIGIN, 0x01, keys.ed.publicKey)));
    list.addMlDsa44(new MlDsa44NoteVerifier(vkey(ORIGIN, 0x06, keys.pq.publicKey)));
    list.build();
    const note = Note.fromBytes(utf8ToBytes(cp.note));
    expect(note.textString()).toBe(cp.note.slice(0, cp.note.lastIndexOf('\n\n') + 1));
    expect(note.verify(list).verified_count).toBe(2);
    const tampered = Note.fromBytes(utf8ToBytes(cp.note.replace('\n9\n', '\n8\n')));
    expect(() => tampered.verify(list)).toThrow();
  });
});

describe('the in-process log', () => {
  it('a duplicate leaf returns its first index and does not grow the tree; stored leaves are copies', async () => {
    const log = createLog(signing);
    const leaf = utf8ToBytes('a');
    expect(await log.add(leaf)).toEqual({ index: 0 });
    expect(await log.add(utf8ToBytes('b'))).toEqual({ index: 1 });
    expect(await log.add(utf8ToBytes('a'))).toEqual({ index: 0 });
    leaf[0] = 0;
    expect((await log.checkpoint()).treeSize).toBe(2);
    expect((await log.checkpoint()).rootHash).toBe(
      Buffer.from(mth([utf8ToBytes('a'), utf8ToBytes('b')])).toString('hex'),
    );
  });

  it('an empty log checkpoints at size 0 with the empty-tree root', async () => {
    const cp = await createLog(signing).checkpoint();
    expect(cp.treeSize).toBe(0);
    expect(cp.rootHash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('inclusion and consistency proofs from the port verify against signed checkpoints', async () => {
    const { log, leaves } = await filled(40);
    const old = mth(leaves.slice(0, 17));
    const cp = await log.checkpoint();
    const proof = await log.consistencyProof(17, 40);
    expect(verifyConsistency(17, 40, old, hexBytes(cp.rootHash), proof.map(hexBytes))).toBe(true);
    expect(verifyConsistency(17, 40, old, hexBytes(cp.rootHash), proof.slice(1).map(hexBytes))).toBe(false);
  });

  it('refuses sizes and indexes outside the tree', async () => {
    const { log } = await filled(4);
    await expect(log.inclusionProof(0, 5)).rejects.toThrow();
    await expect(log.inclusionProof(4, 4)).rejects.toThrow();
    await expect(log.inclusionProof(-1, 4)).rejects.toThrow();
    await expect(log.inclusionProof(0, 0)).rejects.toThrow();
    await expect(log.consistencyProof(5, 4)).rejects.toThrow();
    await expect(log.consistencyProof(1, 9)).rejects.toThrow();
  });
});

describe('P1.13-03 offline receipts', { timeout: 60_000 }, () => {
  it('every leaf of a 1 to 20 leaf log verifies against the checkpoint of that size, and a wrong index fails', async () => {
    for (let n = 1; n <= 20; n++) {
      const { log, leaves } = await filled(n);
      const cp = await log.checkpoint();
      for (let i = 0; i < n; i++) {
        const path = await log.inclusionProof(i, n);
        const r = { leaf: leaves[i]!, index: i, path, note: cp.note };
        expect(verifyReceipt(r, ORIGIN, keys).ok, `n=${n} i=${i}`).toBe(true);
        if (n > 1)
          expect(verifyReceipt({ ...r, index: (i + 1) % n }, ORIGIN, keys)).toEqual({
            ok: false,
            code: 'INCLUSION_FAILED',
          });
      }
    }
  });
  it('a wrong leaf, a wrong origin and a bad note fail', async () => {
    const { log, leaves } = await filled(6);
    const cp = await log.checkpoint();
    const r = { leaf: leaves[2]!, index: 2, path: await log.inclusionProof(2, 6), note: cp.note };
    expect(verifyReceipt({ ...r, leaf: utf8ToBytes('x') }, ORIGIN, keys)).toEqual({
      ok: false,
      code: 'INCLUSION_FAILED',
    });
    expect(verifyReceipt(r, 'elsewhere', keys)).toEqual({ ok: false, code: 'ORIGIN_MISMATCH' });
    expect(verifyReceipt({ ...r, note: 'junk' }, ORIGIN, keys).ok).toBe(false);
  });
});

describe('zero-knowledge trust anchor (DESIGN 6.10, T-U-32d)', () => {
  const files = new Map([['circuit-manifest.json', utf8ToBytes('{"v":1}')]]);
  const trust = { registryRoots: ['aa'] } as never;
  it('the trust root becomes a leaf of the next checkpoint with an inclusion proof; a changed file moves the root', async () => {
    const { zkCheckpointInput } = await import('../src/zkIdentity.ts');
    const { addZkTrustAnchor } = await import('../src/checkpoint.ts');
    const { log } = await filled(3);
    const { root } = zkCheckpointInput(trust, files);
    const { index } = await addZkTrustAnchor(log, root);
    expect(await addZkTrustAnchor(log, root)).toEqual({ index });
    const cp = await log.checkpoint();
    expect(cp.treeSize).toBe(4);
    const r = {
      leaf: utf8ToBytes(`legx/zk-trust-anchor/v1\n${root}`),
      index,
      path: await log.inclusionProof(index, 4),
      note: cp.note,
    };
    expect(verifyReceipt(r, ORIGIN, keys).ok).toBe(true);
    const other = zkCheckpointInput(trust, new Map([['circuit-manifest.json', utf8ToBytes('{"v":2}')]])).root;
    expect(other).not.toBe(root);
    expect(verifyReceipt({ ...r, leaf: utf8ToBytes(`legx/zk-trust-anchor/v1\n${other}`) }, ORIGIN, keys).ok).toBe(
      false,
    );
    expect(() => addZkTrustAnchor(log, 'xyz')).toThrow();
  });
});
