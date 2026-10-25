// P3.12-05, P3.12-10, P3.12-12: the hybrid checkpoint job, the both-lines policy, and the 0x06 context against a second
// implementation (Cloudflare's Rust verifier). Tessera signs only an Ed25519 line, so that is what the job starts from.
// Source: https://c2sp.org/tlog-checkpoint, https://c2sp.org/tlog-cosignature@v1.1.0, https://c2sp.org/signed-note
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Ed25519NoteVerifier, initSync, MlDsa44NoteVerifier, Note, VerifierList } from '@cloudflare/signed-note-wasm';
import type { Checkpoint, CheckpointSignerPort, TransparencyLogPort } from '@legx/contracts/ports';
import { KeyId } from '@legx/contracts/values';
import { toBase64 } from '@legx/core/pq';
import { type CheckpointKeys, checkpointText, noteKeyId, verifyCheckpoint, vkey } from '@legx/core/pqCheckpoint';
import { generateNodeCheckpointKeys, nodeCheckpointSigner } from '@legx/signer/node';
import { inProcessLog } from '@legx/storage/inProcessLog';
import { concatBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { createLogService } from '../../src/log.ts';
import {
  cosignCheckpoint,
  defaultNames,
  hybridCheckpointLog,
  InconsistentCheckpoint,
  QUEUE_CHECKPOINT,
  registerCheckpointJob,
} from '../../src/pq/index.ts';
import { memoryJobs } from '../helpers/memoryJobs.ts';
import { makeWorld } from '../helpers/world.ts';

initSync({
  module: readFileSync(createRequire(import.meta.url).resolve('@cloudflare/signed-note-wasm/signed_note_wasm_bg.wasm')),
});

const ORIGIN = 'legx.test/pq-checkpoint';
const names = defaultNames(ORIGIN);
const CLOSE = 814_000_000;
const clock = { now: async () => ({ ledgerIndex: 1, ledgerHash: '0'.repeat(64) as never, closeTime: CLOSE as never }) };

function ours() {
  const signer = nodeCheckpointSigner(generateNodeCheckpointKeys(KeyId.parse('ck-ed'), KeyId.parse('ck-pq')));
  return signer;
}
async function keysOf(signer: CheckpointSignerPort, origin = ORIGIN): Promise<CheckpointKeys> {
  const p = await signer.publicKeys();
  const n = defaultNames(origin);
  return { ed: { name: n.ed25519, publicKey: p.ed25519 }, pq: { name: n.mlDsa44, publicKey: p.mlDsa44 } };
}

/** What a Tessera sidecar serves: the body and one Ed25519 line under its own key, no ML-DSA line. */
function tesseraNote(cp: Checkpoint, name = ORIGIN): { note: string; vk: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(12));
  const text = checkpointText({
    origin: cp.origin,
    treeSize: cp.treeSize,
    rootHash: Uint8Array.from(Buffer.from(cp.rootHash, 'hex')),
  });
  const sig = new Uint8Array(sign(null, Buffer.from(text), privateKey));
  return {
    note: `${text}\n— ${name} ${toBase64(concatBytes(noteKeyId(name, 0x01, raw), sig))}\n`,
    vk: vkey(name, 0x01, raw),
  };
}
const asTessera = (inner: TransparencyLogPort): TransparencyLogPort => ({
  ...inner,
  checkpoint: async () => {
    const cp = await inner.checkpoint();
    return { ...cp, note: tesseraNote(cp).note };
  },
});

async function logWith(n: number) {
  const plain = nodeCheckpointSigner(generateNodeCheckpointKeys(KeyId.parse('p-ed'), KeyId.parse('p-pq')));
  const log = inProcessLog({ origin: ORIGIN, signer: plain, clock });
  for (let i = 0; i < n; i++) await log.add(new TextEncoder().encode(`leaf ${i}`));
  return log;
}
const lineOf = (note: string, mark: string) =>
  note
    .slice(note.lastIndexOf('\n\n') + 2)
    .split('\n')
    .filter(Boolean)
    .filter((l) => l.startsWith(mark));
const textOf = (note: string) => note.slice(0, note.lastIndexOf('\n\n') + 1);

describe('P3.12-05 the hybrid checkpoint job (closes I-7)', () => {
  it('a Tessera-style note (Ed25519 line only) gets our 0x01 and 0x06 lines; both verify', async () => {
    const signer = ours();
    const cp = await (await logWith(5)).checkpoint();
    const tess = tesseraNote(cp).note;
    expect(verifyCheckpoint(tess, ORIGIN, await keysOf(signer))).toEqual({ ok: false, code: 'ED_LINE_MISSING' });
    const note = await cosignCheckpoint(tess, { signer, closeTime: CLOSE });
    expect(verifyCheckpoint(note, ORIGIN, await keysOf(signer))).toMatchObject({ ok: true, treeSize: 5 });
    expect(lineOf(note, `— ${names.mlDsa44} `)).toHaveLength(1);
  });

  it('is idempotent: a complete note comes back unchanged, so a repeat after a crash is a no-op', async () => {
    const signer = ours();
    const cp = await (await logWith(3)).checkpoint();
    const once = await cosignCheckpoint(tesseraNote(cp).note, { signer, closeTime: CLOSE });
    expect(await cosignCheckpoint(once, { signer, closeTime: CLOSE })).toBe(once);
  });

  it('keeps another cosigner line and replaces a stale line of ours', async () => {
    const signer = ours();
    const cp = await (await logWith(3)).checkpoint();
    const t = tesseraNote(cp, 'other.example/witness');
    const once = await cosignCheckpoint(t.note, { signer, closeTime: CLOSE });
    expect(once).toContain('— other.example/witness ');
    // Tamper with our 0x06 line: the next run signs again instead of trusting it.
    const [pqLine] = lineOf(once, `— ${names.mlDsa44} `) as [string];
    const broken = once.replace(pqLine, `${pqLine.slice(0, -8)}AAAAAAA=`);
    expect(verifyCheckpoint(broken, ORIGIN, await keysOf(signer)).ok).toBe(false);
    const fixed = await cosignCheckpoint(broken, { signer, closeTime: CLOSE });
    expect(verifyCheckpoint(fixed, ORIGIN, await keysOf(signer)).ok).toBe(true);
    expect(fixed).toContain('— other.example/witness ');
  });

  it('refuses text that is not a checkpoint', async () => {
    await expect(cosignCheckpoint('hello\n', { signer: ours(), closeTime: CLOSE })).rejects.toThrow();
    await expect(cosignCheckpoint('a\nx\nAAAA\n\n', { signer: ours(), closeTime: CLOSE })).rejects.toThrow();
  });

  it('the 0x06 timestamp is the ledger close_time, not the wall clock', async () => {
    const signer = ours();
    const cp = await (await logWith(2)).checkpoint();
    const note = await cosignCheckpoint(tesseraNote(cp).note, { signer, closeTime: CLOSE });
    const r = verifyCheckpoint(note, ORIGIN, await keysOf(signer));
    expect(r.ok && r.timestamp).toBe(CLOSE + 946_684_800); // Ripple epoch 2000-01-01 to POSIX
  });

  it('hybridCheckpointLog wraps a log that serves Tessera-style notes; proofs and add pass through', async () => {
    const signer = ours();
    const inner = await logWith(6);
    const log = hybridCheckpointLog(asTessera(inner), { signer, clock, previous: async () => undefined });
    expect((await log.add(new TextEncoder().encode('more'))).index).toBe(6);
    const cp = await log.checkpoint();
    expect(cp.treeSize).toBe(7);
    expect(verifyCheckpoint(cp.note, ORIGIN, await keysOf(signer)).ok).toBe(true);
    expect(await log.inclusionProof(0, 7)).toEqual(await inner.inclusionProof(0, 7));
  });

  it('refuses to cosign a tree that does not extend the last one (a lying sidecar); allows growth and a repeat', async () => {
    const signer = ours();
    const prev = await (await logWith(4)).checkpoint();
    const wrap = (inner: TransparencyLogPort) =>
      hybridCheckpointLog(asTessera(inner), {
        signer,
        clock,
        previous: async () => ({ treeSize: prev.treeSize, rootHash: prev.rootHash }),
      });
    const history = async (leaves: string[]) => {
      const log = inProcessLog({ origin: ORIGIN, signer: ours(), clock });
      for (const l of leaves) await log.add(new TextEncoder().encode(l));
      return log;
    };
    expect((await wrap(await logWith(6)).checkpoint()).treeSize).toBe(6); // grows from the same history
    expect((await wrap(await logWith(4)).checkpoint()).treeSize).toBe(4); // a repeat
    await expect(wrap(await history(['x', 'y', 'z', 'w', 'v'])).checkpoint()).rejects.toBeInstanceOf(
      InconsistentCheckpoint,
    );
    await expect(wrap(await history(['x', 'y', 'z', 'w'])).checkpoint()).rejects.toThrow(/same size/);
    await expect(wrap(await logWith(2)).checkpoint()).rejects.toThrow(/shrank/);
  });

  it('the job: a crash after the WORM copy and before the anchor row repeats cleanly with the first note kept', async () => {
    const w = await makeWorld();
    const signer = ours();
    const log = hybridCheckpointLog(w.log, { signer, clock: w.clock, previous: async () => undefined });
    const svc = createLogService({ db: w.db, log, objects: w.objects, retainDays: 3650, head: w.events.head });
    await w.enroll('alice', 'A');
    const anchors = w.db.repos.checkpointAnchors;
    const insert = anchors.insert.bind(anchors);
    let crash = true;
    anchors.insert = async (c) => {
      if (crash) {
        crash = false;
        throw new Error('crash before the anchor row');
      }
      return insert(c);
    };
    const jobs = memoryJobs();
    await registerCheckpointJob(jobs.jobs, () => svc.checkpoint());
    expect(jobs.schedules).toEqual([{ queue: QUEUE_CHECKPOINT, cron: '*/10 * * * *' }]);
    await jobs.jobs.send(QUEUE_CHECKPOINT, {});
    await jobs.drain();
    expect(jobs.failures).toHaveLength(1);
    const row = await anchors.latest();
    const note = new TextDecoder().decode(row?.checkpoint);
    expect(verifyCheckpoint(note, w.origin, await keysOf(signer, w.origin)).ok).toBe(true);
    const { checkpointKey } = await import('../../src/log.ts');
    expect(await w.objects.get(checkpointKey(row?.tree_size as number, row?.root as string))).toEqual(row?.checkpoint);
  });
});

describe('P3.12-10 our verifier needs BOTH lines; a standard signed-note verifier does not', () => {
  const standard = (note: string, edVk: string, pqVk: string) => {
    const list = new VerifierList();
    list.addEd25519(new Ed25519NoteVerifier(edVk));
    list.addMlDsa44(new MlDsa44NoteVerifier(pqVk));
    list.build();
    const r = Note.fromBytes(new TextEncoder().encode(note)).verify(list);
    return [r.verified_count, r.unverified_count];
  };

  async function setup() {
    const signer = ours();
    const cp = await (await logWith(9)).checkpoint();
    const note = await cosignCheckpoint(tesseraNote(cp).note, { signer, closeTime: CLOSE });
    const keys = await keysOf(signer);
    return {
      note,
      keys,
      edVk: vkey(names.ed25519, 0x01, keys.ed.publicKey),
      pqVk: vkey(names.mlDsa44, 0x06, keys.pq.publicKey),
    };
  }

  it('strip 0x06, strip 0x01, alter the 0x06 signature: ours rejects each and names the line', async () => {
    const { note, keys, edVk, pqVk } = await setup();
    const [ed] = lineOf(note, `— ${names.ed25519} `) as [string];
    const [pq] = lineOf(note, `— ${names.mlDsa44} `) as [string];
    const body = textOf(note);
    expect(verifyCheckpoint(`${body}\n${ed}\n`, ORIGIN, keys)).toEqual({ ok: false, code: 'PQ_LINE_MISSING' });
    expect(verifyCheckpoint(`${body}\n${pq}\n`, ORIGIN, keys)).toEqual({ ok: false, code: 'ED_LINE_MISSING' });
    const flipped = Buffer.from(pq.split(' ')[2] as string, 'base64');
    flipped[flipped.length - 1] = (flipped[flipped.length - 1] as number) ^ 1;
    const altered = `${body}\n${ed}\n— ${names.mlDsa44} ${flipped.toString('base64')}\n`;
    expect(verifyCheckpoint(altered, ORIGIN, keys)).toEqual({ ok: false, code: 'PQ_SIGNATURE_INVALID' });
    // The standard verifier is happy with the stripped-0x06 note (it only needs the line it knows): that is the hole.
    expect(standard(`${body}\n${ed}\n`, edVk, pqVk)).toEqual([1, 0]);
    expect(standard(note, edVk, pqVk)).toEqual([2, 0]);
  });

  it('P3.12-12: our 0x06 line (empty ML-DSA context) verifies in the Rust implementation', async () => {
    const { note, edVk, pqVk } = await setup();
    const list = new VerifierList();
    list.addMlDsa44(new MlDsa44NoteVerifier(pqVk));
    list.build();
    expect(Note.fromBytes(new TextEncoder().encode(note)).verify(list).verified_count).toBe(1);
    expect(edVk).toContain(ORIGIN);
  });
});
