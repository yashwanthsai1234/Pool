// Hybrid checkpoints (DESIGN 6.13, 8.2): C2SP line 0x01 (Ed25519) and line 0x06 (timestamped ML-DSA-44 cosignature
// over the binary CosignedSubtree), both required. T-U-26, P1.16-05, P1.16-06, P1.16-13, and the renewal chain P1.16-10.
// Source: https://c2sp.org/tlog-checkpoint, https://c2sp.org/tlog-cosignature, https://c2sp.org/signed-note
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Ed25519NoteVerifier, initSync, MlDsa44NoteVerifier, Note, VerifierList } from '@cloudflare/signed-note-wasm';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { fromRipple } from '../src/fees.ts';
import { fromBase64Strict, mldsaSign, nobleMlDsaSigner, pqKeygen, toBase64 } from '../src/pq.ts';
import {
  type CheckpointKeys,
  checkpointText,
  cosignedSubtree,
  noteKeyId,
  renewalMsg,
  renewalStatement,
  signCheckpoint,
  verifyCheckpoint,
  verifyRenewalChain,
  vkey,
} from '../src/pqCheckpoint.ts';
import { VECTORS } from './helpers/vectors.ts';

initSync({
  module: readFileSync(createRequire(import.meta.url).resolve('@cloudflare/signed-note-wasm/signed_note_wasm_bg.wasm')),
});

const seed = (n: number) => new Uint8Array(32).fill(n);
const ORIGIN = 'legx.dev/log/test';
const edSeed = seed(21);
const pqKey = ml_dsa44.keygen(seed(22));
const keys: CheckpointKeys = {
  ed: { name: ORIGIN, publicKey: ed25519.getPublicKey(edSeed) },
  pq: { name: ORIGIN, publicKey: pqKey.publicKey },
};
const signers = { ed: { name: ORIGIN, seed: edSeed }, pq: { name: ORIGIN, secretKey: pqKey.secretKey } };
const CLOSE = 814_000_000; // a validated ledger close_time (Ripple epoch)
const cp = { origin: ORIGIN, treeSize: 13, rootHash: sha256(utf8ToBytes('root')) };
const note = signCheckpoint(cp, signers.ed, signers.pq, CLOSE);
const fails = (code: string) => ({ ok: false, code });
const lines = (n: string) =>
  n
    .slice(n.lastIndexOf('\n\n') + 2)
    .split('\n')
    .filter(Boolean);
const textOf = (n: string) => n.slice(0, n.lastIndexOf('\n\n') + 1);

describe('T-U-26a hybrid checkpoint', () => {
  it('both lines verify', () => {
    expect(note.startsWith(checkpointText(cp))).toBe(true);
    expect(lines(note)).toHaveLength(2);
    expect(verifyCheckpoint(note, ORIGIN, keys)).toEqual({
      ok: true,
      origin: ORIGIN,
      treeSize: 13,
      rootHash: cp.rootHash,
      timestamp: fromRipple(CLOSE),
    });
  });

  it('tree size 0 and a large tree size', () => {
    for (const treeSize of [0, 2 ** 40]) {
      const n = signCheckpoint({ ...cp, treeSize }, signers.ed, signers.pq, CLOSE);
      expect(verifyCheckpoint(n, ORIGIN, keys).ok).toBe(true);
    }
  });
});

describe('T-U-26b one changed byte fails', () => {
  const [edLine, pqLine] = lines(note) as [string, string];
  const text = textOf(note);
  const withLines = (...ls: string[]) => `${text}\n${ls.map((l) => `${l}\n`).join('')}`;
  const mutateBlob = (line: string, at: number) => {
    const sp = line.lastIndexOf(' ');
    const blob = fromBase64Strict(line.slice(sp + 1)) as Uint8Array;
    blob[at] = (blob[at] as number) ^ 1;
    return `${line.slice(0, sp)} ${toBase64(blob)}`;
  };

  it('in the note body', () => {
    expect(verifyCheckpoint(note.replace('\n13\n', '\n14\n'), ORIGIN, keys)).toEqual(fails('ED_SIGNATURE_INVALID'));
    const otherRoot = toBase64(sha256(utf8ToBytes('other')));
    expect(verifyCheckpoint(note.replace(toBase64(cp.rootHash), otherRoot), ORIGIN, keys).ok).toBe(false);
  });

  it('in either signature', () => {
    expect(verifyCheckpoint(withLines(mutateBlob(edLine, 10), pqLine), ORIGIN, keys)).toEqual(
      fails('ED_SIGNATURE_INVALID'),
    );
    expect(verifyCheckpoint(withLines(edLine, mutateBlob(pqLine, 100)), ORIGIN, keys)).toEqual(
      fails('PQ_SIGNATURE_INVALID'),
    );
    // The timestamp is signed too.
    expect(verifyCheckpoint(withLines(edLine, mutateBlob(pqLine, 11)), ORIGIN, keys)).toEqual(
      fails('PQ_SIGNATURE_INVALID'),
    );
  });

  it('in either key ID (the line becomes an unknown key, so the required line is missing)', () => {
    expect(verifyCheckpoint(withLines(mutateBlob(edLine, 0), pqLine), ORIGIN, keys)).toEqual(fails('ED_LINE_MISSING'));
    expect(verifyCheckpoint(withLines(edLine, mutateBlob(pqLine, 3)), ORIGIN, keys)).toEqual(fails('PQ_LINE_MISSING'));
  });
});

describe('T-U-26c both lines are required (no setting allows one)', () => {
  const [edLine, pqLine] = lines(note) as [string, string];
  const text = textOf(note);
  it('the 0x06 line stripped, or the 0x01 line stripped', () => {
    expect(verifyCheckpoint(`${text}\n${edLine}\n`, ORIGIN, keys)).toEqual(fails('PQ_LINE_MISSING'));
    expect(verifyCheckpoint(`${text}\n${pqLine}\n`, ORIGIN, keys)).toEqual(fails('ED_LINE_MISSING'));
    expect(verifyCheckpoint.length).toBe(3); // note, origin, keys: there is no options argument
  });

  it('the 0x01 line is verified strictly: the identity-key forgery that ZIP-215 accepts fails', () => {
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const forged = new Uint8Array(64);
    forged[0] = 1;
    const weakKeys = { ...keys, ed: { name: ORIGIN, publicKey: identity } };
    const line = `\u2014 ${ORIGIN} ${toBase64(concatBytes(noteKeyId(ORIGIN, 0x01, identity), forged))}`;
    expect(verifyCheckpoint(`${text}\n${line}\n${pqLine}\n`, ORIGIN, weakKeys)).toEqual(fails('ED_SIGNATURE_INVALID'));
  });

  it('lines in the other order, and an unknown cosigner line, are fine', () => {
    expect(verifyCheckpoint(`${text}\n${pqLine}\n${edLine}\n`, ORIGIN, keys).ok).toBe(true);
    const stranger = `— witness.example/w9 ${toBase64(new Uint8Array(76))}`;
    expect(verifyCheckpoint(`${text}\n${edLine}\n${stranger}\n${pqLine}\n`, ORIGIN, keys).ok).toBe(true);
  });

  it('a duplicated line, another origin, extension lines and hostile notes are refused', () => {
    expect(verifyCheckpoint(`${text}\n${edLine}\n${edLine}\n${pqLine}\n`, ORIGIN, keys)).toEqual(
      fails('DUPLICATE_LINE'),
    );
    expect(verifyCheckpoint(note, 'legx.dev/log/other', keys)).toEqual(fails('ORIGIN_MISMATCH'));
    const ext = `${text}extra line\n\n${edLine}\n${pqLine}\n`;
    expect(verifyCheckpoint(ext, ORIGIN, keys)).toEqual(fails('EXTENSION_LINES'));
    const hostile = [
      '',
      text,
      `${text}\n`,
      note.replaceAll('\n', '\r\n'),
      note.slice(0, -1),
      note.replace('— ', '-- '),
      note.replace(ORIGIN, `${ORIGIN}\u0001`),
      note.replace('\n13\n', '\n013\n'),
      note.replace('\n13\n', '\n-1\n'),
      note.replace('\n13\n', '\n99999999999999999999\n'),
      note.replace(toBase64(cp.rootHash), toBase64(cp.rootHash.subarray(1))),
      `${text}\n${edLine.slice(0, -2)}\n${pqLine}\n`,
      `${text}\n${'— x QUFBQQ==\n'.repeat(40)}${edLine}\n${pqLine}\n`,
      `${text}\n— ${ORIGIN} QUFB\n${pqLine}\n`,
    ];
    for (const h of hostile) {
      expect(verifyCheckpoint(h, ORIGIN, keys).ok, JSON.stringify(h.slice(-40))).toBe(false);
    }
  });
});

describe('P1.16-05 C2SP 0x06 line format', () => {
  const pqLine = lines(note)[1] as string;
  it('is "— <name> base64(keyID(4) || timestamp(8) || signature)" with the spec key ID', () => {
    expect(pqLine.startsWith(`— ${ORIGIN} `)).toBe(true);
    const blob = fromBase64Strict(pqLine.slice(pqLine.lastIndexOf(' ') + 1)) as Uint8Array;
    expect(blob).toHaveLength(4 + 8 + 2420);
    const id = sha256(concatBytes(utf8ToBytes(ORIGIN), Uint8Array.of(0x0a, 0x06), pqKey.publicKey)).subarray(0, 4);
    expect(bytesToHex(blob.subarray(0, 4))).toBe(bytesToHex(id));
    expect(bytesToHex(noteKeyId(ORIGIN, 0x06, pqKey.publicKey))).toBe(bytesToHex(id));
    // The timestamp is the ledger close_time in POSIX seconds, never Date.now().
    expect(new DataView(blob.buffer, blob.byteOffset + 4, 8).getBigUint64(0)).toBe(BigInt(fromRipple(CLOSE)));
  });

  it('the key ID of the signed-note document example (0x01) and its vkey', () => {
    const doc = readFileSync(`${VECTORS}/pq/c2sp/signed-note-example.txt`, 'utf8');
    const v = /^vkey: (.+)$/m.exec(doc)?.[1] as string;
    expect(v).toBe('example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k');
    const pub = (fromBase64Strict(v.split('+')[2] as string) as Uint8Array).subarray(1);
    expect(bytesToHex(noteKeyId('example.com/foo', 0x01, pub))).toBe('530d903a');
    expect(vkey('example.com/foo', 0x01, pub)).toBe(v);
  });

  it('the CosignedSubtree layout (tlog-cosignature): label, name, timestamp, origin, start, end, hash', () => {
    const m = cosignedSubtree('c', 5n, 'o', 0n, 13n, new Uint8Array(32).fill(7));
    const want = concatBytes(
      utf8ToBytes('subtree/v1\n\0'),
      Uint8Array.of(1, 0x63),
      Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 5),
      Uint8Array.of(1, 0x6f),
      new Uint8Array(8),
      Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 13),
      new Uint8Array(32).fill(7),
    );
    expect(bytesToHex(m)).toBe(bytesToHex(want));
    expect(() => cosignedSubtree('', 0n, 'o', 0n, 1n, new Uint8Array(32))).toThrow();
    expect(() => cosignedSubtree('x'.repeat(256), 0n, 'o', 0n, 1n, new Uint8Array(32))).toThrow();
    expect(() => cosignedSubtree('c', 0n, 'o', 0n, 1n, new Uint8Array(31))).toThrow();
  });

  it('a 0x06 signature over the note text (instead of the CosignedSubtree) fails', () => {
    const ts = new Uint8Array(8);
    new DataView(ts.buffer).setBigUint64(0, BigInt(fromRipple(CLOSE)));
    const overText = mldsaSign('ml-dsa-44', pqKey.secretKey, utf8ToBytes(textOf(note)), '');
    const line = `— ${ORIGIN} ${toBase64(concatBytes(noteKeyId(ORIGIN, 0x06, pqKey.publicKey), ts, overText))}`;
    expect(verifyCheckpoint(`${textOf(note)}\n${lines(note)[0]}\n${line}\n`, ORIGIN, keys)).toEqual(
      fails('PQ_SIGNATURE_INVALID'),
    );
  });

  it('a Go-made checkpoint (transparency-dev/formats, filippo.io/mldsa) verifies: 0x01 log line + 0x06 cosigner line', () => {
    const policy = Buffer.from(
      /^policy_b64: (.+)$/m.exec(readFileSync(`${VECTORS}/pq/c2sp/ml-dsa.txt`, 'utf8'))?.[1] as string,
      'base64',
    ).toString();
    const goNote = Buffer.from(
      /^checkpoint_b64: (.+)$/m.exec(
        readFileSync(`${VECTORS}/pq/c2sp/ml-dsa-counted-by-go.txt`, 'utf8'),
      )?.[1] as string,
      'base64',
    ).toString();
    const pick = (re: RegExp) => {
      // vkey = name + hex ID + base64, and base64 may itself contain '+'.
      const [, name, b64] = /^([^+]+)\+[0-9a-f]{8}\+(.+)$/.exec(re.exec(policy)?.[1] as string) as unknown as [
        string,
        string,
        string,
      ];
      return { name, publicKey: (fromBase64Strict(b64) as Uint8Array).subarray(1) };
    };
    const goKeys = { ed: pick(/^log (\S+)$/m), pq: pick(/^witness m1 (\S+)$/m) };
    const r = verifyCheckpoint(goNote, 'example.com/ledgers/acme', goKeys);
    expect(r.ok && [r.treeSize, r.timestamp]).toEqual([13, 1792108800]);
  });

  it('refuses a close_time that is not a non-negative integer', () => {
    expect(() => signCheckpoint(cp, signers.ed, signers.pq, -1)).toThrow();
    expect(() => signCheckpoint(cp, signers.ed, signers.pq, 1.5)).toThrow();
  });
});

describe('P1.16-06 / P1.16-13 a second implementation: @cloudflare/signed-note-wasm (Rust, cloudflare/azul)', () => {
  const verifyWith = (n: string, edV: boolean, pqV: boolean) => {
    const list = new VerifierList();
    if (edV) list.addEd25519(new Ed25519NoteVerifier(vkey(ORIGIN, 0x01, keys.ed.publicKey)));
    if (pqV) list.addMlDsa44(new MlDsa44NoteVerifier(vkey(ORIGIN, 0x06, keys.pq.publicKey)));
    list.build();
    const r = Note.fromBytes(utf8ToBytes(n)).verify(list);
    return [r.verified_count, r.unverified_count];
  };
  const [edLine, pqLine] = lines(note) as [string, string];

  it('P1.16-06: the 0x01 line verifies; with the 0x06 line stripped the standard verifier STILL passes', () => {
    expect(verifyWith(note, true, false)).toEqual([1, 1]);
    expect(verifyWith(`${textOf(note)}\n${edLine}\n`, true, true)).toEqual([1, 0]);
    expect(verifyCheckpoint(`${textOf(note)}\n${edLine}\n`, ORIGIN, keys)).toEqual(fails('PQ_LINE_MISSING'));
  });

  it('P1.16-13 CHECK resolved: our 0x06 line (empty ML-DSA context) verifies in the Rust implementation', () => {
    expect(verifyWith(note, false, true)).toEqual([1, 1]);
    expect(verifyWith(note, true, true)).toEqual([2, 0]);
    expect(verifyWith(`${textOf(note)}\n${pqLine}\n`, false, true)).toEqual([1, 0]);
  });

  it('P1.16-13 golden line: the committed note verifies in ours and in the Rust implementation', () => {
    const golden = readFileSync(`${VECTORS}/pq/legx-checkpoint-golden.txt`, 'utf8');
    expect(verifyCheckpoint(golden, ORIGIN, keys)).toMatchObject({ ok: true, timestamp: fromRipple(CLOSE) });
    expect(verifyWith(golden, true, true)).toEqual([2, 0]);
    // Ed25519 is deterministic: re-signing reproduces the golden 0x01 line byte for byte.
    expect(lines(golden)[0]).toBe(edLine);
  });

  it('the Rust verifier rejects a 0x06 line signed under a non-empty context: the empty context is the interoperable one', () => {
    const ts = new Uint8Array(8);
    new DataView(ts.buffer).setBigUint64(0, BigInt(fromRipple(CLOSE)));
    const m = cosignedSubtree(ORIGIN, BigInt(fromRipple(CLOSE)), ORIGIN, 0n, 13n, cp.rootHash);
    const sig = ml_dsa44.sign(m, pqKey.secretKey, { context: utf8ToBytes('legx/checkpoint/v1') });
    const line = `— ${ORIGIN} ${toBase64(concatBytes(noteKeyId(ORIGIN, 0x06, pqKey.publicKey), ts, sig))}`;
    expect(() => verifyWith(`${textOf(note)}\n${line}\n`, false, true)).toThrow();
    expect(verifyCheckpoint(`${textOf(note)}\n${edLine}\n${line}\n`, ORIGIN, keys)).toEqual(
      fails('PQ_SIGNATURE_INVALID'),
    );
  });
});

describe('property: checkpoints round trip, and a flipped bit anywhere fails', () => {
  it('random sizes and roots', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.nat(),
        (treeSize, rootHash, at) => {
          const n = signCheckpoint({ origin: ORIGIN, treeSize, rootHash }, signers.ed, signers.pq, CLOSE);
          if (!verifyCheckpoint(n, ORIGIN, keys).ok) return false;
          const b = utf8ToBytes(n);
          const i = at % b.length;
          const bad = new TextDecoder().decode(Uint8Array.from(b, (x, j) => (j === i ? x ^ 1 : x)));
          return !verifyCheckpoint(bad, ORIGIN, keys).ok;
        },
      ),
      { numRuns: 25 },
    );
  }, 60_000); // ML-DSA signing is about 10 ms a run, slower under coverage
});

describe('P1.16-10 RFC 4998 style renewal statements', () => {
  const pq = pqKeygen(seed(31));
  const signer = nobleMlDsaSigner('evidence-service', pq.secretKey);
  const notes = [0, 1, 2].map((i) => signCheckpoint({ ...cp, treeSize: 13 + i }, signers.ed, signers.pq, CLOSE + i));
  const build = async () => {
    const out = [];
    let prev: Uint8Array = new Uint8Array(32);
    for (const n of notes) {
      const st = renewalStatement(prev, n, await signer.sign(renewalMsg(prev, n), 'legx/checkpoint/v1'));
      out.push(st);
      prev = st.hash;
    }
    return out;
  };

  it('is pure: the same inputs give the same statement', async () => {
    const sig = await signer.sign(renewalMsg(new Uint8Array(32), notes[0] as string), 'legx/checkpoint/v1');
    const a = renewalStatement(new Uint8Array(32), notes[0] as string, sig);
    const b = renewalStatement(new Uint8Array(32), notes[0] as string, sig);
    expect(bytesToHex(a.hash)).toBe(bytesToHex(b.hash));
    expect(bytesToHex(a.checkpointHash)).toBe(bytesToHex(sha256(utf8ToBytes(notes[0] as string))));
  });

  it('each statement chains to the previous one, and a broken chain fails', async () => {
    const chain = await build();
    expect(verifyRenewalChain(chain, notes, pq.publicKey)).toEqual({ ok: true });
    expect(
      verifyRenewalChain([chain[0], chain[2]] as typeof chain, [notes[0], notes[2]] as string[], pq.publicKey),
    ).toEqual(fails('CHAIN_BROKEN'));
    expect(verifyRenewalChain(chain.slice(1), notes.slice(1), pq.publicKey)).toEqual(fails('CHAIN_BROKEN'));
    expect(verifyRenewalChain(chain, [notes[0], notes[2], notes[1]] as string[], pq.publicKey)).toEqual(
      fails('CHECKPOINT_MISMATCH'),
    );
    expect(verifyRenewalChain(chain, notes.slice(0, 2), pq.publicKey)).toEqual(fails('CHECKPOINT_MISMATCH'));
    const forged = chain.map((s, i) => (i === 1 ? { ...s, hash: new Uint8Array(32) } : s));
    expect(verifyRenewalChain(forged, notes, pq.publicKey)).toEqual(fails('HASH_MISMATCH'));
    expect(verifyRenewalChain(chain, notes, pqKeygen(seed(32)).publicKey)).toEqual(fails('SIG_INVALID'));
  });

  it('hostile statements and keys give typed errors, never a throw', async () => {
    const chain = await build();
    const broken = [{ ...chain[0], prevHash: undefined }] as unknown as typeof chain;
    expect(verifyRenewalChain(broken, notes.slice(0, 1), pq.publicKey)).toEqual(fails('MALFORMED'));
    const badKeys = { ...keys, ed: { name: ORIGIN, publicKey: undefined } } as unknown as CheckpointKeys;
    expect(verifyCheckpoint(note, ORIGIN, badKeys)).toEqual(fails('MALFORMED'));
    expect(() => renewalMsg(new Uint8Array(31), note)).toThrow();
  });

  it('a renewal signature made under another context (legx/dsse/v1) fails', async () => {
    const prev = new Uint8Array(32);
    const n = notes[0] as string;
    const st = renewalStatement(prev, n, await signer.sign(renewalMsg(prev, n), 'legx/dsse/v1'));
    expect(verifyRenewalChain([st], [n], pq.publicKey)).toEqual(fails('SIG_INVALID'));
  });
});
