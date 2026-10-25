import type { ClockPort } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { verifyCheckpoint } from '@legx/core/pqCheckpoint';
import { generateNodeCheckpointKeys, nodeCheckpointSigner } from '@legx/signer/node';
import { bytesToHex } from '@noble/hashes/utils.js';
import { afterEach, describe, expect, it } from 'vitest';
import { inProcessLog } from '../src/inProcessLog.ts';
import { tesseraLog, tileIndexPath } from '../src/tesseraLog.ts';
import { startFakeTessera } from './helpers/fakeTessera.ts';
import { logContract } from './helpers/logContract.ts';
import { H0, naiveRoot, verifyConsistency, verifyInclusion } from './helpers/refTree.ts';

const clock: ClockPort = {
  now: async () => ({ ledgerIndex: 1, ledgerHash: '0'.repeat(64) as never, closeTime: 800_000_000 as never }),
};

logContract('in-process RFC 9162 tree', async () => {
  const signer = nodeCheckpointSigner(generateNodeCheckpointKeys('log-ed' as KeyId, 'log-pq' as KeyId));
  const origin = 'legx.example/log';
  const pub = await signer.publicKeys();
  return {
    log: inProcessLog({ origin, signer, clock }),
    origin,
    keys: { ed: { name: origin, publicKey: pub.ed25519 }, pq: { name: `${origin}-mldsa44`, publicKey: pub.mlDsa44 } },
  };
});

logContract('Tessera adapter on a fake tlog-tiles server', async () => {
  const fake = await startFakeTessera({ integrateDelayMs: 5 });
  return {
    log: tesseraLog({ baseUrl: fake.url, pollIntervalMs: 2 }),
    origin: fake.origin,
    keys: fake.keys,
    close: fake.close,
  };
});

describe('tile paths (C2SP tlog-tiles)', () => {
  it.each([
    [0, '000'],
    [67, '067'],
    [999, '999'],
    [1000, 'x001/000'],
    [1234067, 'x001/x234/067'],
  ])('index %d is %s', (n, path) => expect(tileIndexPath(n)).toBe(path));
});

describe('Tessera adapter, beyond the contract', () => {
  const closers: (() => Promise<void>)[] = [];
  afterEach(async () => {
    await Promise.all(closers.splice(0).map((c) => c()));
  });
  const start = async (o?: Parameters<typeof startFakeTessera>[0]) => {
    const f = await startFakeTessera(o);
    closers.push(f.close);
    return f;
  };

  it('waits for integration: add returns only once a checkpoint covers the entry', async () => {
    const f = await start({ integrateDelayMs: 60 });
    const log = tesseraLog({ baseUrl: f.url, pollIntervalMs: 5 });
    const { index } = await log.add(new Uint8Array([1]));
    expect((await log.checkpoint()).treeSize).toBe(index + 1);
    expect(f.requests.filter((r) => r === 'GET /checkpoint').length).toBeGreaterThan(1);
  });

  it('times out when the sidecar never integrates', async () => {
    const f = await start({ integrateDelayMs: 60_000 });
    const log = tesseraLog({ baseUrl: f.url, pollIntervalMs: 5, integrateTimeoutMs: 100 });
    await expect(log.add(new Uint8Array([1]))).rejects.toThrow(/not integrated/);
  });

  it('reads multi-level tiles: 66,000 leaves need a level-2 partial tile and partial tiles at levels 0 and 1', async () => {
    const f = await start();
    const log = tesseraLog({ baseUrl: f.url });
    f.seed(66_000);
    const cp = await log.checkpoint();
    expect(cp.treeSize).toBe(66_000);
    const inc = await log.inclusionProof(65_999, 66_000);
    const seeded = (i: number) => H0(Uint8Array.of(i & 255, (i >> 8) & 255, (i >> 16) & 255));
    expect(verifyInclusion(65_999, 66_000, seeded(65_999), inc, cp.rootHash)).toBe(true);
    expect(verifyInclusion(0, 66_000, seeded(0), await log.inclusionProof(0, 66_000), cp.rootHash)).toBe(true);
    expect(f.requests.some((r) => r.startsWith('GET /tile/2/000.p/1'))).toBe(true);
    expect(f.requests.some((r) => /GET \/tile\/0\/257\.p\/208/.test(r))).toBe(true);
    const old = bytesToHex(naiveRoot(Array.from({ length: 65_536 }, (_, i) => seeded(i))));
    const proof = await log.consistencyProof(65_536, 66_000);
    expect(verifyConsistency(65_536, 66_000, old, cp.rootHash, proof)).toBe(true);
  }, 60_000);

  it('falls back to the full tile when the sidecar has deleted the partial tile', async () => {
    const f = await start({ deletePartialTiles: true });
    const log = tesseraLog({ baseUrl: f.url });
    f.seed(300);
    // 300 leaves: tile 0 is full, tile 1 is partial (44 wide) and is not deleted yet. Asking for an older size whose
    // partial tile no longer exists must use the full tile.
    await expect(log.inclusionProof(10, 200)).resolves.toBeInstanceOf(Array);
    expect(f.requests.some((r) => r === 'GET /tile/0/000.p/200')).toBe(true);
    expect(f.requests.some((r) => r === 'GET /tile/0/000')).toBe(true);
  });

  it('refuses tiles that do not hash to the checkpoint (a lying sidecar)', async () => {
    const f = await start();
    const log = tesseraLog({ baseUrl: f.url });
    for (let i = 0; i < 5; i++) await log.add(new Uint8Array([i]));
    f.tamper.tileByte = true;
    await expect(log.inclusionProof(1, 5)).rejects.toThrow(/do not hash to the checkpoint/);
  });

  it('refuses a checkpoint root that the tiles contradict', async () => {
    const f = await start();
    const log = tesseraLog({ baseUrl: f.url });
    for (let i = 0; i < 5; i++) await log.add(new Uint8Array([i]));
    f.tamper.checkpointRoot = new Uint8Array(32).fill(1);
    await expect(log.inclusionProof(1, 5)).rejects.toThrow(/do not hash to the checkpoint/);
  });

  it('rejects malformed /add and /checkpoint responses', async () => {
    const mk = (add: string, cp: string) =>
      tesseraLog({
        baseUrl: 'http://x',
        fetch: (async (u: string) =>
          u.endsWith('/add') ? new Response(add) : new Response(cp)) as unknown as typeof fetch,
      });
    await expect(mk('not a number', '').add(new Uint8Array(1))).rejects.toThrow(/add/);
    await expect(mk('-1', '').add(new Uint8Array(1))).rejects.toThrow(/add/);
    await expect(mk('0', 'origin\nabc\nAAAA\n').checkpoint()).rejects.toThrow(/malformed/);
    await expect(mk('0', 'origin\n1\nAAAA\n').checkpoint()).rejects.toThrow(/malformed/);
  });

  it('surfaces a sidecar error', async () => {
    const log = tesseraLog({
      baseUrl: 'http://x',
      fetch: (async () => new Response('boom', { status: 500 })) as unknown as typeof fetch,
    });
    await expect(log.add(new Uint8Array(1))).rejects.toThrow(/500/);
    await expect(log.checkpoint()).rejects.toThrow(/500/);
  });
});

// I-7: a stock Tessera signs Ed25519 only; the adapter adds the ML-DSA-44 (0x06) cosignature line.
describe('Tessera 0x06 cosignature', () => {
  const setup = async () => {
    const fake = await startFakeTessera({ edOnly: true });
    const signer = nodeCheckpointSigner(generateNodeCheckpointKeys('c-ed' as KeyId, 'c-pq' as KeyId));
    const pub = await signer.publicKeys();
    const name = `${fake.origin}-mldsa44`;
    const keys = { ed: fake.keys.ed, pq: { name, publicKey: pub.mlDsa44 } };
    return { fake, signer, name, keys };
  };

  it('without a cosigner the note has no 0x06 line and the hybrid verifier refuses it', async () => {
    const { fake, keys } = await setup();
    const cp = await tesseraLog({ baseUrl: fake.url }).checkpoint();
    expect(verifyCheckpoint(cp.note, fake.origin, keys)).toEqual({ ok: false, code: 'PQ_LINE_MISSING' });
  });

  it('with a cosigner the hybrid verifier accepts it, at the ledger close time', async () => {
    const { fake, signer, name, keys } = await setup();
    const log = tesseraLog({ baseUrl: fake.url, cosign: { signer, name, clock } });
    await log.add(new Uint8Array([1]));
    const cp = await log.checkpoint();
    const r = verifyCheckpoint(cp.note, fake.origin, keys);
    expect(r).toMatchObject({ ok: true, treeSize: 1, timestamp: 800_000_000 + 946_684_800 });
  });

  it('a tampered root is still refused after cosigning', async () => {
    const { fake, signer, name, keys } = await setup();
    const log = tesseraLog({ baseUrl: fake.url, cosign: { signer, name, clock } });
    await log.add(new Uint8Array([1]));
    const note = (await log.checkpoint()).note.replace(/\n[A-Za-z0-9+/=]{44}\n/, `\n${'A'.repeat(43)}=\n`);
    expect(verifyCheckpoint(note, fake.origin, keys).ok).toBe(false);
  });
});
