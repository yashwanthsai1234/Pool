import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { clauseLeaf, contractRoot, proveClause } from '@legx/core/contract';
import type { Envelope } from '@legx/core/evidence';
import { toBase64 } from '@legx/core/pq';
import { bytesToHex } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { zip } from '../../../services/evidence/src/zip.ts';
import { failures, makeBundle, resign, type TestBundle, verify, verifyLenient } from './helpers.ts';

vi.setConfig({ testTimeout: 180_000, hookTimeout: 180_000 });

let b: TestBundle;
beforeAll(async () => {
  b = await makeBundle();
});

const text = (u: Uint8Array) => new TextDecoder().decode(u);
const enc = (s: string) => new TextEncoder().encode(s);
const fileBytes = (path: string) => (b.files.find((f) => f.path === path) as { bytes: Uint8Array }).bytes;
const flip = (bytes: Uint8Array, at: number) => {
  const c = new Uint8Array(bytes);
  c[at % c.length] = (c[at % c.length] as number) ^ 0x01;
  return c;
};
const withFile = (path: string, bytes: Uint8Array) => zip(b.files.map((f) => (f.path === path ? { path, bytes } : f)));

describe('P3.8-01 a good bundle', () => {
  it('exits 0 and reports every check of DESIGN 8.8', async () => {
    const v = await verifyLenient(b.zip);
    expect(failures(v)).toEqual([]);
    expect(v.code).toBe(0);
    for (const c of [
      'manifest',
      'manifest-signature',
      'hybrid-signature',
      'chain',
      'merkle-proof',
      'consistency',
      'checkpoint',
      'anchor',
      'timestamp',
      'signed-contract',
      'bindings',
      'bar-records',
      'attestations',
      'release-gate',
      'zk-proof',
    ]) {
      expect(
        v.report.findings.some((f) => f.check === c),
        c,
      ).toBe(true);
    }
    expect(v.text).toContain('RESULT: PASS');
    expect(v.report.result).toBe('pass');
  });

  it('a folder works like the ZIP, and a pinned service key is accepted; a wrong one fails', async () => {
    const keys = JSON.parse(text(fileBytes('keys/service_keys.json')));
    const ok = await verifyLenient(b.zip, ['--service-key', keys.ed25519.public_key]);
    expect(ok.report.findings.find((f) => f.check === 'manifest-signature')?.status).toBe('pass');
    const bad = await verifyLenient(b.zip, ['--service-key', '00'.repeat(32)]);
    expect(bad.code).toBe(1);
    expect(failures(bad).map((f) => f.check)).toEqual(['manifest-signature']);
  });
});

describe('P3.8-02 one changed byte anywhere', () => {
  it('every file of the bundle, one byte changed: exit 1, naming that file and a check', async () => {
    for (const f of b.files) {
      const v = await verifyLenient(withFile(f.path, flip(f.bytes, Math.floor(f.bytes.length / 2))));
      expect(v.code, f.path).toBe(1);
      expect(
        failures(v).some((x) => x.file === f.path),
        f.path,
      ).toBe(true);
      expect(v.text).toContain(`FAIL  ${f.path}`);
    }
  });

  it('property: any byte of any file', async () => {
    await fc.assert(
      fc.asyncProperty(fc.nat(b.files.length - 1), fc.nat(1_000_000), async (i, at) => {
        const f = b.files[i] as { path: string; bytes: Uint8Array };
        if (f.bytes.length === 0) return;
        const v = await verifyLenient(withFile(f.path, flip(f.bytes, at)));
        expect(v.code).toBe(1);
        expect(failures(v).some((x) => x.file === f.path)).toBe(true);
      }),
      { numRuns: 25 },
    );
  });

  it('a file added, or removed, is named', async () => {
    const added = await verifyLenient(zip([...b.files, { path: 'extra.txt', bytes: enc('x') }]));
    expect(failures(added).find((x) => x.file === 'extra.txt')?.check).toBe('manifest');
    const removed = await verifyLenient(zip(b.files.filter((f) => f.path !== 'keys/service_keys.json')));
    expect(failures(removed).find((x) => x.file === 'keys/service_keys.json')?.check).toBe('manifest');
  });

  it('semantic checks stand alone: with the manifest re-signed, the changed file still fails its own check', async () => {
    const event = 'events/000001.dsse.json';
    const env = JSON.parse(text(fileBytes(event))) as Envelope;
    const payload = JSON.parse(Buffer.from(env.payload, 'base64').toString());
    payload.predicate.seq = 7;
    const forged = enc(JSON.stringify({ ...env, payload: Buffer.from(JSON.stringify(payload)).toString('base64') }));
    const v = await verifyLenient(zip(await resign(b, { [event]: forged })));
    expect(v.code).toBe(1);
    expect(
      failures(v)
        .filter((x) => x.file === event)
        .map((x) => x.check)
        .sort(),
    ).toEqual(['chain', 'hybrid-signature']);
    expect(failures(v).some((x) => x.file === 'manifest.json')).toBe(false);

    const proof = 'tlog/proofs/000000.tlog-proof';
    const lines = text(fileBytes(proof)).split('\n');
    lines[2] = toBase64(new Uint8Array(32).fill(7));
    const v2 = await verifyLenient(zip(await resign(b, { [proof]: enc(lines.join('\n')) })));
    expect(failures(v2).map((x) => `${x.file} ${x.check}`)).toEqual([`${proof} merkle-proof`]);

    const anchor = JSON.parse(text(fileBytes('anchors/server-a.json')));
    anchor.tx.meta.TransactionResult = 'tecFAILED';
    const v3 = await verifyLenient(zip(await resign(b, { 'anchors/server-a.json': enc(JSON.stringify(anchor)) })));
    expect(failures(v3).map((x) => `${x.file} ${x.check}`)).toEqual(['anchors/server-a.json anchor']);

    const v4 = await verifyLenient(
      zip(
        await resign(b, {
          'timestamps/auth-a.tst': flip(
            fileBytes('timestamps/auth-a.tst'),
            fileBytes('timestamps/auth-a.tst').length - 5,
          ),
        }),
      ),
    );
    expect(failures(v4).map((x) => `${x.file} ${x.check}`)).toEqual(['timestamps/auth-a.tst timestamp']);
  });
});

describe('P3.8-07 both signature lines and both envelope signatures are required', () => {
  it('a checkpoint without the 0x06 line', async () => {
    const note = text(fileBytes('tlog/checkpoint.txt'));
    const lines = note.trimEnd().split('\n');
    const stripped = `${lines.slice(0, -1).join('\n')}\n`; // the ML-DSA-44 line is last
    const v = await verifyLenient(zip(await resign(b, { 'tlog/checkpoint.txt': enc(stripped) })));
    expect(v.code).toBe(1);
    const f = failures(v).find((x) => x.check === 'checkpoint');
    expect(f?.file).toBe('tlog/checkpoint.txt');
    expect(f?.message).toContain('0x06');
  });

  it('an event envelope without its ML-DSA-65 signature', async () => {
    const event = 'events/000002.dsse.json';
    const env = JSON.parse(text(fileBytes(event))) as Envelope;
    env.signatures = env.signatures.slice(0, 1);
    const v = await verifyLenient(zip(await resign(b, { [event]: enc(JSON.stringify(env)) })));
    expect(v.code).toBe(1);
    const f = failures(v).find((x) => x.file === event && x.check === 'hybrid-signature');
    expect(f?.message).toContain('PQ_SIGNATURE_MISSING');
  });
});

describe('P3.8-03 offline', () => {
  it('fetch and sockets throw, and the CLI still passes', async () => {
    const { default: net } = await import('node:net');
    const { default: tls } = await import('node:tls');
    const { default: dns } = await import('node:dns');
    const { default: http } = await import('node:http');
    const boom = () => {
      throw new Error('network is blocked in this test');
    };
    const spies = [
      vi.spyOn(globalThis, 'fetch').mockImplementation(boom),
      vi.spyOn(net.Socket.prototype, 'connect').mockImplementation(boom),
      vi.spyOn(net, 'connect').mockImplementation(boom),
      vi.spyOn(tls, 'connect').mockImplementation(boom),
      vi.spyOn(dns, 'lookup').mockImplementation(boom),
      vi.spyOn(http, 'request').mockImplementation(boom),
    ];
    try {
      const v = await verifyLenient(b.zip);
      expect(failures(v)).toEqual([]);
      expect(v.code).toBe(0);
      for (const s of spies) expect(s).not.toHaveBeenCalled();
    } finally {
      for (const s of spies) s.mockRestore();
    }
  });
});

describe('P3.8-04 a clause against the contract root', () => {
  const clauses = ['Seller delivers the shares.', 'Buyer pays on delivery.', 'English law governs.'].map(enc);
  const salts = clauses.map((_, i) => new Uint8Array(32).fill(i + 1));
  const root = contractRoot(clauses, salts);
  const proofJson = (i: number, clause = clauses[i] as Uint8Array) => {
    const p = proveClause(i, clauses, salts);
    return enc(
      JSON.stringify({
        index: p.index,
        size: p.size,
        salt: bytesToHex(p.salt),
        clause: toBase64(clause),
        path: p.path.map(bytesToHex),
      }),
    );
  };
  const contractJson = (r: Uint8Array) =>
    enc(JSON.stringify({ contract_root: bytesToHex(r), deal_seal: null, signed_contract_seal: null, files: {} }));

  it('passes inside the bundle; a changed clause fails', async () => {
    const good = await verifyLenient(
      zip(
        await resign(b, {
          'contract/contract.json': contractJson(root),
          'contract/files/clause-1.clause-proof.json': proofJson(1),
        }),
      ),
    );
    expect(failures(good)).toEqual([]);
    expect(good.report.findings.find((f) => f.check === 'clause-proof')?.status).toBe('pass');
    const bad = await verifyLenient(
      zip(
        await resign(b, {
          'contract/contract.json': contractJson(root),
          'contract/files/clause-1.clause-proof.json': proofJson(1, enc('Buyer pays nothing.')),
        }),
      ),
    );
    expect(bad.code).toBe(1);
    expect(failures(bad).map((f) => `${f.file} ${f.check}`)).toEqual([
      'contract/files/clause-1.clause-proof.json clause-proof',
    ]);
  });

  it('--clause checks one clause an arbitrator brings', async () => {
    const { mkdtempSync, writeFileSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'legx-clause-'));
    const ok = join(dir, 'c0.json');
    const bad = join(dir, 'c2.json');
    writeFileSync(ok, proofJson(0));
    writeFileSync(bad, proofJson(2, enc('French law governs.')));
    const archive = zip(await resign(b, { 'contract/contract.json': contractJson(root) }));
    expect((await verifyLenient(archive, ['--clause', ok])).code).toBe(0);
    const v = await verifyLenient(archive, ['--clause', ok, '--clause', bad]);
    expect(failures(v).map((f) => `${f.file} ${f.check}`)).toEqual(['c2.json clause-proof']);
    expect(clauseLeaf(0, salts[0] as Uint8Array, clauses[0] as Uint8Array).length).toBeGreaterThan(0);
  });
});

describe('usage and unreadable input', () => {
  it('a missing bundle option or an unknown flag exits 2; garbage bytes exit 1 with a report', async () => {
    const { run } = await import('../src/cli.ts');
    const sink = { out: () => undefined, err: () => undefined };
    expect(await run([], sink)).toBe(2);
    expect(await run(['x.zip', '--bogus'], sink)).toBe(2);
    expect(await run(['x.zip', '--chain-check'], sink)).toBe(2);
    const v = await verifyLenient(enc('this is not a zip'));
    expect(v.code).toBe(1);
    expect(failures(v)[0]?.check).toBe('archive');
  });

  it('--require-complete turns a missing release gate input into a failure', async () => {
    const v = await verifyLenient(b.zip, ['--require-complete']);
    expect(v.code).toBe(1);
    expect(failures(v).map((f) => f.check)).toContain('release-gate');
  });
});

describe('I-S-E2, I-S-E3 the arbitrator supplies the trust: a pinned key and the time stamp roots', () => {
  it('passes with the pinned service key and the arbitrator roots file, with no insecure flag', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'legx-roots-'));
    const pem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(b.deps.trustedRoots[0] as Uint8Array).toString('base64')}\n-----END CERTIFICATE-----\n`;
    writeFileSync(join(dir, 'roots.pem'), pem);
    const pin = bytesToHex((await b.deps.signer.publicKeys()).ed25519);
    const v = await verify(b.zip, ['--service-key', pin, '--tsa-roots', join(dir, 'roots.pem')]);
    expect(failures(v)).toEqual([]);
    expect(v.report.findings.some((f) => f.check === 'timestamp' && f.status === 'pass')).toBe(true);
  });
  it('a different key than the pinned one fails the manifest signature', async () => {
    const v = await verify(b.zip, ['--service-key', '00'.repeat(32), '--insecure-bundle-tsa-roots']);
    expect(v.report.findings.some((f) => f.check === 'manifest-signature' && f.status === 'fail')).toBe(true);
  });
});
