import { mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignCommand } from '@aws-sdk/client-kms';
import type { KeyId } from '@legx/contracts/values';
import { describe, expect, it } from 'vitest';
import { fileCheckpointSigner, fileSigner, generateNodeSignerKeys, kmsSigner, nodeSigner } from '../src/index.ts';
import { createFakeKms, FAKE_ED_KEY, FAKE_PQ_KEY } from './helpers/fakeKms.ts';
import { signerContract } from './helpers/signerContract.ts';

const id = (s: string) => s as KeyId;
const DEMO = { LEGX_PROFILE: 'demo' };
const dir = () => mkdtempSync(join(tmpdir(), 'legx-signer-'));
const kmsConfig = (client = createFakeKms()) => ({
  client,
  kmsKeys: { ed25519: FAKE_ED_KEY, mlDsa65: FAKE_PQ_KEY },
  keyIds: { ed25519: id('kms-ed-1'), mlDsa65: id('kms-pq-1') },
});

signerContract('NodeSigner', () => nodeSigner(generateNodeSignerKeys(id('n-ed'), id('n-pq'))));
signerContract('FileSigner', () => fileSigner(join(dir(), 'keys.json'), DEMO));
signerContract('KmsSigner (emulator)', () => kmsSigner(kmsConfig()));

describe('P3.6-02 FileSigner refuses to start unless the profile is demo', () => {
  it.each([
    {},
    { LEGX_PROFILE: 'production' },
    { LEGX_PROFILE: 'Demo' },
    { LEGX_PROFILE: 'demo ' },
    { LEGX_PROFILE: '' },
  ])('refuses with %j', (env) => {
    const path = join(dir(), 'keys.json');
    expect(() => fileSigner(path, env)).toThrow(/demo-only/);
    expect(() => fileCheckpointSigner(path, env)).toThrow(/demo-only/);
  });
  it('creates no key file when it refuses', () => {
    const path = join(dir(), 'keys.json');
    expect(() => fileSigner(path, {})).toThrow();
    expect(() => statSync(path)).toThrow();
  });
  it('starts with demo, writes the key file as 0600, and reloads the same keys', async () => {
    const path = join(dir(), 'keys.json');
    const first = await fileSigner(path, DEMO).publicKeys();
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(await fileSigner(path, DEMO).publicKeys()).toEqual(first);
  });
  it('rejects a key file with extra fields', async () => {
    const path = join(dir(), 'keys.json');
    fileSigner(path, DEMO);
    const { readFileSync, writeFileSync } = await import('node:fs');
    writeFileSync(path, JSON.stringify({ ...JSON.parse(readFileSync(path, 'utf8')), extra: 1 }));
    expect(() => fileSigner(path, DEMO)).toThrow();
  });
});

describe('KmsSigner against the emulator', () => {
  it('calls KMS with the documented algorithms: Ed25519 RAW, ML-DSA EXTERNAL_MU of exactly 64 bytes', async () => {
    const kms = createFakeKms();
    await kmsSigner(kmsConfig(kms)).signHybrid(new TextEncoder().encode('x'), 'legx/dsse/v1');
    const signs = kms.calls.filter((c) => c.type === 'Sign').map((c) => c.input);
    expect(signs).toHaveLength(2);
    expect(signs.find((i) => i.KeyId === FAKE_ED_KEY)).toMatchObject({
      MessageType: 'RAW',
      SigningAlgorithm: 'ED25519_SHA_512',
    });
    const pq = signs.find((i) => i.KeyId === FAKE_PQ_KEY);
    expect(pq).toMatchObject({ MessageType: 'EXTERNAL_MU', SigningAlgorithm: 'ML_DSA_SHAKE_256' });
    expect((pq?.Message as Uint8Array | undefined)?.length).toBe(64);
  });

  it('never sends the message itself to the ML-DSA key (only mu)', async () => {
    const kms = createFakeKms();
    const msg = new TextEncoder().encode('plain message that must not be the ML-DSA input');
    await kmsSigner(kmsConfig(kms)).signHybrid(msg, 'legx/dsse/v1');
    const pq = kms.calls.find((c) => c.type === 'Sign' && c.input.KeyId === FAKE_PQ_KEY);
    expect(pq?.input.Message).not.toEqual(msg);
  });

  it('fetches public keys once', async () => {
    const kms = createFakeKms();
    const s = kmsSigner(kmsConfig(kms));
    await s.publicKeys();
    await s.signHybrid(new Uint8Array(1), 'legx/dsse/v1');
    await s.publicKeys();
    expect(kms.calls.filter((c) => c.type === 'GetPublicKey')).toHaveLength(2); // one per key
  });

  it('PAE over 4096 bytes: fails as a whole before any Sign call (Ed25519 has no EXTERNAL_MU)', async () => {
    const kms = createFakeKms();
    await expect(kmsSigner(kmsConfig(kms)).signHybrid(new Uint8Array(4097), 'legx/dsse/v1')).rejects.toThrow(/4096/);
    expect(kms.calls.filter((c) => c.type === 'Sign')).toHaveLength(0);
  });

  it('rejects an ML-DSA signature that does not verify (wrong mu would otherwise pass unnoticed)', async () => {
    const kms = createFakeKms();
    kms.corruptNextMlDsa();
    await expect(kmsSigner(kmsConfig(kms)).signHybrid(new Uint8Array(3), 'legx/dsse/v1')).rejects.toThrow(/ML-DSA-65/);
  });

  it('fails as a whole when either KMS call fails, and returns no partial result', async () => {
    const kms = createFakeKms();
    const failing = {
      calls: kms.calls,
      send: ((c: unknown) =>
        c instanceof SignCommand && c.input.KeyId === FAKE_PQ_KEY
          ? Promise.reject(new Error('ThrottlingException'))
          : kms.send(c as never)) as typeof kms.send,
    };
    await expect(
      kmsSigner({ ...kmsConfig(), client: failing }).signHybrid(new Uint8Array(3), 'legx/dsse/v1'),
    ).rejects.toThrow(/Throttling/);
  });

  it('retries the public key fetch after a failure', async () => {
    const kms = createFakeKms();
    let first = true;
    const flaky = {
      send: ((c: unknown) => {
        if (first) {
          first = false;
          return Promise.reject(new Error('transient'));
        }
        return kms.send(c as never);
      }) as typeof kms.send,
    };
    const s = kmsSigner({ ...kmsConfig(), client: flaky });
    await expect(s.publicKeys()).rejects.toThrow('transient');
    await expect(s.publicKeys()).resolves.toMatchObject({ ed25519: expect.any(Uint8Array) });
  });

  it('rejects a public key with an unexpected encoding', async () => {
    const kms = createFakeKms();
    const bad = { send: (() => Promise.resolve({ PublicKey: new Uint8Array(44), $metadata: {} })) as typeof kms.send };
    await expect(kmsSigner({ ...kmsConfig(), client: bad }).publicKeys()).rejects.toThrow(/encoding/);
  });
});
