// P3.12-06 and P3.12-07: the RFC 4998 style renewal job. A real RFC 3161 client against a local authority (its own root,
// time-stamping EKU), the real local WORM store, a real hybrid signer, the real offline verifier.
// Source: https://www.rfc-editor.org/rfc/rfc4998#section-5.2 ; https://www.rfc-editor.org/rfc/rfc3161
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ObjectStorePort, SignerPort } from '@legx/contracts/ports';
import { KeyId } from '@legx/contracts/values';
import { createKeyring } from '@legx/evidence/pq/index';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { localObjectStore } from '@legx/storage/localStore';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { type LocalTsa, makeLocalTsa } from '../../evidence/test/helpers/localTsa.ts';
import {
  createRenewal,
  decodeRecord,
  encodeRecord,
  QUEUE_RENEWAL,
  RENEWAL_CRON,
  registerRenewalJob,
  renewalKey,
  type VerifyOptions,
  verifyRenewals,
} from '../src/index.ts';

const NOTE = (n: number) => `legx.test/log\n${n}\n${Buffer.alloc(32, n).toString('base64')}\n\n— legx.test/log AAAA\n`;
const id = (s: string) => KeyId.parse(s);
const store = () => localObjectStore({ dir: mkdtempSync(join(tmpdir(), 'legx-renewal-')) });
let tsa: LocalTsa;
const getTsa = async () => (tsa ??= await makeLocalTsa('renewal'));

async function setup(
  over: { signer?: SignerPort; objects?: ObjectStorePort; head?: () => Promise<string | undefined> } = {},
) {
  const local = await getTsa();
  const signer = over.signer ?? nodeSigner(generateNodeSignerKeys(id('r-ed'), id('r-pq')));
  const objects = over.objects ?? store();
  let head: string | undefined = NOTE(1);
  const svc = createRenewal({
    objects,
    retainDays: 3650,
    signer,
    tsa: local.client(),
    head: over.head ?? (async () => head),
  });
  const pub = await signer.publicKeys();
  const keys: VerifyOptions['keys'] = (k) =>
    k === pub.keyIds.ed25519
      ? { alg: 'ed25519', publicKey: pub.ed25519 }
      : k === pub.keyIds.mlDsa65
        ? { alg: 'ml-dsa-65', publicKey: pub.mlDsa65 }
        : undefined;
  return {
    svc,
    objects,
    signer,
    local,
    keys,
    opts: { keys, trustedRoots: [local.rootDer] } satisfies VerifyOptions,
    setHead: (n: string) => (head = n),
  };
}

describe('P3.12-06 the renewal job', () => {
  it('each run takes the current head, time-stamps it over the old record, stores it; the chain verifies offline; all records are kept', async () => {
    const t = await setup();
    expect(await t.svc.run('2026-10-24')).toMatchObject({ status: 'renewed', seq: 0 });
    t.setHead(NOTE(2));
    expect(await t.svc.run('2026-10-25')).toMatchObject({ status: 'renewed', seq: 1 });
    t.setHead(NOTE(3));
    expect(await t.svc.run('2026-10-26')).toMatchObject({ status: 'renewed', seq: 2 });

    const records = await t.svc.load();
    expect(records).toHaveLength(3);
    expect(await verifyRenewals(records, t.opts)).toMatchObject({ ok: true, count: 3 });
    // Old and new are all there, byte for byte (the WORM store keeps them).
    for (const [i, r] of records.entries()) expect(await t.objects.get(renewalKey(i))).toEqual(r);
    const [a, b, c] = records.map(decodeRecord) as [
      ReturnType<typeof decodeRecord>,
      ReturnType<typeof decodeRecord>,
      ReturnType<typeof decodeRecord>,
    ];
    expect(a.checkpoint).toBe(NOTE(1));
    expect(c.checkpoint).toBe(NOTE(3));
    expect(b.prev_hash).toBe(a.statement_hash);
    expect(c.prev_hash).toBe(b.statement_hash);
  });

  it('the time stamp covers the previous time stamp (RFC 4998 5.2): swapping an old token breaks the chain', async () => {
    const t = await setup();
    await t.svc.run('p1');
    t.setHead(NOTE(2));
    await t.svc.run('p2');
    const [r0, r1] = (await t.svc.load()).map(decodeRecord) as [
      ReturnType<typeof decodeRecord>,
      ReturnType<typeof decodeRecord>,
    ];
    // A record whose token is the first record's token (the right statement but the wrong stamp) fails.
    const swapped = encodeRecord({ ...r1, tsa: r0.tsa });
    expect(await verifyRenewals([encodeRecord(r0), swapped], t.opts)).toMatchObject({
      ok: false,
      seq: 1,
      code: 'TIMESTAMP_INVALID',
    });
  });

  it('is once per period: a repeat in the same period does nothing; no head means nothing to renew', async () => {
    const t = await setup();
    expect(await t.svc.run('d')).toMatchObject({ status: 'renewed' });
    expect(await t.svc.run('d')).toEqual({ status: 'already', seq: 0 });
    expect((await t.svc.load()).length).toBe(1);
    const none = await setup({ head: async () => undefined });
    expect(await none.svc.run('d')).toEqual({ status: 'no_head' });
    expect(await none.svc.load()).toHaveLength(0);
  });

  it('hostile chains are named: a dropped record, a reorder, a tampered note or signature, an unknown key, a wrong root', async () => {
    const t = await setup();
    for (let i = 1; i <= 3; i++) {
      t.setHead(NOTE(i));
      await t.svc.run(`p${i}`);
    }
    const rs = await t.svc.load();
    const rec = rs.map(decodeRecord);
    const code = async (list: Uint8Array[], o: VerifyOptions = t.opts) =>
      (await verifyRenewals(list, o)) as { ok: false; seq: number; code: string };
    expect(await code([rs[0] as Uint8Array, rs[2] as Uint8Array])).toMatchObject({ seq: 1, code: 'SEQ_GAP' });
    expect(await code([rs[1] as Uint8Array, rs[0] as Uint8Array])).toMatchObject({ seq: 0, code: 'SEQ_GAP' });
    expect(await code([encodeRecord({ ...rec[0]!, checkpoint: NOTE(9) })])).toMatchObject({
      code: 'STATEMENT_MISMATCH',
    });
    const flip = (b64: string) => {
      const x = Buffer.from(b64, 'base64');
      x[x.length - 1] = (x[x.length - 1] as number) ^ 1;
      return x.toString('base64');
    };
    expect(
      await code([encodeRecord({ ...rec[0]!, sig: { ...rec[0]!.sig, ed25519: flip(rec[0]!.sig.ed25519) } })]),
    ).toMatchObject({ code: 'ED_SIGNATURE_INVALID' });
    // A changed ML-DSA signature changes the statement hash first (it is part of it): named as such.
    expect(
      await code([encodeRecord({ ...rec[0]!, sig: { ...rec[0]!.sig, ml_dsa_65: flip(rec[0]!.sig.ml_dsa_65) } })]),
    ).toMatchObject({ code: 'STATEMENT_MISMATCH' });
    expect(await code(rs, { ...t.opts, keys: () => undefined })).toMatchObject({ seq: 0, code: 'KEY_UNKNOWN' });
    const other = await makeLocalTsa('some other authority');
    expect(await code(rs, { ...t.opts, trustedRoots: [other.rootDer] })).toMatchObject({
      code: 'TIMESTAMP_INVALID',
      detail: 'CHAIN_UNTRUSTED',
    });
    expect(await code([new TextEncoder().encode('{}')])).toMatchObject({ code: 'MALFORMED' });
    expect(await code([new Uint8Array([0xff, 0xfe])])).toMatchObject({ code: 'MALFORMED' });
    expect(await code([encodeRecord({ ...rec[0]!, extra: 1 } as never)])).toMatchObject({ code: 'MALFORMED' });
    expect(await verifyRenewals([], t.opts)).toEqual({ ok: true, count: 0 });
  });

  it('an optional checkpoint check runs on every embedded note', async () => {
    const t = await setup();
    await t.svc.run('p');
    const records = await t.svc.load();
    expect(await verifyRenewals(records, { ...t.opts, checkpointOk: () => false })).toMatchObject({
      code: 'CHECKPOINT_INVALID',
    });
  });

  it('the job registers a worker and a daily schedule; the handler renews once per period', async () => {
    const t = await setup();
    const handlers = new Map<string, (d: object) => Promise<void>>();
    const schedules: [string, string][] = [];
    await registerRenewalJob(
      {
        send: async () => {},
        work: async (q, h) => void handlers.set(q, h as never),
        schedule: async (q, c) => void schedules.push([q, c]),
      },
      t.svc,
      { periodOf: () => 'fixed' },
    );
    expect(schedules).toEqual([[QUEUE_RENEWAL, RENEWAL_CRON]]);
    await handlers.get(QUEUE_RENEWAL)?.({});
    await handlers.get(QUEUE_RENEWAL)?.({});
    expect((await t.svc.load()).length).toBe(1);
  });
});

describe('P3.12-08 the renewal chain across an ML-DSA key rotation', () => {
  it('records before the rotation keep verifying under the old key, later ones use the new key', async () => {
    const first = nodeSigner(generateNodeSignerKeys(id('rot-1'), id('rot-1:pq')));
    const second = nodeSigner(generateNodeSignerKeys(id('rot-2'), id('rot-2:pq')));
    const ring = await createKeyring(first, 0);
    const t = await setup({ signer: ring.signer });
    await t.svc.run('p1');
    await ring.rotate(second, 1000, async () => {});
    t.setHead(NOTE(2));
    await t.svc.run('p2');
    const records = await t.svc.load();
    const used = records.map((r) => decodeRecord(r).keys.ml_dsa_65);
    expect(used).toEqual(['rot-1:pq', 'rot-2:pq']);
    const gens = ring.generations();
    const keys: VerifyOptions['keys'] = (k) => {
      for (const g of gens) {
        if (k === g.keys.keyIds.ed25519) return { alg: 'ed25519', publicKey: g.keys.ed25519 };
        if (k === g.keys.keyIds.mlDsa65) return { alg: 'ml-dsa-65', publicKey: g.keys.mlDsa65 };
      }
      return undefined;
    };
    expect(await verifyRenewals(records, { ...t.opts, keys })).toMatchObject({ ok: true, count: 2 });
    // Without the old generation's keys the first record cannot be checked: the verifier needs every generation.
    const onlyNew: VerifyOptions['keys'] = (k) => (k.startsWith('rot-2') ? keys(k) : undefined);
    expect(await verifyRenewals(records, { ...t.opts, keys: onlyNew })).toMatchObject({ seq: 0, code: 'KEY_UNKNOWN' });
  });
});

describe('P3.12-07 renewal under an unreachable authority and crashes', () => {
  /** pg-boss's contract in miniature: a throw means "run it again". */
  async function untilDone(run: () => Promise<unknown>, limit = 60): Promise<number> {
    for (let n = 1; n <= limit; n++) {
      try {
        await run();
        return n;
      } catch {
        /* retried */
      }
    }
    throw new Error('never succeeded');
  }

  it('the authority is down: the run fails, nothing is written, the retry after recovery renews once', async () => {
    const t = await setup();
    t.local.behave.status = 503;
    await expect(t.svc.run('d')).rejects.toThrow(/HTTP 503/);
    await expect(t.svc.run('d')).rejects.toThrow();
    expect(await t.svc.load()).toHaveLength(0);
    t.local.behave.status = undefined;
    expect(await t.svc.run('d')).toMatchObject({ status: 'renewed', seq: 0 });
    expect(await t.svc.load()).toHaveLength(1);
  });

  it('a crash after the write (before the job is acknowledged): the retry finds the record and writes nothing more', async () => {
    const base = store();
    let crashAfterPut = true;
    const objects: ObjectStorePort = {
      ...base,
      put: async (k, b, d) => {
        const r = await base.put(k, b, d);
        if (crashAfterPut) {
          crashAfterPut = false;
          throw new Error('process died after the write');
        }
        return r;
      },
    };
    const t = await setup({ objects });
    await expect(t.svc.run('d')).rejects.toThrow('died');
    expect((await t.svc.run('d')).status).toBe('already');
    expect(await t.svc.load()).toHaveLength(1);
    expect(await verifyRenewals(await t.svc.load(), t.opts)).toMatchObject({ ok: true, count: 1 });
  });

  it('a crash before the write (after the time stamp): the retry renews once, the unused token is simply dropped', async () => {
    const base = store();
    let crash = true;
    const objects: ObjectStorePort = {
      ...base,
      put: async (k, b, d) => {
        if (crash) {
          crash = false;
          throw new Error('process died before the write');
        }
        return base.put(k, b, d);
      },
    };
    const t = await setup({ objects });
    await expect(t.svc.run('d')).rejects.toThrow();
    expect(await t.svc.load()).toHaveLength(0);
    expect(await t.svc.run('d')).toMatchObject({ status: 'renewed', seq: 0 });
    expect(await t.svc.load()).toHaveLength(1);
  });

  it('two workers at once: exactly one record per period, and it verifies', async () => {
    const t = await setup();
    const results = await Promise.all([t.svc.run('d'), t.svc.run('d'), t.svc.run('d')]);
    const renewed = results.filter((r) => r.status === 'renewed');
    expect(renewed).toHaveLength(1);
    expect(
      results.filter((r) => r.status !== 'renewed').every((r) => r.status === 'raced' || r.status === 'already'),
    ).toBe(true);
    expect(await verifyRenewals(await t.svc.load(), t.opts)).toMatchObject({ ok: true, count: 1 });
  });

  it('property: random failures of the authority and of the store, retried: one record per period, none lost, chain verifies', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 4 }),
        fc.array(fc.constantFrom('tsa', 'put-before', 'put-after', 'ok'), { minLength: 0, maxLength: 12 }),
        async (periods, faults) => {
          const base = store();
          const script = [...faults];
          const objects: ObjectStorePort = {
            ...base,
            put: async (k, b, d) => {
              const f = script[0];
              if (f === 'put-before') {
                script.shift();
                throw new Error('died before');
              }
              const r = await base.put(k, b, d);
              if (f === 'put-after') {
                script.shift();
                throw new Error('died after');
              }
              return r;
            },
          };
          const local = await getTsa();
          const signer = nodeSigner(generateNodeSignerKeys(id('pr-ed'), id('pr-pq')));
          const tsaClient = local.client();
          const svc = createRenewal({
            objects,
            retainDays: 1,
            signer,
            head: async () => NOTE(7),
            tsa: {
              timestamp: async (h) => {
                if (script[0] === 'tsa') {
                  script.shift();
                  throw new Error('authority down');
                }
                if (script[0] === 'ok') script.shift();
                return tsaClient.timestamp(h);
              },
            },
          });
          for (let p = 0; p < periods; p++) await untilDone(() => svc.run(`p${p}`));
          const records = await svc.load();
          const pub = await signer.publicKeys();
          const ok = await verifyRenewals(records, {
            trustedRoots: [local.rootDer],
            keys: (k) =>
              k === pub.keyIds.ed25519
                ? { alg: 'ed25519', publicKey: pub.ed25519 }
                : k === pub.keyIds.mlDsa65
                  ? { alg: 'ml-dsa-65', publicKey: pub.mlDsa65 }
                  : undefined,
          });
          expect(ok).toMatchObject({ ok: true, count: periods });
          expect(records.map((r) => decodeRecord(r).period)).toEqual(
            Array.from({ length: periods }, (_, i) => `p${i}`),
          );
        },
      ),
      { numRuns: 15 },
    );
  }, 120_000);
});
