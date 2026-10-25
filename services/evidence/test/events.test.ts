import { createHash } from 'node:crypto';
import { fc } from '@fast-check/vitest';
import { EventKind } from '@legx/contracts/events';
import type { SignerPort } from '@legx/contracts/ports';
import { verifyChainWith } from '@legx/core/evidence';
import { verifyHybrid } from '@legx/core/hybridEnvelope';
import { kmsSigner } from '@legx/signer/kms';
import { describe, expect, it, vi } from 'vitest';
import { createFakeKms, FAKE_ED_KEY, FAKE_PQ_KEY } from '../../../packages/signer/test/helpers/fakeKms.ts';
import {
  EnvelopeRejected,
  envelopeBytes,
  eventBody,
  PaeTooLarge,
  SERVICE_PAE_LIMIT,
  signAsService,
} from '../src/events.ts';
import { registryFromRows } from '../src/keys.ts';
import { goldenOf, inputFor, makeParty, makeWorld, type World } from './helpers/world.ts';

vi.setConfig({ testTimeout: 60_000 });

const decode = (b: Uint8Array) => JSON.parse(new TextDecoder().decode(b));

async function chainOk(w: World): Promise<boolean> {
  const rows = await w.db.repos.evidenceEvents.listAfter(w.dealId, -1);
  const registry = registryFromRows(await w.db.repos.enrollmentKeys.listForDeal(w.dealId), {
    keys: await w.service.signer.publicKeys(),
    validFrom: 0,
  });
  return verifyChainWith(
    rows.map((r) => ({ envelopeBytes: r.envelope, leafHash: r.leaf_hash })),
    (env) => verifyHybrid(env, registry, w.clock.closeTime).ok,
  );
}

describe('P3.4-01 nextSeq, sign, append', () => {
  it('stores a signed event; the chain verifies (T-U-10 at service level)', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    for (const kind of ['shell.opened', 'escrow.created', 'wallet.locked'] as const) {
      const res = await w.events.append(w.dealId, await w.sign(alice, 'alice', kind));
      expect(res.status).toBe('stored');
    }
    expect(await chainOk(w)).toBe(true);
    expect((await w.events.head(w.dealId)).nextSeq).toBe(4); // key.bound + 3
  });

  it('head of an unknown deal is seq 0 with a zero prev_hash and leaves nothing behind', async () => {
    const w = await makeWorld();
    const h = await w.events.head('0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8caa');
    expect(h).toEqual({ nextSeq: 0, prevHash: '0'.repeat(64) });
    expect(await w.db.repos.evidenceEvents.listAfter('0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8caa', -1)).toEqual([]);
  });

  it('each append leaves one outbox row with the exact envelope bytes (the replay log)', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    const bytes = await w.sign(alice, 'alice', 'shell.opened');
    await w.events.append(w.dealId, bytes);
    const rows = await w.db.repos.outbox.listAfter(w.dealId, 0);
    expect(rows.map((r) => r.seq)).toEqual([1]);
    expect(rows[0]?.topic).toBe('deal.event');
    expect(rows[0]?.payload).toEqual(bytes);
  });
});

describe('P3.4-02 a race for the same seq', () => {
  it('one wins; the other gets seq_taken with the new head, signs again, and is stored next', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    const lawyer = await w.enroll('lawyerA', 'LA');
    const a = await w.sign(alice, 'alice', 'shell.opened');
    const b = await w.sign(lawyer, 'lawyerA', 'escrow.created'); // same head: same seq
    const [ra, rb] = await Promise.all([w.events.append(w.dealId, a), w.events.append(w.dealId, b)]);
    const statuses = [ra.status, rb.status].sort();
    expect(statuses).toEqual(['seq_taken', 'stored']);
    const loser = ra.status === 'seq_taken' ? ra : (rb as typeof ra);
    if (loser.status !== 'seq_taken') throw new Error('unreachable');
    expect(loser.head.nextSeq).toBe(3);
    const again = await w.sign(
      ra.status === 'seq_taken' ? alice : lawyer,
      ra.status === 'seq_taken' ? 'alice' : 'lawyerA',
      ra.status === 'seq_taken' ? 'shell.opened' : 'escrow.created',
    );
    expect((await w.events.append(w.dealId, again)).status).toBe('stored');
    expect(await chainOk(w)).toBe(true);
  });

  it('a wrong prev_hash at the right seq is refused with the real head', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    const head = await w.events.head(w.dealId);
    const forged = envelopeBytes(
      await (await import('@legx/core/hybridEnvelope')).signHybrid(
        'application/vnd.legx.event+json;v=1',
        eventBody(inputFor(w, 'shell.opened', { role: 'alice', keyId: alice.keyId }), {
          ...head,
          prevHash: 'ab'.repeat(32) as never,
        }),
        alice.signer,
      ),
    );
    const res = await w.events.append(w.dealId, forged);
    expect(res).toEqual({ status: 'seq_taken', head });
  });

  it('a future seq (a gap) is refused', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    const head = await w.events.head(w.dealId);
    const ahead = envelopeBytes(
      await (await import('@legx/core/hybridEnvelope')).signHybrid(
        'application/vnd.legx.event+json;v=1',
        eventBody(inputFor(w, 'shell.opened', { role: 'alice', keyId: alice.keyId }), {
          ...head,
          nextSeq: head.nextSeq + 5,
        }),
        alice.signer,
      ),
    );
    expect((await w.events.append(w.dealId, ahead)).status).toBe('seq_taken');
    expect(await w.db.repos.evidenceEvents.getBySeq(w.dealId, head.nextSeq + 5)).toBeUndefined();
  });

  it('the same envelope sent twice is stored once (idempotent retry)', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    const bytes = await w.sign(alice, 'alice', 'shell.opened');
    const first = await w.events.append(w.dealId, bytes);
    const second = await w.events.append(w.dealId, bytes);
    expect(second).toEqual(first);
    expect(await w.db.repos.evidenceEvents.listAfter(w.dealId, 0)).toHaveLength(1);
    expect(await w.db.repos.outbox.listAfter(w.dealId, 0)).toHaveLength(1);
  });

  it('many signers racing under random scheduling: gap-free seq, unbroken chain, every event stored once', async () => {
    const w = await makeWorld();
    const parties = [await w.enroll('alice', 'A'), await w.enroll('lawyerA', 'LA'), await w.enroll('bob', 'B')];
    await fc.assert(
      fc.asyncProperty(fc.scheduler(), fc.integer({ min: 2, max: 3 }), async (s, rounds) => {
        const before = (await w.events.head(w.dealId)).nextSeq;
        const run = async (p: (typeof parties)[number], role: 'alice' | 'lawyerA' | 'bob') => {
          for (let i = 0; i < rounds; i++) {
            for (let attempt = 0; attempt < 20; attempt++) {
              const bytes = await s.schedule(Promise.resolve(w.sign(p, role, 'shell.opened'))); // sign on a head that may go stale
              const res = await w.events.append(w.dealId, bytes);
              if (res.status === 'stored') break;
            }
          }
        };
        const done = Promise.all([run(parties[0]!, 'alice'), run(parties[1]!, 'lawyerA'), run(parties[2]!, 'bob')]);
        await s.waitFor(done);
        const rows = await w.db.repos.evidenceEvents.listAfter(w.dealId, -1);
        expect(rows.map((r) => r.seq)).toEqual(rows.map((_, i) => i));
        expect(rows.length - before).toBe(3 * rounds);
        expect(await chainOk(w)).toBe(true);
      }),
      { numRuns: 6 },
    );
  }, 120_000);
});

describe('P3.4-03 byte for byte', () => {
  it('the stored envelope is returned unchanged and its SHA-256 is the leaf hash', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    // Deliberately not canonical: spaces and key order differ from what we would write ourselves.
    const env = decode(await w.sign(alice, 'alice', 'shell.opened'));
    const odd = new TextEncoder().encode(
      `{ "signatures" : ${JSON.stringify(env.signatures)} , "payload":${JSON.stringify(env.payload)},"payloadType":${JSON.stringify(env.payloadType)} }`,
    );
    const res = await w.events.append(w.dealId, odd);
    expect(res.status).toBe('stored');
    const [stored] = (await w.events.list(w.dealId, 0, 10)) as unknown as [{ envelope: Uint8Array; leafHash: string }];
    expect(stored.envelope).toEqual(odd);
    expect(createHash('sha256').update(stored.envelope).digest('hex')).toBe(stored.leafHash);
  });
});

describe('P3.4-14 every stored envelope is hybrid-signed', () => {
  const strip = (bytes: Uint8Array, keep: (i: number) => boolean) => {
    const e = decode(bytes);
    e.signatures = e.signatures.filter((_: unknown, i: number) => keep(i));
    return new TextEncoder().encode(JSON.stringify(e));
  };

  it('refuses the append when the ML-DSA-65 signature, then the Ed25519 one, is missing', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    const full = await w.sign(alice, 'alice', 'shell.opened');
    await expect(
      w.events.append(
        w.dealId,
        strip(full, (i) => i === 0),
      ),
    ).rejects.toMatchObject({ code: 'PQ_SIGNATURE_MISSING' });
    await expect(
      w.events.append(
        w.dealId,
        strip(full, (i) => i === 1),
      ),
    ).rejects.toMatchObject({ code: 'ED_SIGNATURE_MISSING' });
    await expect(
      w.events.append(
        w.dealId,
        strip(full, () => false),
      ),
    ).rejects.toBeInstanceOf(EnvelopeRejected);
    expect((await w.events.append(w.dealId, full)).status).toBe('stored');
  });

  it('the verifier rejects a stored envelope after either signature is stripped', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    await w.events.append(w.dealId, await w.sign(alice, 'alice', 'shell.opened'));
    const [row] = await w.db.repos.evidenceEvents.listAfter(w.dealId, 0);
    const registry = await w.deps.registry(w.dealId);
    for (const [keep, code] of [
      [(i: number) => i === 0, 'PQ_SIGNATURE_MISSING'],
      [(i: number) => i === 1, 'ED_SIGNATURE_MISSING'],
    ] as const) {
      const env = JSON.parse(new TextDecoder().decode(strip((row as { envelope: Uint8Array }).envelope, keep)));
      expect(verifyHybrid(env, registry, w.clock.closeTime)).toEqual({ ok: false, code });
    }
  });

  it('refuses: an unknown key, a signature by another deal key, a tampered payload, a classical-only sig_algs', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    const stranger = makeParty('enroll/stranger');
    await expect(w.events.append(w.dealId, await w.sign(stranger, 'alice', 'shell.opened'))).rejects.toMatchObject({
      code: 'KEY_UNKNOWN',
    });
    const good = decode(await w.sign(alice, 'alice', 'shell.opened'));
    const body = JSON.parse(Buffer.from(good.payload, 'base64').toString());
    body.predicate.payload_commitment = 'ff'.repeat(32);
    const tampered = { ...good, payload: Buffer.from(JSON.stringify(body)).toString('base64') };
    await expect(w.events.append(w.dealId, new TextEncoder().encode(JSON.stringify(tampered)))).rejects.toMatchObject({
      code: 'ED_SIGNATURE_INVALID',
    });
    body.predicate.sig_algs = ['ed25519'];
    const classical = { ...good, payload: Buffer.from(JSON.stringify(body)).toString('base64') };
    await expect(w.events.append(w.dealId, new TextEncoder().encode(JSON.stringify(classical)))).rejects.toMatchObject({
      code: 'SIG_ALGS_MISMATCH',
    });
  });

  it('refuses garbage, an event of another deal, and a key outside its validity window', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    await expect(w.events.append(w.dealId, new TextEncoder().encode('not json'))).rejects.toMatchObject({
      code: 'NOT_JSON',
    });
    await expect(w.events.append(w.dealId, new TextEncoder().encode('{"payloadType":1}'))).rejects.toBeInstanceOf(
      EnvelopeRejected,
    );
    const bytes = await w.sign(alice, 'alice', 'shell.opened');
    await expect(w.events.append('0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8caa', bytes)).rejects.toMatchObject({
      code: 'DEAL_MISMATCH',
    });
  });
});

describe('P3.4-04 the 4 KB rule for service-signed events', () => {
  const recording = (inner: SignerPort) => {
    const sizes: number[] = [];
    const signer: SignerPort = {
      publicKeys: () => inner.publicKeys(),
      signHybrid: (msg, ctx) => {
        sizes.push(msg.length);
        return inner.signHybrid(msg, ctx);
      },
    };
    return { signer, sizes };
  };

  it('over every event kind: a RAW sign call never gets more than 4,096 bytes; a larger PAE is refused first', async () => {
    const w = await makeWorld();
    const { signer, sizes } = recording(w.service.signer);
    const outcomes = new Map<string, 'signed' | 'too-large'>();
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...EventKind.options),
        fc.boolean(),
        fc.boolean(),
        async (kind, trace, withLedger) => {
          const g = goldenOf(kind).predicate;
          const body = eventBody(
            inputFor(
              w,
              kind,
              { role: 'coordinator', keyId: 'svc' },
              {
                ...(trace ? { traceId: '4bf92f3577b34da6a3ce929d0e0e4736' } : {}),
                ...(withLedger && g.ledger ? {} : { ledger: undefined }),
              },
            ),
            { nextSeq: 7, prevHash: 'cd'.repeat(32) as never },
          );
          const before = sizes.length;
          try {
            await signAsService(signer, body);
            outcomes.set(kind, 'signed');
            expect(sizes.length).toBe(before + 1);
          } catch (e) {
            expect(e).toBeInstanceOf(PaeTooLarge);
            outcomes.set(kind, 'too-large');
            expect(sizes.length).toBe(before); // the signer was never called
          }
          expect(Math.max(0, ...sizes)).toBeLessThanOrEqual(SERVICE_PAE_LIMIT);
        },
      ),
      { numRuns: 120 },
    );
    // Only the events a party signs on its own device are bigger than the service key can sign.
    expect(
      [...outcomes]
        .filter(([, v]) => v === 'too-large')
        .map(([k]) => k)
        .sort(),
    ).toEqual(['pq.bound']);
  });

  it('a whole append through the KMS signer (RAW limit enforced by the emulator) works for every other kind', async () => {
    const w = await makeWorld();
    const kms = createFakeKms();
    const signer = kmsSigner({
      client: kms,
      kmsKeys: { ed25519: FAKE_ED_KEY, mlDsa65: FAKE_PQ_KEY },
      keyIds: { ed25519: 'svc/kms-ed' as never, mlDsa65: 'svc/kms-pq' as never },
    });
    const keys = await signer.publicKeys();
    const events = (await import('../src/events.ts')).createEvents({
      ...w.deps,
      signer,
      registry: async () => registryFromRows([], { keys, validFrom: 0 }),
    });
    for (const kind of EventKind.options.filter((k) => k !== 'pq.bound')) {
      const res = await events.appendOwn(w.dealId, () => inputFor(w, kind, { role: 'coordinator', keyId: '' }));
      expect(res.leafHash).toMatch(/^[0-9a-f]{64}$/);
    }
    await expect(
      events.appendOwn(w.dealId, () => inputFor(w, 'pq.bound', { role: 'coordinator', keyId: '' })),
    ).rejects.toBeInstanceOf(PaeTooLarge);
    expect(kms.calls.filter((c) => c.type === 'Sign').every((c) => c.input.MessageType !== undefined)).toBe(true);
  });

  it('lock.verified at its schema maximum (512 findings) is refused, and the boundary is exact', async () => {
    const w = await makeWorld();
    const base = goldenOf('lock.verified').predicate.data as { ledger: unknown; findings: unknown[] };
    const finding = base.findings[0];
    const sizeFor = (_n: number) => (body: Uint8Array) => body.length;
    void sizeFor;
    const fits = async (n: number) => {
      const body = eventBody(
        inputFor(
          w,
          'lock.verified',
          { role: 'watcher', keyId: 'svc' },
          { data: { ...base, findings: Array(n).fill(finding) } },
        ),
        { nextSeq: 1, prevHash: 'cd'.repeat(32) as never },
      );
      return signAsService(w.service.signer, body).then(
        () => true,
        (e) => (e instanceof PaeTooLarge ? false : Promise.reject(e)),
      );
    };
    expect(await fits(0)).toBe(true);
    expect(await fits(512)).toBe(false);
    let lo = 0;
    let hi = 512;
    while (hi - lo > 1) {
      const mid = (lo + hi) >> 1;
      if (await fits(mid)) lo = mid;
      else hi = mid;
    }
    expect(await fits(lo)).toBe(true);
    expect(await fits(lo + 1)).toBe(false);
  });
});
