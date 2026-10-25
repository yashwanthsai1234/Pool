// P3.2-09: the coordinator never accepts or stores a private key, a release code or a raw passport.
// (1) Schema test: no route it serves has an input field that could carry one. (2) Fuzz test: such fields, planted
// anywhere in a request or in an event, are refused and never reach a table, an outbox row or a log line.
import { listRoutes } from '@legx/contracts/catalog';
import fc from 'fast-check';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { procedures } from '../src/routes.ts';
import { joinAll, ok, toVerified } from './support/lifecycle.ts';
import {
  addTx,
  append,
  call,
  holderOf,
  makeEvent,
  makeWorld,
  newDeal,
  rndHex,
  SHELL,
  type World,
} from './support/world.ts';

vi.setConfig({ testTimeout: 300_000 });

const FORBIDDEN =
  /priv|secret|seed|mnemonic|passphrase|preimage|fulfil|release.?code|passport|dg1|dg2|sod\b|mrz|face|biometric|facts|birth|first.?name|last.?name|nationality|bar.?number|salt|query.?result/i;

const names = (schema: unknown): string[] => {
  const out: string[] = [];
  const walk = (n: unknown) => {
    if (Array.isArray(n)) return n.forEach(walk);
    if (n && typeof n === 'object') {
      for (const [k, v] of Object.entries(n)) {
        if (k === 'properties' && v && typeof v === 'object') out.push(...Object.keys(v));
        walk(v);
      }
    }
  };
  walk(schema);
  return out;
};

describe('schema test', () => {
  const served = listRoutes().filter((r) => r.name in procedures);
  it('serves routes of its own lane only (the verifier, ZK, FROST, recovery and bar routes live elsewhere)', () => {
    expect(served.map((r) => r.name).sort()).toEqual(
      [
        'deals.create',
        'deals.get',
        'deals.keys',
        'deals.publicData',
        'deals.setContract',
        'deals.setWallet',
        'events.append',
        'events.head',
        'events.list',
        'identityBox.get',
        'identityBox.put',
        'keys.get',
        'keys.register',
        'deals.mine',
        'ledger.accountInfo',
        'ledger.submit',
        'presence.open',
        'presence.get',
        'presence.submit',
        'signatures.create',
        'signatures.list',
        'signatures.submit',
      ].sort(),
    );
  });
  it.each(served.map((r) => [r.name, r] as const))('%s: no input or output field is named like a secret', (_n, r) => {
    const fields = [
      ...names(z.toJSONSchema(r.input as z.ZodType)),
      ...names(z.toJSONSchema(r.output as z.ZodType, { io: 'output' })),
    ];
    expect(fields.filter((f) => FORBIDDEN.test(f))).toEqual([]);
  });
  it('the only Secret-typed inputs of the whole route table are the four of the verifier lanes, and none is served here', () => {
    const secretRoutes = listRoutes()
      .filter((r) => JSON.stringify(z.toJSONSchema(r.input as z.ZodType)).includes('x-legx-secret'))
      .map((r) => r.name);
    expect(secretRoutes.sort()).toEqual(['bar.dealLink', 'bar.manualEvidence', 'bar.verify', 'zk.verify']);
    for (const n of secretRoutes) expect(n in procedures).toBe(false);
  });
});

describe('fuzz test', () => {
  let w: World;
  let id: string;
  const SENTINEL = 'SENTINEL-SECRET-4f7a9c';
  beforeAll(async () => {
    w = await makeWorld();
    id = await newDeal(w);
    await joinAll(w, id);
  });
  afterAll(async () => w.close());

  const fieldName = fc.constantFrom(
    'privateKey',
    'seed',
    'secret',
    'releasePreimage',
    'release_code',
    'fulfillment',
    'passport',
    'dg1',
    'sod',
    'mrz',
    'faceImage',
    'family_seed',
    'mnemonic',
    'birthdate',
    'bar_number',
    'zkSalt',
  );
  const where = fc.constantFrom('body', 'query', 'event-data', 'event-top', 'gate');

  /** Every byte the coordinator holds for the deal, decoded one level so a base64 payload is searched as text. */
  async function stored(): Promise<string> {
    const parts: string[] = [];
    const text = (b: Uint8Array) => {
      const t = Buffer.from(b).toString('utf8');
      parts.push(t);
      try {
        const env = JSON.parse(t) as { payload?: string };
        if (env.payload) parts.push(Buffer.from(env.payload, 'base64').toString('utf8'));
      } catch {
        /* not JSON */
      }
    };
    for (const e of await w.db.repos.evidenceEvents.listAfter(id, -1)) text(e.envelope);
    for (const o of await w.db.repos.outbox.listAfter(id, -1)) text(o.payload);
    for (const r of await w.db.repos.signatureRequests.listOpen(id)) parts.push(JSON.stringify(r));
    return parts.join('\n');
  }

  it('secret-named fields planted in bodies, queries and events are refused and never stored', async () => {
    const before = (await w.db.repos.evidenceEvents.listAfter(id, -1)).length;
    await fc.assert(
      fc.asyncProperty(fieldName, where, async (name, place) => {
        let status: number;
        if (place === 'body') {
          status = (
            await call(w, holderOf(w, 'alice'), 'POST', `/deals/${id}/wallet`, {
              dealId: id,
              walletAddress: SHELL,
              [name]: SENTINEL,
            })
          ).status;
        } else if (place === 'query') {
          status = (
            await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}/events?afterSeq=-1&limit=5&${name}=${SENTINEL}`)
          ).status;
        } else if (place === 'event-top') {
          const b64 = await makeEvent(w, id, 'alice', 'shell.opened', {
            wallet_address: SHELL,
            funding_tx_hash: addTx(w, 'Payment', 'rX'),
          });
          const env = JSON.parse(Buffer.from(b64, 'base64').toString());
          status = (
            await call(w, holderOf(w, 'alice'), 'POST', `/deals/${id}/events`, {
              dealId: id,
              envelope: b64,
              [name]: SENTINEL,
            })
          ).status;
          expect(env.signatures).toHaveLength(2);
        } else if (place === 'event-data') {
          status = (
            await append(
              w,
              id,
              'alice',
              await makeEvent(w, id, 'alice', 'shell.opened', {
                wallet_address: SHELL,
                funding_tx_hash: addTx(w, 'Payment', 'rX'),
                [name]: SENTINEL,
              }),
            )
          ).status;
        } else {
          status = (
            await append(
              w,
              id,
              'lawyerB',
              await makeEvent(w, id, 'lawyerB', 'release.gate.passed', { gate: { [name]: SENTINEL } }),
            )
          ).status;
        }
        expect(status).toBe(400);
        expect(await stored()).not.toContain(SENTINEL);
      }),
      { numRuns: 40 },
    );
    expect((await w.db.repos.evidenceEvents.listAfter(id, -1)).length).toBe(before);
  });

  it('a release code that arrives anywhere is refused: the coordinator keeps only the condition (the fingerprint)', async () => {
    const code = rndHex(32);
    const wid = await newDeal(w);
    await toVerified(w, wid);
    const b64 = await makeEvent(w, wid, 'lawyerB', 'release.performed', {
      finish_tx_hash: addTx(w, 'EscrowFinish', 'rX'),
      ledger_index: w.ledger.index,
      gate_leaf_hash: rndHex(32),
      preimage: code,
    });
    const r = await append(w, wid, 'lawyerB', b64);
    expect(r.status).toBe(400);
    const log = (await w.db.repos.evidenceEvents.listAfter(wid, -1))
      .map(
        (e) =>
          Buffer.from(e.envelope).toString() +
          Buffer.from(JSON.parse(Buffer.from(e.envelope).toString()).payload, 'base64').toString(),
      )
      .join('');
    expect(log).not.toContain(code);
    ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${wid}`));
  });
});
