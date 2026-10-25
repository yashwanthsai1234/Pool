import { randomBytes } from 'node:crypto';
import type { ValidatedTx } from '@legx/contracts/ports';
import type { XrplHash } from '@legx/contracts/values';
import { toBase64 } from '@legx/core/pq';
import { bytesToHex } from '@noble/hashes/utils.js';
import { sql } from 'kysely';
import { describe, expect, it, vi } from 'vitest';
import { apiRequestMessage, listClientRecords, Refused, type Side, type SignedRequest } from '../src/records.ts';
import { fakeLedger } from './helpers/fakeLedger.ts';
import { goldenOf, inputFor, makeParty, makeWorld, type Party, type World } from './helpers/world.ts';

vi.setConfig({ testTimeout: 60_000 });

const LEDGER_INDEX = 1000; // the fake clock's validated ledger

interface Req {
  method?: string;
  path?: string;
  body?: Uint8Array;
  ledgerIndex?: number;
  nonce?: string;
  signAs?: { method?: string; path?: string; body?: Uint8Array };
}

async function sign(party: Party, o: Req = {}): Promise<SignedRequest> {
  const method = o.method ?? 'POST';
  const path = o.path ?? '/deals/x/records';
  const body = o.body ?? new TextEncoder().encode('{"side":"A"}');
  const nonce = o.nonce ?? bytesToHex(randomBytes(32));
  const ledgerIndex = o.ledgerIndex ?? LEDGER_INDEX;
  const msg = apiRequestMessage(
    o.signAs?.method ?? method,
    o.signAs?.path ?? path,
    o.signAs?.body ?? body,
    nonce,
    ledgerIndex,
  );
  const sig = await party.signer.signHybrid(msg, 'legx/api-request/v1' as never);
  return {
    method,
    path,
    body,
    auth: {
      nonce,
      ledgerIndex,
      signatures: [
        { keyid: sig.keyIds.ed25519, sig: toBase64(sig.ed25519) },
        { keyid: sig.keyIds.mlDsa65, sig: toBase64(sig.mlDsa65) },
      ],
    },
  };
}

async function deal() {
  const w = await makeWorld();
  const alice = await w.enroll('alice', 'A');
  const lawyerA = await w.enroll('lawyerA', 'LA');
  const bob = await w.enroll('bob', 'B');
  const lawyerB = await w.enroll('lawyerB', 'LB');
  const ledger = fakeLedger();
  const g = goldenOf('shell.opened').predicate.ledger as { tx_hash: string; ledger_index: number };
  const linked: ValidatedTx = {
    hash: g.tx_hash as XrplHash,
    ledgerIndex: g.ledger_index,
    closeTime: 1 as never,
    tx: {},
    meta: {},
  };
  ledger.txs.set(g.tx_hash, linked);
  const noLedger = { ledger: undefined } as const;
  const put = async (
    p: Party,
    role: 'alice' | 'bob' | 'lawyerA' | 'lawyerB',
    kind: Parameters<World['sign']>[2],
    patch: Parameters<World['sign']>[3] = {},
  ) => expect((await w.events.append(w.dealId, await w.sign(p, role, kind, patch))).status).toBe('stored');
  await put(alice, 'alice', 'shell.opened'); // ledger: linked
  await put(alice, 'alice', 'escrow.created', noLedger);
  await put(lawyerA, 'lawyerA', 'lawyer.approved', noLedger);
  await put(bob, 'bob', 'shell.opened', noLedger);
  await put(lawyerB, 'lawyerB', 'ops.bound', noLedger);
  await w.events.appendOwn(w.dealId, () => inputFor(w, 'exit.signed', { role: 'watcher', keyId: '' }, noLedger));
  const deps = { db: w.db, clock: w.clock, ledger: ledger.port, registry: w.deps.registry };
  return { w, alice, lawyerA, bob, lawyerB, deps, ledger };
}

const seqsOf = (r: { records: { seq: number }[] }) => r.records.map((x) => x.seq);

describe('P3.4-11 the client records view', () => {
  it("a request signed by Alice's x-key returns Alice's records only, each with its three checks", async () => {
    const { w, alice, deps } = await deal();
    const res = await listClientRecords(deps, await sign(alice), { dealId: w.dealId, side: 'A' });
    // seq: 0..3 are the four key.bound events of the service, 4 alice shell, 5 alice escrow, 6 lawyerA, 7 bob, 8 lawyerB, 9 watcher
    expect(seqsOf(res)).toEqual([0, 1, 2, 3, 4, 5, 6, 9]);
    expect(res.records.every((r) => r.checks.signature && r.checks.chain)).toBe(true);
    expect(res.records.find((r) => r.seq === 4)?.checks.ledger).toBe('linked');
    expect(res.records.find((r) => r.seq === 5)?.checks.ledger).toBe('none');
    const stored = await w.db.repos.evidenceEvents.listAfter(w.dealId, 3, 1);
    expect(res.records.find((r) => r.seq === 4)?.envelope).toEqual(stored[0]?.envelope); // exact bytes
  });

  it("Alice's own lawyer sees Alice's records; Bob sees Bob's, never Alice's", async () => {
    const { w, lawyerA, bob, deps } = await deal();
    expect(seqsOf(await listClientRecords(deps, await sign(lawyerA), { dealId: w.dealId, side: 'A' }))).toContain(6);
    const forBob = await listClientRecords(deps, await sign(bob), { dealId: w.dealId, side: 'B' });
    expect(seqsOf(forBob)).toEqual([0, 1, 2, 3, 7, 8, 9]);
    expect(seqsOf(forBob)).not.toContain(4);
  });

  it('a record claiming a ledger transaction the ledger does not know shows "mismatch"; a record edited after the fact fails its checks', async () => {
    const { w, alice, deps, ledger } = await deal();
    ledger.txs.clear();
    const res = await listClientRecords(deps, await sign(alice), { dealId: w.dealId, side: 'A' });
    expect(res.records.find((r) => r.seq === 4)?.checks.ledger).toBe('mismatch');
    // a superuser rewrites the leaf of record 5 (its envelope and its hash); record 5 now fails its signature
    // and record 6 fails its chain position
    const row = (await w.db.repos.evidenceEvents.listAfter(w.dealId, 4, 1))[0] as { envelope: Uint8Array };
    const forged = new Uint8Array(row.envelope);
    forged[forged.length - 8] = (forged[forged.length - 8] as number) ^ 1;
    const leaf = (await import('node:crypto')).createHash('sha256').update(forged).digest();
    await sql`set session_replication_role = replica`.execute(w.db.kysely);
    await sql`update evidence_event set envelope = ${forged}, leaf_hash = ${leaf} where seq = 5`.execute(w.db.kysely);
    await sql`set session_replication_role = origin`.execute(w.db.kysely);
    const after = await listClientRecords(deps, await sign(alice), { dealId: w.dealId, side: 'A' });
    expect(after.records.find((r) => r.seq === 5)?.checks.signature).toBe(false);
    expect(after.records.find((r) => r.seq === 6)?.checks.chain).toBe(false);
    expect(after.records.find((r) => r.seq === 4)?.checks).toMatchObject({ signature: true, chain: true });
  });
});

const refusal = async (p: Promise<unknown>): Promise<Refused> => {
  const e = await p.then(
    () => undefined,
    (x: unknown) => x,
  );
  expect(e).toBeInstanceOf(Refused);
  return e as Refused;
};

describe("T-A-31 nobody else asks for Alice's records", () => {
  it('Bob, Lawyer B: refused with 403; an unsigned request: 401', async () => {
    const { w, bob, lawyerB, deps } = await deal();
    const q = { dealId: w.dealId, side: 'A' as Side };
    expect(await refusal(listClientRecords(deps, await sign(bob), q))).toMatchObject({
      status: 403,
      code: 'NOT_YOUR_SIDE',
    });
    expect(await refusal(listClientRecords(deps, await sign(lawyerB), q))).toMatchObject({
      status: 403,
      code: 'NOT_YOUR_SIDE',
    });
    expect(
      await refusal(
        listClientRecords(deps, { method: 'POST', path: '/x', body: new Uint8Array(), auth: undefined }, q),
      ),
    ).toMatchObject({ status: 401, code: 'UNSIGNED' });
  });

  it('a stranger with valid hybrid keys that are not pinned in this deal: 401', async () => {
    const { w, deps } = await deal();
    expect(
      await refusal(listClientRecords(deps, await sign(makeParty('enroll/mallory')), { dealId: w.dealId, side: 'A' })),
    ).toMatchObject({ status: 401, code: 'KEY_UNKNOWN' });
  });

  it("Alice's key in another deal does not open this deal (403)", async () => {
    const { w, alice, deps } = await deal();
    const other = await makeWorld();
    expect(
      await refusal(listClientRecords({ ...deps, db: w.db }, await sign(alice), { dealId: other.dealId, side: 'A' })),
    ).toMatchObject({ status: 403, code: 'KEY_WRONG_DEAL' });
  });

  it('malformed auth: junk, one signature only, keys that are not a pair, a signature over another path or body or method', async () => {
    const { w, alice, bob, deps } = await deal();
    const q = { dealId: w.dealId, side: 'A' as Side };
    const base = await sign(alice);
    const auth = base.auth as { signatures: unknown[] };
    for (const bad of ['junk', {}, { ...auth, signatures: [auth.signatures[0]] }, null]) {
      const r = await refusal(listClientRecords(deps, { ...base, auth: bad }, q));
      expect(r.status).toBe(401);
    }
    // a pairing of Alice's Ed25519 key id with Bob's ML-DSA key id
    const mixed = {
      ...(base.auth as object),
      signatures: [auth.signatures[0], ((await sign(bob)).auth as { signatures: unknown[] }).signatures[1]],
    };
    expect(await refusal(listClientRecords(deps, { ...base, auth: mixed }, q))).toMatchObject({
      code: 'KEY_NOT_PAIRED',
    });
    for (const signAs of [
      { path: '/deals/x/bundle' },
      { body: new TextEncoder().encode('{"side":"B"}') },
      { method: 'GET' },
    ]) {
      expect(await refusal(listClientRecords(deps, await sign(alice, { signAs }), q))).toMatchObject({
        status: 401,
        code: 'BAD_SIGNATURE',
      });
    }
  });

  it('the query string is part of the signed path (OD-8)', async () => {
    const { w, alice, deps } = await deal();
    const q = { dealId: w.dealId, side: 'A' as Side };
    const ok = await sign(alice, { path: '/deals/x/records?limit=5' });
    expect((await listClientRecords(deps, ok, q)).records.length).toBeGreaterThan(0);
    expect(
      await refusal(
        listClientRecords(
          deps,
          { ...(await sign(alice, { path: '/deals/x/records?limit=5' })), path: '/deals/x/records?limit=500' },
          q,
        ),
      ),
    ).toMatchObject({ code: 'BAD_SIGNATURE' });
  });

  it('a signature with either half broken is refused (Ed25519 alone, ML-DSA alone)', async () => {
    const { w, alice, deps } = await deal();
    const q = { dealId: w.dealId, side: 'A' as Side };
    for (const i of [0, 1]) {
      const r = await sign(alice);
      const sigs = (r.auth as { signatures: { sig: string }[] }).signatures;
      const raw = Buffer.from((sigs[i] as { sig: string }).sig, 'base64');
      raw[5] = (raw[5] as number) ^ 1;
      (sigs[i] as { sig: string }).sig = raw.toString('base64');
      expect(await refusal(listClientRecords(deps, r, q))).toMatchObject({ code: 'BAD_SIGNATURE' });
    }
  });
});

describe('P3.4-12 replay and age', () => {
  it('a replayed signed request (same nonce) is refused; a bad request does not burn the nonce', async () => {
    const { w, alice, deps } = await deal();
    const q = { dealId: w.dealId, side: 'A' as Side };
    const nonce = bytesToHex(randomBytes(32));
    const bad = await sign(alice, { nonce, signAs: { path: '/other' } });
    expect(await refusal(listClientRecords(deps, bad, q))).toMatchObject({ code: 'BAD_SIGNATURE' });
    const good = await sign(alice, { nonce });
    await listClientRecords(deps, good, q);
    expect(await refusal(listClientRecords(deps, good, q))).toMatchObject({ status: 401, code: 'REPLAY' });
    // the same nonce by another key is also a replay: nonces are global
    expect(await refusal(listClientRecords(deps, await sign(alice, { nonce }), q))).toMatchObject({ code: 'REPLAY' });
  });

  it('refuses a ledger index more than 20 ledgers old, accepts exactly 20, and refuses one from the future', async () => {
    const { w, alice, deps } = await deal();
    const q = { dealId: w.dealId, side: 'A' as Side };
    await listClientRecords(deps, await sign(alice, { ledgerIndex: LEDGER_INDEX - 20 }), q);
    expect(
      await refusal(listClientRecords(deps, await sign(alice, { ledgerIndex: LEDGER_INDEX - 21 }), q)),
    ).toMatchObject({ status: 401, code: 'STALE' });
    await listClientRecords(deps, await sign(alice, { ledgerIndex: LEDGER_INDEX + 2 }), q);
    expect(
      await refusal(listClientRecords(deps, await sign(alice, { ledgerIndex: LEDGER_INDEX + 3 }), q)),
    ).toMatchObject({ code: 'FUTURE' });
  });

  it('the age is the ledger, not the wall clock: when the ledger moves 21 ledgers, an old request is stale', async () => {
    const { w, alice, deps } = await deal();
    const q = { dealId: w.dealId, side: 'A' as Side };
    const req = await sign(alice);
    const clock = { now: async () => ({ ...(await w.clock.now()), ledgerIndex: LEDGER_INDEX + 21 }) };
    expect(await refusal(listClientRecords({ ...deps, clock }, req, q))).toMatchObject({ code: 'STALE' });
  });

  it('a key outside its validity window is refused', async () => {
    const { w, alice, deps } = await deal();
    w.clock.closeTime = -1;
    expect(await refusal(listClientRecords(deps, await sign(alice), { dealId: w.dealId, side: 'A' }))).toMatchObject({
      code: 'KEY_EXPIRED',
    });
  });

  it('old nonces are pruned once they are too old to be replayed anyway', async () => {
    const { w, alice, deps } = await deal();
    const q = { dealId: w.dealId, side: 'A' as Side };
    const first = await sign(alice, { ledgerIndex: LEDGER_INDEX - 20 });
    await listClientRecords(deps, first, q);
    const clock = { now: async () => ({ ...(await w.clock.now()), ledgerIndex: LEDGER_INDEX + 5 }) };
    await listClientRecords({ ...deps, clock }, await sign(alice, { ledgerIndex: LEDGER_INDEX + 5 }), q); // prunes below index 985
    const rows = await sql<{ n: number }>`select count(*)::int as n from used_nonce`.execute(w.db.kysely);
    expect(rows.rows[0]?.n).toBe(1);
  });
});
