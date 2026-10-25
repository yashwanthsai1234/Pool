// The repository suite. It runs unchanged on PGlite (test/) and on Postgres 18 (test-int/); the observations it records
// are compared between the two engines (the A/B test, scripts/ab-compare.ts).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import fc from 'fast-check';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { KyselyDatabase } from '../../src/client.ts';
import { KeyNotRecorded, SeqTaken } from '../../src/errors.ts';
import { generateSchemaTs } from '../../src/gen-schema.ts';
import { ADDR, addEvent, asRole, b64, clientKey, lawyerKey, newDeal, refusal, rnd, rndHex, uuid7 } from './helpers.ts';
import { appendOnlyTables, catalogSnapshot } from './snapshot.ts';

/** The 18 tables of DESIGN 9 and the three working-state tables of task 3.1 (P3.1-13). */
const DESIGN9_TABLES = [
  'deal',
  'deal_key',
  'lawyer',
  'bar_verification',
  'attorney_credential',
  'bar_deal_link',
  'passport_attestation',
  'zk_proof',
  'enrollment_key',
  'release_gate',
  'signature_request',
  'signature',
  'evidence_event',
  'evidence_log_entry',
  'ledger_observation',
  'watcher_cursor',
  'outbox',
  'checkpoint_anchor',
];
const TASK_TABLES = [
  'deal_head',
  'used_nonce',
  'frost_nonce_use',
  // migration 0003 (fix fleet F1): the presence relay and the tables the FROST services used to create themselves
  'presence_request',
  'frost_relay_session',
  'frost_relay_message',
  'recovery_agent_share',
  'recovery_agent_recovery',
  'recovery_agent_refresh',
  'firm_cosigner_share',
  'firm_cosigner_credential',
  'firm_cosigner_approval_use',
  'firm_cosigner_audit',
  // migration 0004 (OD-36 b): the client's sealed salt and disclosure boxes
  'identity_box',
];
const APPEND_ONLY = [
  'attorney_credential',
  'bar_deal_link',
  'bar_verification',
  'enrollment_key',
  'evidence_event',
  'evidence_log_entry',
  'firm_cosigner_approval_use',
  'firm_cosigner_audit',
  'frost_nonce_use',
  'passport_attestation',
  'release_gate',
  'zk_proof',
];

const SNAPSHOT_FILE = new URL('../schema.snapshot.txt', import.meta.url);
const SCHEMA_TS = new URL('../../src/schema.ts', import.meta.url);

export function repositorySuite(engine: string, open: () => Promise<KyselyDatabase>): void {
  const observed: Record<string, unknown> = {};
  const observe = (k: string, v: unknown) => {
    observed[k] = v;
  };
  let db: KyselyDatabase;
  beforeAll(async () => {
    db = await open();
    await db.migrate();
  });
  afterAll(async () => {
    mkdirSync(new URL('../../../../build/tmp/3.1/', import.meta.url), { recursive: true });
    writeFileSync(
      new URL(`../../../../build/tmp/3.1/ab-${engine}.json`, import.meta.url),
      JSON.stringify(observed, Object.keys(observed).sort(), 2),
    );
    await db.close();
  });

  describe(`schema on ${engine}`, () => {
    it('P3.1-01 migrations roll forward twice without change, and the schema equals the committed snapshot', async () => {
      expect(await db.migrate()).toEqual([]);
      expect(await db.migrate()).toEqual([]);
      const snap = await catalogSnapshot(db);
      if (process.env.UPDATE_SNAPSHOT === '1') writeFileSync(SNAPSHOT_FILE, snap);
      expect(snap).toBe(readFileSync(SNAPSHOT_FILE, 'utf8'));
      observe('snapshot', snap);
    });

    it('P3.1-13 the tables are exactly the 18 of DESIGN 9 plus deal_head, used_nonce and frost_nonce_use', async () => {
      const r = await sql<{
        t: string;
      }>`SELECT table_name AS t FROM information_schema.tables WHERE table_schema = 'public' AND table_name NOT LIKE 'kysely\\_%'`.execute(
        db.kysely,
      );
      expect(r.rows.map((x) => x.t).sort()).toEqual([...DESIGN9_TABLES, ...TASK_TABLES].sort());
    });

    it('the committed Kysely types equal the types generated from the migrated schema', async () => {
      expect(readFileSync(SCHEMA_TS, 'utf8')).toBe(await generateSchemaTs(db.kysely));
    });

    it('P3.1-07 no column has a name that could hold passport data', async () => {
      const r = await sql<{
        t: string;
        c: string;
      }>`SELECT table_name AS t, column_name AS c FROM information_schema.columns WHERE table_schema = 'public' AND table_name NOT LIKE 'kysely\\_%'`.execute(
        db.kysely,
      );
      const bad =
        /^(dg\d+|sod|mrz|name|full_name|given_names?|surname|first_name|last_name|dob|birth.*|date_of_birth|nationality|document_(number|no)|passport.*|doc_?(number|no)|photo|face.*)$/;
      expect(r.rows.filter((x) => bad.test(x.c))).toEqual([]);
      expect(r.rows.filter((x) => /passport/.test(x.t) && x.t !== 'passport_attestation')).toEqual([]);
      const tables = await sql<{
        t: string;
      }>`SELECT table_name AS t FROM information_schema.tables WHERE table_schema = 'public'`.execute(db.kysely);
      expect(tables.rows.map((x) => x.t).filter((t) => /passport|dg1|mrz|sod/.test(t))).toEqual([
        'passport_attestation',
      ]);
    });

    it('P3.1-09 deal_key has the post-quantum columns and refuses a bad id_method, key hash or binding signature count', async () => {
      const cols = await sql<{
        c: string;
        t: string;
      }>`SELECT column_name AS c, data_type AS t FROM information_schema.columns WHERE table_name = 'deal_key'`.execute(
        db.kysely,
      );
      const m = new Map(cols.rows.map((x) => [x.c, x.t]));
      for (const c of ['slot_policy', 'pq_key_hash', 'pq_cross_sig', 'id_method']) expect(m.has(c)).toBe(true);
      expect(m.get('pq_binding_sigs')).toBe('jsonb');
      const dealId = await newDeal(db);
      const base = {
        deal_id: dealId,
        role: 'alice',
        xrpl_pubkey: `ED${rndHex(32).toUpperCase()}`,
        xrpl_account: ADDR[0],
        commitment: rnd(32),
        binding_sig: rnd(64),
        slot_policy: rnd(32),
        pq_key_hash: rnd(32),
        pq_binding_sigs: JSON.stringify([
          { key_id: 'a', sig: 's' },
          { key_id: 'b', sig: 's' },
        ]),
        pq_cross_sig: rnd(64),
        id_method: 'zkpassport',
      };
      const ins = (over: Record<string, unknown>) =>
        db.kysely
          .insertInto('deal_key')
          .values({ ...base, ...over } as never)
          .execute();
      const refused = {
        idMethod: await refusal(ins({ id_method: 'passport-scan' })),
        keyHash: await refusal(ins({ pq_key_hash: rnd(31) })),
        oneSig: await refusal(ins({ pq_binding_sigs: JSON.stringify([{ key_id: 'a', sig: 's' }]) })),
        threeSigs: await refusal(
          ins({
            pq_binding_sigs: JSON.stringify([
              { key_id: 'a', sig: 's' },
              { key_id: 'b', sig: 's' },
              { key_id: 'c', sig: 's' },
            ]),
          }),
        ),
        notArray: await refusal(ins({ pq_binding_sigs: JSON.stringify({ key_id: 'a', sig: 's' }) })),
        unnamedSig: await refusal(
          ins({ pq_binding_sigs: JSON.stringify([{ key_id: 'a' }, { key_id: 'b', sig: 's' }]) }),
        ),
      };
      for (const r of Object.values(refused)) expect(r.code).toBe('23514');
      observe('deal_key checks', refused);
      await ins({}); // the good row goes in
    });

    it('P3.1-04 a lawyer deal_key without contract_sig or ops_account is refused', async () => {
      const dealId = await newDeal(db);
      const lawyer = {
        deal_id: dealId,
        role: 'lawyerA',
        xrpl_pubkey: `ED${rndHex(32).toUpperCase()}`,
        xrpl_account: ADDR[0],
        commitment: rnd(32),
        binding_sig: rnd(64),
        slot_policy: rnd(32),
        pq_key_hash: rnd(32),
        pq_binding_sigs: JSON.stringify([
          { key_id: 'a', sig: 's' },
          { key_id: 'b', sig: 's' },
        ]),
        pq_cross_sig: rnd(64),
        contract_sig: rnd(64),
        ops_account: ADDR[1],
        ops_bind_sig_ops: rnd(64),
        ops_bind_sig_lawyer: rnd(64),
      };
      const ins = (over: Record<string, unknown>) =>
        db.kysely
          .insertInto('deal_key')
          .values({ ...lawyer, ...over } as never)
          .execute();
      const r = {
        noContractSig: await refusal(ins({ contract_sig: null })),
        noOpsAccount: await refusal(ins({ ops_account: null })),
        noOpsBindSig: await refusal(ins({ ops_bind_sig_ops: null })),
        lawyerWithIdMethod: await refusal(ins({ id_method: 'zkpassport' })),
        clientWithLawyerFields: await refusal(ins({ role: 'bob', id_method: 'zkpassport' })),
      };
      for (const x of Object.values(r)) expect(x.code).toBe('23514');
      observe('lawyer deal_key checks', r);
      await ins({});
    });

    it('P3.1-03 deal.releaser_account different from lawyer_ops_b (or with no lawyer_ops_b) is refused', async () => {
      const ok = await newDeal(db, { lawyer_ops_b: ADDR[1] });
      await db.repos.deals.update(ok, { releaser_account: ADDR[1] });
      const r = {
        different: await refusal(db.repos.deals.update(ok, { releaser_account: ADDR[2] })),
        noOpsB: await refusal(db.repos.deals.update(await newDeal(db), { releaser_account: ADDR[2] })),
      };
      expect(r.different.code).toBe('23514');
      expect(r.noOpsB.code).toBe('23514');
      observe('releaser checks', r);
    });
  });

  describe(`append-only on ${engine}`, () => {
    let dealId: string;
    let eventId: string;
    beforeAll(async () => {
      dealId = await newDeal(db);
      const r = db.repos;
      await r.lawyers.insert({ ops_account: ADDR[1], jurisdiction: 'US-NY', bar_number_sha256: rndHex(32) });
      const vh = rndHex(32);
      await r.barVerifications.insert({
        envelope_sha256: vh,
        ops_account: ADDR[1],
        envelope: rnd(50),
        status: 'active',
        checked_at_ledger: 7,
        checked_at_ledger_hash: rndHex(32).toUpperCase(),
      });
      await r.attorneyCredentials.insert({
        ops_account: ADDR[1],
        verification_sha256: vh,
        create_tx_hash: rndHex(32),
        accept_tx_hash: null,
        expiration: 99,
      });
      await r.barDealLinks.insert({ deal_id: dealId, role: 'lawyerA', envelope: rnd(50), verification_sha256: vh });
      await r.passportAttestations.insert({
        deal_id: dealId,
        side: 'A',
        envelope: rnd(50),
        anchor_ledger: 5,
        leaf_hash: rndHex(32),
      });
      await r.zkProofs.insert(zkInput(dealId));
      const ev = await addEvent(db, dealId);
      eventId = ev.event_id;
      await r.evidenceLogEntries.insert(eventId, 0);
      await r.enrollmentKeys.insert(enrollment(dealId, eventId, 'seed-key'));
      await r.releaseGates.insert({ deal_id: dealId, leaf_hash: rndHex(32), envelope: rnd(50), ledger_index: 9 });
      await r.frostNonceUses.markUsed({ key_id: 'k', commitment_id: 'c', deal_id: dealId, message_hash: rndHex(32) });
      // the firm co-signer writes these two with raw SQL (services/firm-cosigner)
      await sql`INSERT INTO firm_cosigner_approval_use (approval_id) VALUES ('seed')`.execute(db.kysely);
      await sql`INSERT INTO firm_cosigner_audit (deal_id, slot, decision, reason, message_hash, seal, detail, prev_hash,
        entry_hash) VALUES (${dealId}, 'LB', 'refused', 'SEED', '', '', '{}', '', '')`.execute(db.kysely);
    });

    it('every append-only table is the expected one and has its triggers', async () => {
      expect(await appendOnlyTables(db)).toEqual(APPEND_ONLY);
    });

    const counts = async () => {
      const out: Record<string, number> = {};
      for (const t of APPEND_ONLY)
        out[t] = Number(
          (await sql<{ n: string }>`SELECT count(*) AS n FROM ${sql.table(t)}`.execute(db.kysely)).rows[0]?.n,
        );
      return out;
    };

    const firstColumn = async (t: string) =>
      (
        await sql<{
          c: string;
        }>`SELECT column_name AS c FROM information_schema.columns WHERE table_name = ${t} ORDER BY ordinal_position LIMIT 1`.execute(
          db.kysely,
        )
      ).rows[0]?.c as string;

    it('P3.1-02 and P3.1-10 as app_rw UPDATE, DELETE and TRUNCATE are refused by the REVOKE; as the owner by the trigger', async () => {
      const before = await counts();
      for (const t of APPEND_ONLY) expect(before[t], t).toBeGreaterThan(0);
      const seen: Record<string, unknown> = {};
      for (const t of APPEND_ONLY) {
        const col = await firstColumn(t);
        const stmts = {
          update: `UPDATE ${t} SET ${col} = ${col}`,
          delete: `DELETE FROM ${t}`,
          truncate: `TRUNCATE ${t}`,
        };
        for (const [op, text] of Object.entries(stmts)) {
          const asApp = await asRole(db, 'app_rw', (q) => refusal(q(text)));
          expect(asApp.code, `${t} ${op} as app_rw`).toBe('42501');
          const asOwner = await refusal(sql.raw(text).execute(db.kysely));
          if (op !== 'truncate') expect(asOwner.message, `${t} ${op} as owner`).toContain('append-only');
          seen[`${t} ${op}`] = { app_rw: asApp, owner: op === 'truncate' ? asOwner.code : asOwner };
        }
      }
      expect(await counts()).toEqual(before);
      observe('append-only refusals', seen);
    });

    it('INSERT and SELECT stay allowed for app_rw on every append-only table', async () => {
      for (const t of APPEND_ONLY) {
        const r = await sql<{
          i: boolean;
          s: boolean;
        }>`SELECT has_table_privilege('app_rw', ${t}, 'INSERT') AS i, has_table_privilege('app_rw', ${t}, 'SELECT') AS s`.execute(
          db.kysely,
        );
        expect(r.rows[0], t).toEqual({ i: true, s: true });
      }
    });

    it('property: random sequences of mutations never change an append-only table', async () => {
      const before = await counts();
      const firstCol: Record<string, string> = {};
      for (const t of APPEND_ONLY) firstCol[t] = await firstColumn(t);
      const op = fc.record({
        t: fc.constantFrom(...APPEND_ONLY),
        kind: fc.constantFrom('update', 'delete', 'truncate'),
        role: fc.constantFrom('owner', 'app_rw'),
      });
      await fc.assert(
        fc.asyncProperty(fc.array(op, { minLength: 1, maxLength: 8 }), async (ops) => {
          for (const o of ops) {
            const col = firstCol[o.t] as string;
            const text =
              o.kind === 'update'
                ? `UPDATE ${o.t} SET ${col} = ${col}`
                : o.kind === 'delete'
                  ? `DELETE FROM ${o.t}`
                  : `TRUNCATE ${o.t}`;
            const run = () =>
              o.role === 'owner' ? sql.raw(text).execute(db.kysely) : asRole(db, 'app_rw', (q) => q(text));
            let refused = false;
            try {
              await run();
            } catch {
              refused = true;
            }
            if (!refused) return false;
          }
          return JSON.stringify(await counts()) === JSON.stringify(before);
        }),
        { numRuns: 25 },
      );
    });

    it('P3.1-14 enrollment keys are never replaced: a rotated key is a new row, and a key with no evidence is refused', async () => {
      const second = await db.repos.evidenceEvents.insert({
        deal_id: dealId,
        seq: 50,
        prev_hash: rndHex(32),
        envelope: rnd(10),
        leaf_hash: rndHex(32),
      });
      const rotated = enrollment(dealId, second.event_id, 'rotated-key', { slot: 'A', holder_role: 'phone' });
      const first = enrollment(dealId, eventId, 'first-key', { slot: 'A', holder_role: 'phone' });
      await db.repos.enrollmentKeys.insert(first);
      await db.repos.enrollmentKeys.insert(rotated);
      const keys = (await db.repos.enrollmentKeys.listForDeal(dealId)).filter(
        (k) => k.slot === 'A' && k.holder_role === 'phone',
      );
      expect(keys.map((k) => k.key_id).sort()).toEqual(['first-key', 'rotated-key']);
      expect(await db.repos.enrollmentKeys.getUsable('first-key')).toMatchObject({
        ed25519_pub: first.ed25519_pub,
        mldsa65_pub: first.mldsa65_pub,
      });
      await expect(db.repos.enrollmentKeys.insert(enrollment(dealId, uuid7(), 'orphan-key'))).rejects.toBeInstanceOf(
        KeyNotRecorded,
      );
      const orphan = enrollment(dealId, uuid7(), 'orphan-raw');
      const noEvidence = await refusal(
        db.kysely
          .insertInto('enrollment_key')
          .values({
            key_id: orphan.key_id,
            deal_id: dealId,
            slot: 'B',
            holder_role: 'phone',
            ed25519_pub: rnd(32),
            mldsa65_pub: rnd(1952),
            valid_from: 1,
            evidence_event_id: orphan.evidence_event_id,
          } as never)
          .execute(),
      );
      expect(noEvidence.code).toBe('23503');
      const otherDeal = await newDeal(db);
      await expect(
        db.repos.enrollmentKeys.insert(enrollment(otherDeal, eventId, 'foreign-event-key')),
      ).rejects.toBeInstanceOf(KeyNotRecorded);
      await expect(db.repos.enrollmentKeys.getUsable('orphan-key')).rejects.toBeInstanceOf(KeyNotRecorded);
      observe('enrollment orphan', noEvidence);
    });

    it('P3.1-12 enrollment_key refuses a duplicate row and a missing half', async () => {
      const k = enrollment(dealId, eventId, 'dup-1', { slot: 'LA', holder_role: 'console' });
      await db.repos.enrollmentKeys.insert(k);
      const dup = await refusal(db.repos.enrollmentKeys.insert({ ...k, key_id: 'dup-2' as never }));
      const sameKeyId = await refusal(
        db.repos.enrollmentKeys.insert({ ...k, ed25519_pub: rndHex(32) as never, mldsa65_pub: b64(1952) as never }),
      );
      const raw = (over: Record<string, unknown>) =>
        db.kysely
          .insertInto('enrollment_key')
          .values({
            key_id: `raw-${rndHex(4)}`,
            deal_id: dealId,
            slot: 'B',
            holder_role: 'phone',
            ed25519_pub: rnd(32),
            mldsa65_pub: rnd(1952),
            valid_from: 1,
            valid_to: null,
            evidence_event_id: eventId,
            ...over,
          } as never)
          .execute();
      const noEd = await refusal(raw({ ed25519_pub: null }));
      const noPq = await refusal(raw({ mldsa65_pub: null }));
      const shortPq = await refusal(raw({ mldsa65_pub: rnd(100) }));
      expect([dup.code, sameKeyId.code, noEd.code, noPq.code, shortPq.code]).toEqual([
        '23505',
        '23505',
        '23502',
        '23502',
        '23514',
      ]);
      observe('enrollment refusals', { dup, sameKeyId, noEd, noPq, shortPq });
    });

    it('P3.1-11 zk_proof stores the trust record and refuses any extra field, including nested ones', async () => {
      const cols = await sql<{
        c: string;
      }>`SELECT column_name AS c FROM information_schema.columns WHERE table_name = 'zk_proof' ORDER BY column_name`.execute(
        db.kysely,
      );
      expect(cols.rows.map((x) => x.c)).toEqual([
        'deal_id',
        'identifier_hash',
        'proof',
        'registry_roots',
        'side',
        'stage',
      ]);
      const d = await newDeal(db);
      const good = zkInput(d);
      await db.repos.zkProofs.insert(good);
      expect(await db.repos.zkProofs.list(d)).toEqual([good]);
      const trust = good.registry_roots;
      for (const extra of [
        { name: 'JANE DOE' },
        { dg1: 'abc' },
        { mrz: 'P<UTO' },
        { birth_date: '1990-01-01' },
        { document_number: 'X123' },
      ]) {
        await expect(db.repos.zkProofs.insert({ ...good, ...extra })).rejects.toThrow();
        await expect(db.repos.zkProofs.insert({ ...good, registry_roots: { ...trust, ...extra } })).rejects.toThrow();
      }
      expect((await db.repos.zkProofs.list(d)).length).toBe(1);
    });
  });

  describe(`idempotency and races on ${engine}`, () => {
    it('P3.1-06 the same leaf_hash twice is a no-op that returns the first row', async () => {
      const dealId = await newDeal(db);
      const e = { deal_id: dealId, seq: 0, prev_hash: '00'.repeat(32), envelope: rnd(20), leaf_hash: rndHex(32) };
      const first = await db.repos.evidenceEvents.insert(e);
      const again = await db.repos.evidenceEvents.insert({ ...e, envelope: rnd(20) });
      expect(again).toEqual(first);
      const pa = { deal_id: dealId, side: 'A' as const, envelope: rnd(30), anchor_ledger: 3, leaf_hash: rndHex(32) };
      const p1 = await db.repos.passportAttestations.insert(pa);
      expect(await db.repos.passportAttestations.insert({ ...pa, envelope: rnd(30) })).toEqual(p1);
      const g = { deal_id: dealId, leaf_hash: rndHex(32), envelope: rnd(10), ledger_index: 4 };
      const g1 = await db.repos.releaseGates.insert(g);
      expect(await db.repos.releaseGates.insert({ ...g, envelope: rnd(10) })).toEqual(g1);
    });

    it('P3.1-05 two writers with the same (deal_id, seq): exactly one wins, the other gets SeqTaken', async () => {
      const results: string[] = [];
      for (let i = 0; i < 20; i++) {
        const dealId = await newDeal(db);
        const mk = () => ({
          deal_id: dealId,
          seq: 0,
          prev_hash: '00'.repeat(32),
          envelope: rnd(20),
          leaf_hash: rndHex(32),
        });
        const r = await Promise.allSettled([
          db.repos.evidenceEvents.insert(mk()),
          db.repos.evidenceEvents.insert(mk()),
        ]);
        expect(r.filter((x) => x.status === 'fulfilled').length).toBe(1);
        const lost = r.find((x) => x.status === 'rejected') as PromiseRejectedResult;
        expect(lost.reason).toBeInstanceOf(SeqTaken);
        results.push((lost.reason as SeqTaken).name);
      }
      observe('seq race losers', [...new Set(results)]);
    });

    it('concurrent appendNext: 30 writers get seq 0..29 with no gap and an unbroken prev_hash chain', async () => {
      const dealId = await newDeal(db);
      const rows = await Promise.all(Array.from({ length: 30 }, () => addEvent(db, dealId)));
      const all = await db.repos.evidenceEvents.listAfter(dealId, -1);
      expect(all.map((e) => e.seq)).toEqual(Array.from({ length: 30 }, (_, i) => i));
      expect(rows.length).toBe(30);
      for (const [i, e] of all.entries())
        expect(e.prev_hash).toBe(i === 0 ? '00'.repeat(32) : (all[i - 1]?.leaf_hash as string));
      const head = await sql<{ head_seq: number }>`SELECT head_seq FROM deal_head WHERE deal_id = ${dealId}`.execute(
        db.kysely,
      );
      expect(head.rows[0]?.head_seq).toBe(29);
    });

    it('a failed appendNext rolls the head back, so the seq is not burnt', async () => {
      const dealId = await newDeal(db);
      await addEvent(db, dealId);
      await expect(
        db.transaction((r) =>
          r.evidenceEvents.appendNext(dealId, () => {
            throw new Error('signing failed');
          }),
        ),
      ).rejects.toThrow('signing failed');
      expect((await addEvent(db, dealId)).seq).toBe(1);
    });

    it('deal_head only moves forward by one and is never deleted', async () => {
      const dealId = await newDeal(db);
      await addEvent(db, dealId);
      const r = {
        skip: await refusal(
          sql`UPDATE deal_head SET head_seq = head_seq + 2 WHERE deal_id = ${dealId}`.execute(db.kysely),
        ),
        back: await refusal(
          sql`UPDATE deal_head SET head_seq = head_seq - 1 WHERE deal_id = ${dealId}`.execute(db.kysely),
        ),
        del: await refusal(sql`DELETE FROM deal_head WHERE deal_id = ${dealId}`.execute(db.kysely)),
        truncate: await refusal(sql`TRUNCATE deal_head`.execute(db.kysely)),
      };
      for (const x of Object.values(r)) expect(x.message).toMatch(/moves forward by one|append-only/);
      observe('deal_head refusals', r);
    });

    it('P3.1-08 the outbox: 4 workers with FOR UPDATE SKIP LOCKED process 1,000 rows, each exactly once', async () => {
      const topic = `t-${rndHex(4)}`;
      await db.transaction(async (r) => {
        for (let i = 0; i < 1000; i++) await r.outbox.enqueue({ topic, payload: rnd(8) });
      });
      const processed = new Map<string, number>();
      const worker = async () => {
        for (;;) {
          const n = await db.transaction(async (r) => {
            const rows = (await r.outbox.claim(40)).filter((x) => x.topic === topic);
            await sleep(1); // widen the window in which another worker could take the same rows
            for (const row of rows) processed.set(row.id, (processed.get(row.id) ?? 0) + 1);
            await r.outbox.markSent(rows.map((x) => x.id));
            return rows.length;
          });
          if (n === 0) return;
        }
      };
      await Promise.all([worker(), worker(), worker(), worker()]);
      expect(processed.size).toBe(1000);
      expect([...processed.values()].every((c) => c === 1)).toBe(true);
      const unsent = await sql<{
        n: string;
      }>`SELECT count(*) AS n FROM outbox WHERE topic = ${topic} AND sent_at IS NULL`.execute(db.kysely);
      expect(Number(unsent.rows[0]?.n)).toBe(0);
      observe('outbox', { processed: processed.size, maxCount: Math.max(...processed.values()) });
    });

    it('outbox rows with a deal replay by seq, and deal_id and seq go together', async () => {
      const dealId = uuid7();
      for (const seq of [2, 0, 1, 3])
        await db.repos.outbox.enqueue({ topic: 'deal_events', payload: rnd(4), deal_id: dealId, seq });
      expect((await db.repos.outbox.listAfter(dealId, 0)).map((x) => x.seq)).toEqual([1, 2, 3]);
      const lonely = await refusal(db.repos.outbox.enqueue({ topic: 'x', payload: rnd(1), seq: 4 }));
      expect(lonely.code).toBe('23514');
      observe('outbox pair check', lonely);
    });

    it('enqueueNext gives every topic of a deal one shared gap-free seq, also under concurrent transactions (I-W-5)', async () => {
      const dealId = uuid7();
      await Promise.all(
        ['deal.event', 'deal.state', 'signature.request', 'deal.event', 'deal.state', 'deal.event'].map((topic) =>
          db.transaction(async (r) => {
            await r.outbox.enqueueNext(dealId, topic, rnd(4));
            await sleep(1);
          }),
        ),
      );
      const rows = await db.repos.outbox.listAfter(dealId, -1);
      expect(rows.map((x) => x.seq)).toEqual([0, 1, 2, 3, 4, 5]);
      // another deal counts from 0, and a plain `enqueue` with a seq still works beside it
      const other = uuid7();
      await db.transaction((r) => r.outbox.enqueueNext(other, 'deal.event', rnd(4)));
      expect((await db.repos.outbox.listAfter(other, -1)).map((x) => x.seq)).toEqual([0]);
    });

    it('signed-request nonces (DESIGN 8.10): the first use wins, a reuse is refused, old ones are pruned', async () => {
      const n = rndHex(32);
      expect(await db.repos.usedNonces.consume(n, 'key-a', 100)).toBe(true);
      expect(await db.repos.usedNonces.consume(n, 'key-b', 101)).toBe(false);
      const m = rndHex(32);
      const wins = await Promise.all(
        Array.from({ length: 8 }, () => db.repos.usedNonces.consume(m, 'key-a', 5_000_000)),
      );
      expect(wins.filter(Boolean).length).toBe(1);
      expect(await db.repos.usedNonces.pruneBelow(1_000_000)).toBeGreaterThanOrEqual(1);
      expect(await db.repos.usedNonces.consume(n, 'key-a', 5_000_001)).toBe(true);
    });

    it('FROST nonces (DESIGN 6.4): one atomic mark per commitment, whatever the message', async () => {
      const dealId = uuid7();
      const u = { key_id: 'hsm-1', commitment_id: rndHex(8), deal_id: dealId, message_hash: rndHex(32) };
      const wins = await Promise.all(Array.from({ length: 8 }, () => db.repos.frostNonceUses.markUsed(u)));
      expect(wins.filter(Boolean).length).toBe(1);
      expect(await db.repos.frostNonceUses.markUsed({ ...u, message_hash: rndHex(32) })).toBe(false);
      expect(await db.repos.frostNonceUses.get(u.key_id, u.commitment_id)).toEqual({
        deal_id: dealId,
        message_hash: u.message_hash,
      });
      const r = await asRole(db, 'app_rw', (q) => refusal(q(`DELETE FROM frost_nonce_use`)));
      expect(r.code).toBe('42501');
    });
  });

  describe(`repositories on ${engine}`, () => {
    it('deal and deal_key round-trip as plain objects', async () => {
      const d = await db.repos.deals.insert({
        state: 'DRAFT',
        network: 'standalone',
        contract_root: rndHex(32),
        payout_a: ADDR[0],
        payout_b: `${ADDR[1]}:12`,
        amount_drops: '100000000000000000',
      });
      expect(d.amount_drops).toBe('100000000000000000');
      expect(d.contract_root).toMatch(/^[0-9a-f]{64}$/);
      const seal = rndHex(32);
      const u = await db.repos.deals.update(d.deal_id, {
        state: 'WALLET_LOCKED',
        deal_seal: seal,
        was_locked: true,
        escrow_sequence: 12345678901,
        cancel_after: 800000000,
      });
      expect(u).toMatchObject({
        state: 'WALLET_LOCKED',
        deal_seal: seal,
        was_locked: true,
        escrow_sequence: 12345678901,
      });
      expect(Object.getPrototypeOf(u)).toBe(Object.prototype);
      const keys = [clientKey('alice'), clientKey('bob'), lawyerKey('lawyerA'), lawyerKey('lawyerB')];
      for (const k of keys) await db.repos.dealKeys.insert(d.deal_id, k);
      const back = await db.repos.dealKeys.list(d.deal_id);
      expect(back.map((k) => k.role)).toEqual(['alice', 'bob', 'lawyerA', 'lawyerB']);
      expect(back[0]).toMatchObject({ id_method: 'zkpassport', commitment: keys[0]?.commitment, contract_sig: null });
      expect(back[2]?.pq_binding_sigs.length).toBe(2);
      const mismatched = clientKey('alice');
      await expect(
        db.repos.dealKeys.insert(d.deal_id, {
          ...mismatched,
          pq: { ...mismatched.pq, pq_key_hash: rndHex(32) as never },
        }),
      ).rejects.toThrow('key hash');
    });

    it('lawyer, bar and ledger repositories round-trip', async () => {
      const ops = ADDR[2];
      await db.repos.lawyers.insert({ ops_account: ops, jurisdiction: 'GB', bar_number_sha256: rndHex(32) });
      expect(await db.repos.lawyers.get(ops)).toMatchObject({ jurisdiction: 'GB' });
      const vh = rndHex(32);
      const v = {
        envelope_sha256: vh,
        ops_account: ops,
        envelope: rnd(20),
        status: 'active' as const,
        checked_at_ledger: 12,
        checked_at_ledger_hash: 'AB',
      };
      expect(await db.repos.barVerifications.insert(v)).toEqual(v);
      expect((await db.repos.barVerifications.listFor(ops)).length).toBe(1);
      const tx = rndHex(32);
      const o = {
        tx_hash: tx,
        ledger_index: 3,
        tx_index: 1,
        account: ops,
        tx_type: 'Payment',
        result: 'tesSUCCESS',
        meta: [{ nested: true }],
      };
      // I-3.5-c: the caller learns whether the row is new, so a watcher queues each observation once.
      expect(await db.repos.ledgerObservations.insert(o)).toBe(true);
      expect(await db.repos.ledgerObservations.insert(o)).toBe(false);
      expect(await db.repos.ledgerObservations.listForAccount(ops, 0)).toEqual([o]);
      await db.repos.watcherCursors.advance(ops, 10);
      await db.repos.watcherCursors.advance(ops, 7);
      expect(await db.repos.watcherCursors.get(ops)).toBe(10);
    });

    it('signature requests, signatures and checkpoints round-trip', async () => {
      const dealId = await newDeal(db);
      const req = await db.repos.signatureRequests.insert({
        deal_id: dealId,
        purpose: 'escrow_finish',
        unsigned_tx: { TransactionType: 'EscrowFinish', list: [1, 2] },
        last_ledger: 50,
      });
      expect(req.status).toBe('open');
      expect(req.unsigned_tx).toEqual({ TransactionType: 'EscrowFinish', list: [1, 2] });
      await db.repos.signatures.insert({ request_id: req.request_id, role: 'alice', signer_blob: 'AA' });
      await db.repos.signatures.insert({ request_id: req.request_id, role: 'alice', signer_blob: 'BB' });
      expect(await db.repos.signatures.list(req.request_id)).toEqual([
        { request_id: req.request_id, role: 'alice', signer_blob: 'AA' },
      ]);
      expect((await db.repos.signatureRequests.listOpen(dealId)).length).toBe(1);
      await db.repos.signatureRequests.setStatus(req.request_id, 'done');
      expect(await db.repos.signatureRequests.listOpen(dealId)).toEqual([]);
      const root = rndHex(32);
      const size = 1_000_000 + Math.floor(Math.random() * 1000);
      await db.repos.checkpointAnchors.insert({ tree_size: size, root, checkpoint: rnd(10) });
      await db.repos.checkpointAnchors.setAnchor(size, { anchor_tx_hash: 'AB', anchor_ledger: 77 });
      expect((await db.repos.checkpointAnchors.latest())?.anchor_ledger).toBeGreaterThanOrEqual(0);
    });

    it('a transaction rolls back every repository write on a throw', async () => {
      const dealId = await newDeal(db);
      await expect(
        db.transaction(async (r) => {
          await r.outbox.enqueue({ topic: 'rollback-probe', payload: rnd(2), deal_id: dealId, seq: 0 });
          throw new Error('boom');
        }),
      ).rejects.toThrow('boom');
      expect(await db.repos.outbox.listAfter(dealId, -1)).toEqual([]);
    });
  });
}

function zkInput(dealId: string) {
  return {
    deal_id: dealId,
    side: 'A' as const,
    stage: 'onboarding' as const,
    proof: rnd(64),
    registry_roots: {
      chain_id: 1,
      block_number: 123,
      block_hash: `0x${rndHex(32)}`,
      registry_address: `0x${rndHex(20)}`,
      root: `0x${rndHex(32)}`,
      circuit_manifest_version: '0.1.0',
      vkey_hashes: [`0x${rndHex(32)}`],
      identifier_type: 'SALTED' as const,
      dev_mode: false,
    },
    identifier_hash: rndHex(32),
  };
}

function enrollment(
  dealId: string,
  eventId: string,
  keyId: string,
  over: { slot?: 'A' | 'LA' | 'B' | 'LB'; holder_role?: 'phone' | 'console' } = {},
) {
  return {
    key_id: keyId,
    deal_id: dealId,
    evidence_event_id: eventId,
    slot: over.slot ?? 'B',
    holder_role: over.holder_role ?? 'phone',
    ed25519_pub: rndHex(32),
    mldsa65_pub: b64(1952),
    valid_from: 100,
  } as never as import('../../src/repos/identity.ts').EnrollmentKeyRow;
}
