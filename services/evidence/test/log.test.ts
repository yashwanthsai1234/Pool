import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Ed25519NoteVerifier, initSync, MlDsa44NoteVerifier, Note, VerifierList } from '@cloudflare/signed-note-wasm';
import { verifyReceipt } from '@legx/core/checkpoint';
import { verifyInclusion } from '@legx/core/dealcore';
import { verifyConsistency } from '@legx/core/merkle';
import { verifyCheckpoint, vkey } from '@legx/core/pqCheckpoint';
import { sql } from 'kysely';
import { describe, expect, it, vi } from 'vitest';
import { registryFromRows } from '../src/keys.ts';
import { checkpointKey, envelopeKey, putWorm, WormConflict } from '../src/log.ts';
import { makeWorld, type World } from './helpers/world.ts';

vi.setConfig({ testTimeout: 60_000 });

initSync({
  module: readFileSync(createRequire(import.meta.url).resolve('@cloudflare/signed-note-wasm/signed_note_wasm_bg.wasm')),
});

const hexBytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

async function stocked(n = 3): Promise<{ w: World; alice: Awaited<ReturnType<World['enroll']>> }> {
  const w = await makeWorld();
  const alice = await w.enroll('alice', 'A');
  for (let i = 0; i < n; i++) await w.events.append(w.dealId, await w.sign(alice, 'alice', 'shell.opened'));
  return { w, alice };
}

const verifyOpts = async (w: World) => ({
  registry: registryFromRows(await w.db.repos.enrollmentKeys.listForDeal(w.dealId), {
    keys: await w.service.signer.publicKeys(),
    validFrom: 0,
  }),
  at: w.clock.closeTime,
  origin: w.origin,
  keys: w.cpKeys,
});

describe('P3.4-05 the Merkle log integrates every leaf', () => {
  it('each stored event gets a log index in a separate insert, and its inclusion proof verifies', async () => {
    const { w } = await stocked(4);
    const rows = await w.db.repos.evidenceEvents.listAfter(w.dealId, -1);
    const { checkpoint } = await w.logSvc.checkpoint();
    expect(checkpoint.treeSize).toBe(rows.length);
    for (const r of rows) {
      const index = await w.db.repos.evidenceLogEntries.get(r.event_id);
      expect(index).toBeTypeOf('number');
      const path = (await w.log.inclusionProof(index as number, checkpoint.treeSize)).map(hexBytes);
      expect(
        verifyInclusion(r.envelope, index as number, checkpoint.treeSize, path, hexBytes(checkpoint.rootHash)),
      ).toBe(true);
    }
    expect(rows.map((r) => r.leaf_hash).sort()).toEqual(rows.map((r) => r.leaf_hash).sort());
  });

  it('integrating the same event twice adds one leaf; integratePending repairs a crash between commit and integration', async () => {
    const { w } = await stocked(2);
    const [row] = await w.db.repos.evidenceEvents.listAfter(w.dealId, -1);
    const first = await w.logSvc.integrate(row as never);
    expect(await w.logSvc.integrate(row as never)).toBe(first);
    expect((await w.logSvc.checkpoint()).checkpoint.treeSize).toBe(3);
  });

  it('integratePending repairs a crash between commit and integration', async () => {
    let crash = false;
    const w: World = await makeWorld({
      afterStore: async (row) => {
        if (crash) throw new Error('crash after commit');
        await w.logSvc.integrate(row);
      },
    });
    const alice = await w.enroll('alice', 'A');
    crash = true;
    await expect(w.events.append(w.dealId, await w.sign(alice, 'alice', 'shell.opened'))).rejects.toThrow(
      'crash after commit',
    );
    crash = false;
    expect((await w.logSvc.verifyDeal(w.dealId, await verifyOpts(w))).problems.map((p) => p.code)).toContain(
      'NOT_IN_LOG',
    );
    expect(await w.logSvc.integratePending(w.dealId)).toBe(1);
    expect(await w.logSvc.integratePending(w.dealId)).toBe(0);
    await w.logSvc.checkpoint();
    expect(await w.logSvc.verifyDeal(w.dealId, await verifyOpts(w))).toMatchObject({ ok: true });
  });

  it('consistency proofs link successive checkpoints', async () => {
    const { w, alice } = await stocked(3);
    const a = (await w.logSvc.checkpoint()).checkpoint;
    for (let i = 0; i < 4; i++) await w.events.append(w.dealId, await w.sign(alice, 'alice', 'escrow.created'));
    const b = (await w.logSvc.checkpoint()).checkpoint;
    const proof = (await w.log.consistencyProof(a.treeSize, b.treeSize)).map(hexBytes);
    expect(verifyConsistency(a.treeSize, b.treeSize, hexBytes(a.rootHash), hexBytes(b.rootHash), proof)).toBe(true);
  });

  it('a receipt (leaf, index, path, hybrid checkpoint) verifies offline', async () => {
    const { w } = await stocked(5);
    const { checkpoint } = await w.logSvc.checkpoint();
    const [row] = await w.db.repos.evidenceEvents.listAfter(w.dealId, 2, 1);
    const index = (await w.db.repos.evidenceLogEntries.get((row as { event_id: string }).event_id)) as number;
    const path = await w.log.inclusionProof(index, checkpoint.treeSize);
    expect(
      verifyReceipt(
        { leaf: (row as { envelope: Uint8Array }).envelope, index, path, note: checkpoint.note },
        w.origin,
        w.cpKeys,
      ),
    ).toMatchObject({ ok: true });
  });
});

describe('P3.4-07c / P3.4-16 the hybrid checkpoint', () => {
  it('parses and verifies with @cloudflare/signed-note-wasm (both lines) and with our verifier', async () => {
    const { w } = await stocked(3);
    const { checkpoint } = await w.logSvc.checkpoint();
    expect(verifyCheckpoint(checkpoint.note, w.origin, w.cpKeys)).toMatchObject({ ok: true, treeSize: 4 });
    const list = new VerifierList();
    list.addEd25519(new Ed25519NoteVerifier(vkey(w.cpKeys.ed.name, 0x01, w.cpKeys.ed.publicKey)));
    list.addMlDsa44(new MlDsa44NoteVerifier(vkey(w.cpKeys.pq.name, 0x06, w.cpKeys.pq.publicKey)));
    list.build();
    expect(Note.fromBytes(new TextEncoder().encode(checkpoint.note)).verify(list).verified_count).toBe(2);
  });

  it('with the 0x06 line removed: our verifier fails and names it; a standard verifier of the 0x01 key alone passes', async () => {
    const { w } = await stocked(2);
    const { checkpoint } = await w.logSvc.checkpoint();
    const lines = checkpoint.note.split('\n');
    const without = `${lines.filter((l) => !l.startsWith(`— ${w.cpKeys.pq.name} `)).join('\n')}`;
    expect(without).not.toBe(checkpoint.note);
    expect(verifyCheckpoint(without, w.origin, w.cpKeys)).toEqual({ ok: false, code: 'PQ_LINE_MISSING' });
    const standard = new VerifierList();
    standard.addEd25519(new Ed25519NoteVerifier(vkey(w.cpKeys.ed.name, 0x01, w.cpKeys.ed.publicKey)));
    standard.build();
    expect(Note.fromBytes(new TextEncoder().encode(without)).verify(standard).verified_count).toBe(1);
  });

  it('with the 0x06 line altered (one byte of the signature, then the timestamp): our verifier fails; the standard one still passes', async () => {
    const { w } = await stocked(2);
    const { checkpoint } = await w.logSvc.checkpoint();
    const lines = checkpoint.note.split('\n');
    const i = lines.findIndex((l) => l.startsWith(`— ${w.cpKeys.pq.name} `));
    const blob = Buffer.from((lines[i] as string).split(' ')[2] as string, 'base64');
    const flip = (offset: number) => {
      const b = Buffer.from(blob);
      b[offset] = (b[offset] as number) ^ 1;
      const copy = [...lines];
      copy[i] = `— ${w.cpKeys.pq.name} ${b.toString('base64')}`;
      return copy.join('\n');
    };
    expect(verifyCheckpoint(flip(200), w.origin, w.cpKeys)).toEqual({ ok: false, code: 'PQ_SIGNATURE_INVALID' });
    expect(verifyCheckpoint(flip(8), w.origin, w.cpKeys)).toEqual({ ok: false, code: 'PQ_SIGNATURE_INVALID' }); // timestamp byte
    const standard = new VerifierList();
    standard.addEd25519(new Ed25519NoteVerifier(vkey(w.cpKeys.ed.name, 0x01, w.cpKeys.ed.publicKey)));
    standard.build();
    expect(Note.fromBytes(new TextEncoder().encode(flip(200))).verify(standard).verified_count).toBe(1);
  });

  it('with the 0x01 line removed: our verifier names it', async () => {
    const { w } = await stocked(1);
    const { checkpoint } = await w.logSvc.checkpoint();
    const without = checkpoint.note
      .split('\n')
      .filter((l) => !l.startsWith(`— ${w.cpKeys.ed.name} `))
      .join('\n');
    expect(verifyCheckpoint(without, w.origin, w.cpKeys)).toEqual({ ok: false, code: 'ED_LINE_MISSING' });
  });

  it('the checkpoint is stamped with validated ledger time, never the wall clock', async () => {
    const { w } = await stocked(1);
    w.clock.closeTime = 812_345_678;
    const { checkpoint } = await w.logSvc.checkpoint();
    const v = verifyCheckpoint(checkpoint.note, w.origin, w.cpKeys);
    expect(v.ok && v.timestamp).toBe(812_345_678 + 946_684_800);
  });
});

describe('P3.4-09 the WORM store', () => {
  it('the same object twice with different bytes is refused; with the same bytes it is a no-op', async () => {
    const { w } = await stocked(1);
    expect(await putWorm(w.objects, 'x/test', new Uint8Array([1, 2, 3]), 10)).toBe(true);
    expect(await putWorm(w.objects, 'x/test', new Uint8Array([1, 2, 3]), 10)).toBe(false);
    await expect(putWorm(w.objects, 'x/test', new Uint8Array([1, 2, 4]), 10)).rejects.toBeInstanceOf(WormConflict);
    expect(await w.objects.get('x/test')).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('every envelope and every checkpoint is in WORM, byte for byte', async () => {
    const { w } = await stocked(3);
    const { checkpoint } = await w.logSvc.checkpoint();
    for (const r of await w.db.repos.evidenceEvents.listAfter(w.dealId, -1)) {
      expect(await w.objects.get(envelopeKey(r.leaf_hash))).toEqual(r.envelope);
    }
    expect(new TextDecoder().decode(await w.objects.get(checkpointKey(checkpoint.treeSize, checkpoint.rootHash)))).toBe(
      checkpoint.note,
    );
    // publishing the same checkpoint again is a no-op
    await expect(w.logSvc.checkpoint()).resolves.toBeDefined();
  });
});

describe('a superuser rewrites Postgres (DESIGN 8.9): the next verification must catch it', () => {
  // The owner and superusers bypass REVOKE; only the triggers stop them, and a superuser can switch triggers off with
  // session_replication_role = replica. These tests do exactly that, then verify.
  const asSuperuser = async (w: World, statement: ReturnType<typeof sql>) => {
    await sql`set session_replication_role = replica`.execute(w.db.kysely);
    await statement.execute(w.db.kysely);
    await sql`set session_replication_role = origin`.execute(w.db.kysely);
  };
  const clean = async () => {
    const { w } = await stocked(4);
    await w.logSvc.checkpoint();
    const opts = await verifyOpts(w);
    expect(await w.logSvc.verifyDeal(w.dealId, opts)).toMatchObject({ ok: true, problems: [] });
    return { w, opts };
  };
  const codes = (r: { problems: readonly { code: string }[] }) => r.problems.map((p) => p.code);

  it('control: without a trigger bypass the edit is refused by the database itself', async () => {
    const { w } = await clean();
    await expect(
      sql`update evidence_event set envelope = ${new Uint8Array([0])} where seq = 2`.execute(w.db.kysely),
    ).rejects.toThrow(/append-only/);
  });

  it('an edited envelope (same leaf_hash): the stored hash, the WORM copy and the signature all fail', async () => {
    const { w, opts } = await clean();
    const [row] = await w.db.repos.evidenceEvents.listAfter(w.dealId, 1, 1);
    const forged = new Uint8Array((row as { envelope: Uint8Array }).envelope);
    forged[forged.length - 10] = (forged[forged.length - 10] as number) ^ 1;
    await asSuperuser(w, sql`update evidence_event set envelope = ${forged} where seq = 2`);
    const r = await w.logSvc.verifyDeal(w.dealId, opts);
    expect(r.ok).toBe(false);
    expect(codes(r)).toEqual(expect.arrayContaining(['LEAF_HASH_MISMATCH', 'WORM_MISMATCH']));
  });

  it('an edited envelope AND leaf_hash (a careful attacker): the WORM copy, the signature and the log all fail', async () => {
    const { w, opts } = await clean();
    const [row] = await w.db.repos.evidenceEvents.listAfter(w.dealId, 1, 1);
    const forged = new Uint8Array((row as { envelope: Uint8Array }).envelope);
    forged[forged.length - 10] = (forged[forged.length - 10] as number) ^ 1;
    const { createHash } = await import('node:crypto');
    const leaf = createHash('sha256').update(forged).digest();
    await asSuperuser(w, sql`update evidence_event set envelope = ${forged}, leaf_hash = ${leaf} where seq = 2`);
    const r = await w.logSvc.verifyDeal(w.dealId, opts);
    expect(r.ok).toBe(false);
    expect(codes(r)).toEqual(expect.arrayContaining(['WORM_MISSING', 'INCLUSION_FAILED']));
  });

  it('a deleted middle event: the chain breaks', async () => {
    const { w, opts } = await clean();
    await asSuperuser(
      w,
      sql`delete from evidence_log_entry where event_id = (select event_id from evidence_event where seq = 2)`,
    );
    await asSuperuser(w, sql`delete from evidence_event where seq = 2`);
    const r = await w.logSvc.verifyDeal(w.dealId, opts);
    expect(r.ok).toBe(false);
    expect(codes(r)).toContain('CHAIN_BROKEN');
  });

  it('the newest event deleted (the chain stays clean): the head row gives it away', async () => {
    const { w, opts } = await clean();
    await asSuperuser(
      w,
      sql`delete from evidence_log_entry where event_id = (select event_id from evidence_event where seq = 4)`,
    );
    await asSuperuser(w, sql`delete from evidence_event where seq = 4`);
    const r = await w.logSvc.verifyDeal(w.dealId, opts);
    expect(r.ok).toBe(false);
    expect(codes(r)).toEqual(['HEAD_MISMATCH']);
  });

  it('a log index swapped between two events: inclusion fails', async () => {
    const { w, opts } = await clean();
    await asSuperuser(w, sql`update evidence_log_entry set log_index = log_index + 1000 where log_index in (1, 2)`);
    await asSuperuser(
      w,
      sql`update evidence_log_entry set log_index = case log_index when 1001 then 2 else 1 end where log_index in (1001, 1002)`,
    );
    const r = await w.logSvc.verifyDeal(w.dealId, opts);
    expect(r.ok).toBe(false);
    expect(codes(r)).toContain('INCLUSION_FAILED');
  });

  it('a checkpoint row replaced by one signed with other keys: the checkpoint check names it', async () => {
    const { w, opts } = await clean();
    const forged = new TextEncoder().encode(
      'legx.test/evidence\n9\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— legx.test/evidence AAAAAAAA\n',
    );
    await asSuperuser(w, sql`update checkpoint_anchor set checkpoint = ${forged}`);
    const r = await w.logSvc.verifyDeal(w.dealId, opts);
    expect(r.ok).toBe(false);
    expect(r.problems[0]).toMatchObject({ code: 'CHECKPOINT_INVALID' });
  });

  it('a verification with no checkpoint at all is not "ok"', async () => {
    const { w } = await stocked(2);
    const r = await w.logSvc.verifyDeal(w.dealId, await verifyOpts(w));
    expect(r.ok).toBe(false);
    expect(codes(r)).toContain('NO_CHECKPOINT');
  });

  it('events newer than the last checkpoint are counted, not failed', async () => {
    const { w, alice } = await stocked(2);
    await w.logSvc.checkpoint();
    await w.events.append(w.dealId, await w.sign(alice, 'alice', 'escrow.created'));
    const r = await w.logSvc.verifyDeal(w.dealId, await verifyOpts(w));
    expect(r).toMatchObject({ ok: true, uncheckpointed: 1 });
  });
});
