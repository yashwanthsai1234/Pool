// P3.2-11 to P3.2-14: the coordinator runs the lock checker and the release gate itself before it stores or relays
// release records (DESIGN 10.2). The real gate is task 1.12; until it lands these tests drive the coordinator through
// the `GatePort` with a gate that fails on cue, and the rows that need the real gate's rules are skipped with the reason.
import { GATE_CODES } from '@legx/contracts/records';
import { lsf } from '@legx/core/lockcheck';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { account, gatePassed, gateRecord, ok, ourEscrow, publicData, toVerified } from './support/lifecycle.ts';
import { addTx, call, holderOf, makeWorld, newDeal, OPS_B, post, rndHex, SHELL, type World } from './support/world.ts';

vi.setConfig({ testTimeout: 180_000 });
let w: World;
beforeAll(async () => {
  w = await makeWorld();
});
afterAll(async () => w.close());

const eventCount = async (id: string) => (await w.db.repos.evidenceEvents.listAfter(id, -1)).length;
const outboxCount = async (id: string) => (await w.db.repos.outbox.listAfter(id, -1)).length;
const stateOf = async (id: string) => ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}`)).state;

describe('P3.2-11 the coordinator runs the gate before it relays release records', () => {
  it('a gate failure stops the relay: nothing stored, no outbox row, no gate record, and the release is refused', async () => {
    const id = await newDeal(w);
    await toVerified(w, id);
    const before = { e: await eventCount(id), o: await outboxCount(id) };
    w.gate.run = async () => ({ ok: false, failed: ['PASSPORT_B_OK'] });
    const r = await gatePassed(w, id);
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('GATE_FAILED');
    expect(r.body.message).toContain('PASSPORT_B_OK');
    expect([await eventCount(id), await outboxCount(id)]).toEqual([before.e, before.o]);
    expect(await w.db.repos.releaseGates.list(id)).toEqual([]);
    // The lawyer cannot skip the gate record: a release naming no stored gate leaf is refused by the machine (I8).
    const finish = addTx(w, 'EscrowFinish', OPS_B, ourEscrow(w));
    const rel = await post(w, id, 'lawyerB', 'release.performed', {
      finish_tx_hash: finish,
      ledger_index: w.ledger.index,
      gate_leaf_hash: rndHex(32),
    });
    expect(rel.status).toBe(422);
    expect(rel.body.error).toBe('refused_gate');
    expect(await stateOf(id)).toBe('VERIFIED');
    w.gate.run = async () => ({ ok: true });
  });

  it('a passing gate is stored once with the record, relayed, and the release then funds the deal (slot S recorded)', async () => {
    const id = await newDeal(w);
    await toVerified(w, id);
    const seen: string[] = [];
    w.gate.run = async (i) => {
      seen.push(i.dealId);
      expect(i.publicData.releaserAccount).toBe(OPS_B);
      return { ok: true };
    };
    const g = ok(await gatePassed(w, id));
    expect(seen).toEqual([id]);
    const stored = await w.db.repos.releaseGates.list(id);
    expect(stored.map((s) => s.leaf_hash)).toEqual([g.leafHash]);
    const finish = addTx(w, 'EscrowFinish', OPS_B, ourEscrow(w));
    ok(
      await post(w, id, 'lawyerB', 'release.performed', {
        finish_tx_hash: finish,
        ledger_index: w.ledger.index,
        gate_leaf_hash: g.leafHash,
      }),
    );
    const v = ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}`));
    expect([v.state, v.exitSlot]).toEqual(['FUNDED', 41]);
  });

  it('a finish submitted by anyone but the sealed releaser is refused (D4, D22)', async () => {
    const id = await newDeal(w);
    await toVerified(w, id);
    const g = ok(await gatePassed(w, id));
    const finish = addTx(w, 'EscrowFinish', account(w, 'alice'), ourEscrow(w));
    const rel = await post(w, id, 'lawyerB', 'release.performed', {
      finish_tx_hash: finish,
      ledger_index: w.ledger.index,
      gate_leaf_hash: g.leafHash,
    });
    expect(rel.status).toBe(422);
    expect(rel.body.error).toBe('refused_submitter');
  });

  it('the coordinator re-runs the lock checker itself: a bad lock fails even if the lawyer says it is fine', async () => {
    const id = await newDeal(w);
    const { toKeysReady, setGoodLock } = await import('./support/lifecycle.ts');
    await toKeysReady(w, id);
    const pd = await publicData(w, id);
    setGoodLock(w, pd.domain);
    ok(await post(w, id, 'alice', 'wallet.locked', { tx_hashes: [addTx(w, 'AccountSet', SHELL)], domain: pd.domain }));
    // The setup key was left on (T-A-01): the master is not disabled.
    const snap = w.ledger.accounts.get(SHELL);
    if (snap)
      w.ledger.accounts.set(SHELL, {
        ...snap,
        accountData: { ...snap.accountData, Flags: Number(snap.accountData.Flags) & ~lsf.DisableMaster },
      });
    const l = await w.ledger.validatedLedger();
    const r = await post(w, id, 'lawyerB', 'lock.verified', {
      ledger: { ledger_index: l.ledgerIndex, ledger_hash: l.ledgerHash },
      findings: [],
    });
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('lock_check_failed');
    expect(r.body.message).toContain('MASTER_DISABLED');
    expect(await stateOf(id)).toBe('WALLET_LOCKED');
    // A ledger hash that is not the anchor's is refused.
    const wrongHash = await post(w, id, 'lawyerB', 'lock.verified', {
      ledger: { ledger_index: l.ledgerIndex, ledger_hash: 'AB'.repeat(32) },
      findings: [],
    });
    expect(wrongHash.body.error).toBe('ledger_mismatch');
  });
});

describe('P3.2-13 each gate code fails on its own and stops the relay', () => {
  it.each(GATE_CODES.map((c) => [c]))('%s', async (code) => {
    const id = await newDeal(w);
    await toVerified(w, id);
    w.gate.run = async () => ({ ok: false, failed: [code] });
    const before = await eventCount(id);
    const r = await gatePassed(w, id);
    expect(r.status).toBe(422);
    expect(r.body.message).toContain(code);
    expect(await eventCount(id)).toBe(before);
    w.gate.run = async () => ({ ok: true });
  });

  it('the stored gate record lists all 15 codes, and a record that omits one is refused by the schema with its path', async () => {
    const id = await newDeal(w);
    await toVerified(w, id);
    const pd = await publicData(w, id);
    const rec = gateRecord(w, id, pd.dealSeal);
    const short = { ...rec, findings: rec.findings.slice(1) };
    const bad = await post(w, id, 'lawyerB', 'release.gate.passed', { gate: short });
    expect(bad.status).toBe(400);
    expect(JSON.stringify(bad.body.issues)).toContain('findings');
    const good = ok(await post(w, id, 'lawyerB', 'release.gate.passed', { gate: rec }));
    const row = (await w.db.repos.releaseGates.list(id))[0];
    const stored = JSON.parse(
      Buffer.from(JSON.parse(new TextDecoder().decode(row?.envelope)).payload, 'base64').toString(),
    );
    expect(stored.predicate.data.gate.findings.map((f: { code: string }) => f.code).sort()).toEqual(
      [...GATE_CODES].sort(),
    );
    expect(good.leafHash).toBe(row?.leaf_hash);
  });
});

describe('P3.2-12 and P3.2-14 need the real release gate (task 1.12)', () => {
  it.skip('P3.2-12 chip policy with a ZK attestation, or a method that differs from the sealed idMethod or the onboarding method: IDENTITY_POLICY_OK fails and the relay stops (needs task 1.12, not done at this time)', () => {});
  it.skip('P3.2-14 a release attestation whose face_match_passed is false: PASSPORT_*_OK fails, no relay (needs task 1.12, not done at this time)', () => {});
});
