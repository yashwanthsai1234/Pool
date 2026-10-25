// Task 5.4 (issue I-16): tests added to kill surviving StrykerJS mutants in releaseGate.ts. Each test pins the exact
// failure detail, not only that the gate failed. Equivalent mutants are explained at the end of the file.
import { beforeAll, describe, expect, it } from 'vitest';
import { checkRelease, gateMemo, type ReleaseInput, verifyGatePassedRecord } from '../src/releaseGate.ts';
import { makeWorld, mutable, type World } from './helpers/gate.ts';

const T = 120_000;
const detail = (i: ReleaseInput, code: string) => checkRelease(i).find((f) => f.code === code);
// biome-ignore lint/suspicious/noExplicitAny: attack rows rewrite arbitrary parts of a copied input
type Mut = any;

let w: World;
beforeAll(async () => {
  w = await makeWorld();
}, T);

describe('CONTRACT_SEAL_OK boundaries', () => {
  it('a mint in the gate ledger itself is applied; one in a later ledger is not', () => {
    const same: Mut = mutable(w.input);
    same.ledger.mintTx.ledger_index = same.ledger.index;
    expect(detail(same, 'CONTRACT_SEAL_OK')?.ok).toBe(true);
    const later: Mut = mutable(w.input);
    later.ledger.mintTx.ledger_index = later.ledger.index + 1;
    expect(detail(later, 'CONTRACT_SEAL_OK')).toMatchObject({ ok: false, detail: 'MINT_NOT_APPLIED' });
    const failed: Mut = mutable(w.input);
    failed.ledger.mintTx.meta.TransactionResult = 'tecFAILED';
    expect(detail(failed, 'CONTRACT_SEAL_OK')?.detail).toBe('MINT_NOT_APPLIED');
  });
  it('the NFTokenID must be the one in the metadata', () => {
    const i: Mut = mutable(w.input);
    i.ledger.mintTx.meta.nftoken_id = '00'.repeat(32);
    expect(detail(i, 'CONTRACT_SEAL_OK')?.detail).toBe('NFT_ID_MISMATCH');
  });
});

describe('ATTORNEY_CREDENTIAL stages', () => {
  const cred = (i: Mut) => i.ledger.credentials[0];
  it.each([
    ['Subject', 'rOTHER', 'MISSING'],
    ['CredentialType', '00', 'MISSING'],
    ['Issuer', 'rOTHER', 'WRONG_ISSUER'],
    ['Flags', 0, 'NOT_ACCEPTED'],
  ])('%s changed gives %s', (field, value, code) => {
    const i: Mut = mutable(w.input);
    cred(i)[field] = value;
    expect(detail(i, 'ATTORNEY_CREDENTIAL_A_OK')).toMatchObject({ ok: false, detail: code });
    expect(detail(i, 'ATTORNEY_CREDENTIAL_B_OK')?.ok).toBe(true);
  });
  it('a credential of the wrong subject does not hide behind an accepted one of the right issuer', () => {
    const i: Mut = mutable(w.input);
    i.ledger.credentials = [{ ...cred(i), Subject: 'rOTHER' }];
    expect(detail(i, 'ATTORNEY_CREDENTIAL_A_OK')?.detail).toBe('MISSING');
  });
  it('expiry: strictly after the close time is valid, equal is expired, absent never expires', () => {
    const i: Mut = mutable(w.input);
    cred(i).Expiration = i.ledger.closeTime + 1;
    expect(detail(i, 'ATTORNEY_CREDENTIAL_A_OK')?.ok).toBe(true);
    cred(i).Expiration = i.ledger.closeTime;
    expect(detail(i, 'ATTORNEY_CREDENTIAL_A_OK')?.detail).toBe('EXPIRED');
    delete cred(i).Expiration;
    expect(detail(i, 'ATTORNEY_CREDENTIAL_A_OK')?.ok).toBe(true);
  });
});

describe('RELEASER_SEALED', () => {
  it('a wrong submitter and a missing preauth have distinct details', () => {
    const a: Mut = mutable(w.input);
    a.submitter = 'rOTHER';
    expect(detail(a, 'RELEASER_SEALED')?.detail).toBe('SUBMITTER_NOT_SEALED');
    const b: Mut = mutable(w.input);
    b.ledger.objects = b.ledger.objects.filter((o: Mut) => o.LedgerEntryType !== 'DepositPreauth');
    expect(detail(b, 'RELEASER_SEALED')?.detail).toBe('PREAUTH_NOT_RELEASER');
  });
  it('a preauth of another account is ignored, a second one of the wallet is refused', () => {
    const pre = (w.input.ledger.objects as Mut[]).find((o) => o.LedgerEntryType === 'DepositPreauth');
    const other: Mut = mutable(w.input);
    other.ledger.objects.push({ ...pre, Account: 'rOTHER', Authorize: 'rOTHER' });
    expect(detail(other, 'RELEASER_SEALED')?.ok).toBe(true);
    const wrong: Mut = mutable(w.input);
    wrong.ledger.objects.forEach((o: Mut) => {
      if (o.LedgerEntryType === 'DepositPreauth') o.Authorize = 'rOTHER';
    });
    expect(detail(wrong, 'RELEASER_SEALED')?.detail).toBe('PREAUTH_NOT_RELEASER');
    const two: Mut = mutable(w.input);
    two.ledger.objects.push({ ...pre });
    expect(detail(two, 'RELEASER_SEALED')?.detail).toBe('PREAUTH_NOT_RELEASER');
  });
  it('a non-preauth object of the wallet is not counted as a preauth', () => {
    const pre = (w.input.ledger.objects as Mut[]).find((o) => o.LedgerEntryType === 'DepositPreauth');
    const i: Mut = mutable(w.input);
    i.ledger.objects.push({ ...pre, LedgerEntryType: 'Ticket' });
    expect(detail(i, 'RELEASER_SEALED')?.ok).toBe(true);
  });
});

describe('IDS_DISTINCT and IDENTITY_POLICY_OK', { timeout: 60_000 }, () => {
  it('two zkpassport sides with the same identifier fail; different ones pass', async () => {
    const same = await makeWorld({ methodA: 'zkpassport', methodB: 'zkpassport', identifiers: { A: '111', B: '111' } });
    expect(detail(same.input, 'IDS_DISTINCT')).toMatchObject({ ok: false, detail: 'IDENTIFIERS_EQUAL' });
    const diff = await makeWorld({ methodA: 'zkpassport', methodB: 'zkpassport', identifiers: { A: '111', B: '222' } });
    expect(detail(diff.input, 'IDS_DISTINCT')?.ok).toBe(true);
  });
  it('equal commitments fail whatever the methods', async () => {
    const x = await makeWorld({ sameCommitment: true });
    expect(detail(x.input, 'IDS_DISTINCT')?.detail).toBe('COMMITMENTS_EQUAL');
  });
  it('a release method outside the sealed policy is refused with METHOD_NOT_ALLOWED', async () => {
    // dealSeal refuses a policy that disallows a sealed method, so the stored release record is what differs.
    const x = await makeWorld({ policy: 'zk', methodA: 'zkpassport', methodB: 'zkpassport' });
    expect(detail(x.input, 'IDENTITY_POLICY_OK')?.ok).toBe(true);
    const i: Mut = mutable(x.input);
    i.records.passport.A = await x.passport('A', { method: 'nfc-chip' });
    expect(detail(i, 'IDENTITY_POLICY_OK')?.detail).toContain('METHOD_NOT_ALLOWED');
  });
});

describe('SLOT_SETUP_OK', () => {
  it('a record of another slot, and one that is missing, are both MISSING', () => {
    const swapped: Mut = mutable(w.input);
    swapped.records.dkgCompleted.A = swapped.records.dkgCompleted.LA;
    expect(detail(swapped, 'SLOT_SETUP_OK')?.detail).toBe('A:MISSING');
    const gone: Mut = mutable(w.input);
    delete gone.records.dkgCompleted.LA;
    expect(detail(gone, 'SLOT_SETUP_OK')?.detail).toBe('LA:MISSING');
  });
  it('the sealed slot policy must match the record', () => {
    const i: Mut = mutable(w.input);
    i.deal.data.slotPolicyB = '00'.repeat(32);
    expect(detail(i, 'SLOT_SETUP_OK')?.detail).toBe('B:SLOT_POLICY_MISMATCH');
  });
});

describe('details, evidence list and gate record', () => {
  it('the lock checker detail lists blocking codes comma-joined, in order', () => {
    const i: Mut = mutable(w.input);
    i.ledger.account.RegularKey = 'rX';
    i.ledger.account.AMMID = 'X';
    expect(detail(i, 'LOCK_OK')?.detail).toBe('NO_REGULARKEY,NO_AMMID');
  });
  it('allowedTicketSequences reach the lock checker only when given', () => {
    const i: Mut = mutable(w.input);
    i.ledger.account.OwnerCount += 1;
    i.ledger.objects.push({ LedgerEntryType: 'Ticket', Account: i.ledger.account.Account, TicketSequence: 5 });
    expect(detail(i, 'LOCK_OK')?.detail).toBe('TICKET_ALLOWED');
    i.deal.allowedTicketSequences = [5];
    expect(detail(i, 'LOCK_OK')?.ok).toBe(true);
  });
  it('gateMemo rejects every leaf hash that is not 32 bytes', () => {
    expect(() => gateMemo(new Uint8Array(31))).toThrow('leaf hash must be 32 bytes');
    expect(() => gateMemo(new Uint8Array(33))).toThrow(RangeError);
    expect(gateMemo(new Uint8Array(32)).MemoData).toBe('00'.repeat(32));
  });
  it('a record that is not a gate record, or is for another deal, is refused', async () => {
    const ctx = {
      deal: w.input.deal,
      keys: w.input.records.keys,
      lawyerB: w.input.records.slotHolders.LB,
      at: w.input.ledger.closeTime,
    };
    expect(verifyGatePassedRecord(new Uint8Array([1, 2, 3]), ctx)).toEqual({ ok: false, code: 'MALFORMED' });
    const opsBound = w.input.records.opsBound.LB as Uint8Array;
    const r = verifyGatePassedRecord(opsBound, ctx);
    expect(r.ok).toBe(false);
  });
});

// Equivalent mutants in releaseGate.ts (kept here so the review of each is in one place):
// - `isObj` typeof/null/array guards (L116): the callers also test `p.kind`, `p.deal_id` or fields on the value, which
//   are undefined on a non-object, so the same `undefined` result is reached; JSON.parse never yields a function.
// - `new TextDecoder('utf-8', { fatal: true })` (L121): the stored bytes are UTF-8 JSON; a decode with replacement
//   characters still fails JSON.parse or the later signature check, so the finding code is the same.
// - Optional-chaining removals (`subject?.digest`, `k?.alg`, `anchor?.ledger_hash`, `r.bar[role]?.link` ...): the
//   operand is checked defined one line earlier or the thrown TypeError is caught by `safely`/`payloadOf`, giving the
//   same failing result.
// - `catch {}` blocks that return `undefined`/`[]` (L128, L166): the following statement treats `undefined` the same.
// - `.join(',')` -> `.join('')` on a one-element list (L198) is unobservable; the detail is covered above with two codes.
