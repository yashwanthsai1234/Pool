// T-U-31 core parts: approvals (a), the message allow-list (b), the nonce ledger (c), the recovery machine (d); cosign.

import { LAWYER_RECOVERY_TAG } from '@legx/contracts/api';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';
import { deriveAddress, encodeForMultiSigning, encodeForSigning, type Transaction } from 'xrpl';
import { tupleHash } from '../src/dealcore.ts';
import { type FrostError, SigningSession, type SlotName, slotPubkey } from '../src/frost.ts';
import {
  type Approval,
  approvalCheck,
  commitmentId,
  cosign,
  lawyerRecoveryMessage,
  MemoryNonceLedger,
  messageAllowed,
  PROOF_FRESH_MS,
  RECOVERY_DELAY_MS,
  type RecoveryError,
  recoveryAuthorize,
  recoveryCancel,
  recoveryCancelMessage,
  recoverySigned,
  recoveryStart,
  releaseShare,
  type SealedDeal,
  type SignRequest,
} from '../src/frostRules.ts';
import { allow, dkgKeys, enc, hex } from './helpers/frost.ts';

// DKG and X-Wing are slow when the whole suite runs in parallel.
vi.setConfig({ testTimeout: 60_000 });

const lawyerKey = p256.utils.randomSecretKey();
const approver = { p256Pub: p256.getPublicKey(lawyerKey), rpId: 'legx.example' };

/** A WebAuthn assertion as an authenticator makes it (ES256, DER signature). */
function assertion(
  msgHash: Uint8Array,
  opts: { uv?: boolean; rpId?: string; type?: string; key?: Uint8Array; client?: Record<string, unknown> } = {},
): Approval {
  const flags = 0x01 | (opts.uv === false ? 0 : 0x04);
  const authenticatorData = new Uint8Array([...sha256(utf8ToBytes(opts.rpId ?? approver.rpId)), flags, 0, 0, 0, 1]);
  const clientDataJSON = utf8ToBytes(
    JSON.stringify({
      type: opts.type ?? 'webauthn.get',
      challenge: Buffer.from(msgHash).toString('base64url'),
      origin: 'https://legx.example',
      ...opts.client,
    }),
  );
  const signature = p256.sign(
    new Uint8Array([...authenticatorData, ...sha256(clientDataJSON)]),
    opts.key ?? lawyerKey,
    { format: 'der' },
  );
  return { authenticatorData, clientDataJSON, signature };
}

describe('T-U-31a approvals', () => {
  const h = sha256(enc('exit message'));
  it('missing, not user-verified, or over another hash: refused with its own code', () => {
    expect(approvalCheck(undefined, h, approver)).toEqual({ ok: false, code: 'APPROVAL_MISSING' });
    expect(approvalCheck(assertion(h, { uv: false }), h, approver)).toEqual({ ok: false, code: 'APPROVAL_NOT_UV' });
    expect(approvalCheck(assertion(sha256(enc('other'))), h, approver)).toEqual({
      ok: false,
      code: 'APPROVAL_HASH_MISMATCH',
    });
    expect(approvalCheck(assertion(h, { type: 'webauthn.create' }), h, approver)).toEqual({
      ok: false,
      code: 'APPROVAL_HASH_MISMATCH',
    });
    expect(approvalCheck(assertion(h), h, approver)).toEqual({ ok: true });
  });
  it('a forged signature, another relying party, or junk client data is APPROVAL_SIG_INVALID', () => {
    expect(approvalCheck(assertion(h, { key: p256.utils.randomSecretKey() }), h, approver).ok).toBe(false);
    expect(approvalCheck(assertion(h, { rpId: 'evil.example' }), h, approver)).toEqual({
      ok: false,
      code: 'APPROVAL_SIG_INVALID',
    });
    const a = assertion(h);
    expect(approvalCheck({ ...a, signature: new Uint8Array(3) }, h, approver)).toEqual({
      ok: false,
      code: 'APPROVAL_SIG_INVALID',
    });
    expect(approvalCheck(a, h, { ...approver, p256Pub: new Uint8Array(33) })).toEqual({
      ok: false,
      code: 'APPROVAL_SIG_INVALID',
    });
    const junk = utf8ToBytes('not json');
    const sig = p256.sign(new Uint8Array([...a.authenticatorData, ...sha256(junk)]), lawyerKey, { format: 'der' });
    expect(approvalCheck({ ...a, clientDataJSON: junk, signature: sig }, h, approver)).toEqual({
      ok: false,
      code: 'APPROVAL_SIG_INVALID',
    });
  });

  // I-S-F3, WebAuthn L3 7.2 steps 13-14: the origin is expected, and the ceremony was not framed by another site.
  it('refuses an unexpected origin or a cross-origin ceremony', () => {
    const h = sha256(utf8ToBytes('m'));
    const check = (client: Record<string, unknown>, key = approver) => approvalCheck(assertion(h, { client }), h, key);
    expect(check({ origin: 'https://vault.legx.example' })).toEqual({ ok: true });
    expect(check({ origin: 'https://legx.example', crossOrigin: false })).toEqual({ ok: true });
    for (const origin of [
      'https://evil.example',
      'http://legx.example',
      'https://legx.example:8443',
      'https://evillegx.example',
      7,
    ]) {
      expect(check({ origin }), String(origin)).toEqual({ ok: false, code: 'APPROVAL_ORIGIN' });
    }
    expect(check({ crossOrigin: true, topOrigin: 'https://evil.example' })).toEqual({
      ok: false,
      code: 'APPROVAL_ORIGIN',
    });
    const local = { ...approver, rpId: 'localhost' };
    const atLocal = (origin: string) =>
      approvalCheck(assertion(h, { rpId: 'localhost', client: { origin } }), h, local);
    expect(atLocal('http://localhost:63315')).toEqual({ ok: true });
    expect(atLocal('http://localhost.evil.example')).toEqual({ ok: false, code: 'APPROVAL_ORIGIN' });
    const pinned = { ...approver, origins: ['https://vault.legx.example'] };
    expect(check({ origin: 'https://vault.legx.example' }, pinned)).toEqual({ ok: true });
    expect(check({}, pinned)).toEqual({ ok: false, code: 'APPROVAL_ORIGIN' });
  });
});

// ---------- a sealed deal for the allow-list ----------

const slots = await Promise.all((['A', 'LA', 'B', 'LB'] as SlotName[]).map((s) => dkgKeys(s)));
const slotPubs = Object.fromEntries(slots.map((s) => [s.ctx.slot, slotPubkey(s.pub)])) as Record<SlotName, Uint8Array>;
const wallet = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const deal: SealedDeal = {
  walletAddress: wallet,
  contractRoot: randomBytes(32),
  dealSeal: randomBytes(32),
  dealId: '0192f1a0-7b3c-7d4e-8f00-0000000000a1',
  payoutA: { account: 'rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY' },
  payoutB: { account: 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn', tag: 7 },
  exitAmountDrops: '1000000',
  maxFeeDrops: '250000',
  slotPubs,
};
const signerOf = (slot: SlotName) => deriveAddress(hex(slotPubs[slot]).toUpperCase());
const payBob = {
  TransactionType: 'Payment',
  Account: wallet,
  Destination: deal.payoutB.account,
  DestinationTag: 7,
  Amount: '1000000',
  Fee: '50',
  Sequence: 9,
};
const encodeMs = (tx: Record<string, unknown>, slot: SlotName) =>
  Uint8Array.from(Buffer.from(encodeForMultiSigning(tx as unknown as Transaction, signerOf(slot)), 'hex'));
/** A request and its bytes; a transaction xrpl.js cannot encode is paired with the bytes of the good exit. */
const multisign = (tx: Record<string, unknown>, slot: SlotName = 'A') => {
  let msg: Uint8Array;
  try {
    msg = encodeMs(tx, slot);
  } catch {
    msg = encodeMs(payBob, slot);
  }
  return { req: { kind: 'xrpl-multisign', tx } as SignRequest, msg };
};
const tagged = (tag: string, parts: Uint8Array[]) => ({
  req: { kind: 'tagged', tag, parts } as SignRequest,
  msg: tupleHash(tag, parts),
});
const u = utf8ToBytes;

describe('T-U-31b message allow-list', () => {
  it('refuses a disallowed type, a wrong destination or amount, another wallet, and an unknown tag', () => {
    const bad: [SignRequest, Uint8Array][] = [
      multisign({ ...payBob, TransactionType: 'TrustSet' }),
      multisign({
        TransactionType: 'SetRegularKey',
        Account: wallet,
        RegularKey: deal.payoutA.account,
        Fee: '50',
        Sequence: 9,
      }),
      multisign({ ...payBob, Destination: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp' }),
      multisign({ ...payBob, DestinationTag: 8 }),
      multisign({ ...payBob, Amount: '1000001' }),
      multisign({ ...payBob, Account: 'rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY' }),
      multisign({ ...payBob, Flags: 0x00020000 }), // partial payment
      multisign({ ...payBob, SendMax: '5' }),
      multisign({ ...payBob, Fee: '250001' }),
      multisign({ ...payBob, Fee: 50 }),
      multisign({ ...payBob, Sequence: 'not a number' }), // xrpl.js would encode this as 0
      multisign({ ...payBob, LastLedgerSequence: -1 }),
      multisign({ ...payBob, SigningPubKey: hex(slotPubs.A).toUpperCase() }),
      multisign({
        TransactionType: 'AccountDelete',
        Account: wallet,
        Destination: deal.payoutB.account,
        DestinationTag: 7,
        Fee: '200000',
        Sequence: 9,
      }),
      tagged('legx/unknown/v1', [deal.contractRoot]),
      tagged('legx/dealseal/v1', [deal.contractRoot]),
    ].map((x) => [x.req, x.msg]);
    for (const [req, msg] of bad) expect(messageAllowed(req, msg, deal, 'A').ok).toBe(false);
    // The right transaction, but the bytes are another transaction's, or signed as another account.
    const ok = multisign(payBob);
    expect(messageAllowed(ok.req, multisign({ ...payBob, Sequence: 10 }).msg, deal, 'A').ok).toBe(false);
    expect(messageAllowed(ok.req, multisign(payBob, 'B').msg, deal, 'A').ok).toBe(false);
    expect(
      messageAllowed(
        { kind: 'xrpl-multisign', tx: { ...payBob, Amount: { currency: 'USD', value: '1', issuer: wallet } } },
        ok.msg,
        deal,
        'A',
      ).ok,
    ).toBe(false);
  });

  it('allows each allowed kind: the matching multisign, binding, contract signature, presence, PQ cross-signature, ops binding, gate record', () => {
    const good: [SignRequest, Uint8Array, SlotName][] = [
      [multisign(payBob).req, multisign(payBob).msg, 'A'],
      [
        multisign({ ...payBob, Destination: deal.payoutA.account, DestinationTag: undefined }).req,
        multisign({ ...payBob, Destination: deal.payoutA.account, DestinationTag: undefined }).msg,
        'A',
      ],
      ...(() => {
        const del = {
          TransactionType: 'AccountDelete',
          Account: wallet,
          Destination: deal.payoutA.account,
          Fee: '200000',
          Sequence: 9,
          Flags: 0x80000000,
        };
        const m = multisign(del, 'LB');
        return [[m.req, m.msg, 'LB'] as [SignRequest, Uint8Array, SlotName]];
      })(),
      ...[
        tagged('legx/binding/v1', [deal.contractRoot, randomBytes(32), slotPubs.A, u('A')]),
        tagged('legx/passport-presence/v1', [deal.dealSeal!, u('A'), randomBytes(32), randomBytes(32)]),
        tagged('legx/pq-binding/v1', [deal.dealSeal!, slotPubs.A, randomBytes(32)]),
      ].map((x) => [x.req, x.msg, 'A'] as [SignRequest, Uint8Array, SlotName]),
      ...[
        tagged('legx/contract-sign/v1', [deal.contractRoot, u(wallet), u('LA')]),
        tagged('legx/ops-binding/v1', [deal.contractRoot, u('rOps'), slotPubs.LA, randomBytes(32), u('LA')]),
      ].map((x) => [x.req, x.msg, 'LA'] as [SignRequest, Uint8Array, SlotName]),
    ];
    for (const [req, msg, slot] of good) expect(messageAllowed(req, msg, deal, slot)).toEqual({ ok: true });
    const envelope = gateEnvelope('release.gate.passed', deal.contractRoot);
    expect(messageAllowed({ kind: 'gate-record', envelope }, sha256(envelope), deal, 'LB')).toEqual({ ok: true });
  });

  it("refuses tagged messages whose parts do not match this slot or seal, and gate records that are not this deal's", () => {
    const bad: [ReturnType<typeof tagged>, SlotName][] = [
      [tagged('legx/binding/v1', [randomBytes(32), randomBytes(32), slotPubs.A, u('A')]), 'A'],
      [tagged('legx/binding/v1', [deal.contractRoot, randomBytes(32), slotPubs.B, u('A')]), 'A'],
      [tagged('legx/binding/v1', [deal.contractRoot, randomBytes(32), slotPubs.A, u('B')]), 'A'],
      [tagged('legx/contract-sign/v1', [deal.contractRoot, u(wallet), u('LA')]), 'A'],
      [tagged('legx/contract-sign/v1', [deal.contractRoot, u('rOther'), u('LA')]), 'LA'],
      [tagged('legx/passport-presence/v1', [deal.dealSeal!, u('LA'), randomBytes(32), randomBytes(32)]), 'LA'],
      [tagged('legx/pq-binding/v1', [randomBytes(32), slotPubs.A, randomBytes(32)]), 'A'],
      [tagged('legx/ops-binding/v1', [deal.contractRoot, u('rOps'), slotPubs.LB, randomBytes(32), u('LA')]), 'LA'],
    ];
    for (const [x, slot] of bad) expect(messageAllowed(x.req, x.msg, deal, slot).ok).toBe(false);
    const ok = tagged('legx/binding/v1', [deal.contractRoot, randomBytes(32), slotPubs.A, u('A')]);
    expect(messageAllowed(ok.req, randomBytes(32), deal, 'A').ok).toBe(false); // bytes are not the tuple hash
    const noSeal = { ...deal, dealSeal: undefined };
    const pq = tagged('legx/pq-binding/v1', [deal.dealSeal!, slotPubs.A, randomBytes(32)]);
    expect(messageAllowed(pq.req, pq.msg, noSeal, 'A').ok).toBe(false);
    const env = gateEnvelope('release.gate.passed', deal.contractRoot);
    expect(messageAllowed({ kind: 'gate-record', envelope: env }, sha256(env), deal, 'LA').ok).toBe(false);
    expect(messageAllowed({ kind: 'gate-record', envelope: env }, randomBytes(32), deal, 'LB').ok).toBe(false);
    const other = gateEnvelope('release.performed', deal.contractRoot);
    expect(messageAllowed({ kind: 'gate-record', envelope: other }, sha256(other), deal, 'LB').ok).toBe(false);
    const junk = enc('{');
    expect(messageAllowed({ kind: 'gate-record', envelope: junk }, sha256(junk), deal, 'LB').ok).toBe(false);
  });
});

describe('OD-37 shipment and receipt tags', () => {
  const id = u(deal.dealId!);
  const seal = deal.dealSeal!;
  const h = () => randomBytes(32);
  const ship = (over: Partial<Record<number, Uint8Array>> = {}) => {
    const parts = [id, seal, h(), u('DHL'), u('JD0146'), Uint8Array.of(0, 0, 3, 232)];
    for (const [k, v] of Object.entries(over)) parts[Number(k)] = v as Uint8Array;
    return tagged('legx/shipment/v1', parts);
  };
  const rcpt = (over: Partial<Record<number, Uint8Array>> = {}) => {
    const parts = [id, seal, h(), h(), Uint8Array.of(0), Uint8Array.of(0, 0, 3, 233)];
    for (const [k, v] of Object.entries(over)) parts[Number(k)] = v as Uint8Array;
    return tagged('legx/receipt/v1', parts);
  };
  const allowed = (x: ReturnType<typeof tagged>, slot: SlotName, d: SealedDeal = deal) =>
    messageAllowed(x.req, x.msg, d, slot).ok;

  it('slot B alone signs a shipment; slot A alone signs a receipt', () => {
    expect(allowed(ship(), 'B')).toBe(true);
    for (const s of ['A', 'LA', 'LB'] as const) expect(allowed(ship(), s)).toBe(false);
    for (const c of [0, 1, 2]) expect(allowed(rcpt({ 4: Uint8Array.of(c) }), 'A')).toBe(true);
    for (const s of ['B', 'LA', 'LB'] as const) expect(allowed(rcpt(), s)).toBe(false);
  });
  it('refuses another deal, another seal, a deal without seal or id, and malformed parts', () => {
    const other = u('0192f1a0-7b3c-7d4e-8f00-0000000000a2');
    expect(allowed(ship({ 0: other }), 'B')).toBe(false);
    expect(allowed(ship({ 1: h() }), 'B')).toBe(false);
    expect(allowed(ship(), 'B', { ...deal, dealSeal: undefined })).toBe(false);
    expect(allowed(ship(), 'B', { ...deal, dealId: undefined })).toBe(false);
    expect(allowed(ship({ 2: randomBytes(31) }), 'B')).toBe(false);
    expect(allowed(ship({ 3: new Uint8Array() }), 'B')).toBe(false);
    expect(allowed(ship({ 4: u('x'.repeat(65)) }), 'B')).toBe(false);
    expect(allowed(ship({ 5: Uint8Array.of(1, 2, 3) }), 'B')).toBe(false);
    expect(allowed(rcpt({ 0: other }), 'A')).toBe(false);
    expect(allowed(rcpt({ 1: h() }), 'A')).toBe(false);
    expect(allowed(rcpt({ 3: randomBytes(33) }), 'A')).toBe(false);
    expect(allowed(rcpt({ 4: Uint8Array.of(3) }), 'A')).toBe(false);
    expect(allowed(rcpt({ 4: Uint8Array.of(0, 0) }), 'A')).toBe(false);
    expect(allowed(rcpt({ 5: Uint8Array.of(0, 0, 0, 0, 1) }), 'A')).toBe(false);
    const short = tagged('legx/receipt/v1', [id, seal, h(), h(), Uint8Array.of(0)]);
    expect(allowed(short, 'A')).toBe(false);
  });
});

function gateEnvelope(kind: string, root: Uint8Array): Uint8Array {
  const st = { subject: [{ name: 'deal:x', digest: { sha256: hex(root) } }], predicate: { kind } };
  return enc(
    JSON.stringify({
      payloadType: 'application/vnd.legx.event+json;v=1',
      payload: Buffer.from(JSON.stringify(st)).toString('base64'),
      signatures: [],
    }),
  );
}

// OD-33: step 5f, the client accepts its party badge with its own slot account (the slot's group key), single-signed.
describe('OD-33 CredentialAccept by the slot account', () => {
  const partyType = (side: 'A' | 'B') => Buffer.from(`LEGX_PARTY_${side}`).toString('hex').toUpperCase();
  const accept = (slot: SlotName = 'A') => ({
    TransactionType: 'CredentialAccept',
    Account: signerOf(slot),
    Issuer: wallet,
    CredentialType: partyType(slot === 'B' ? 'B' : 'A'),
    Fee: '12',
    Sequence: 1,
    LastLedgerSequence: 100,
    SigningPubKey: hex(slotPubs[slot]).toUpperCase(),
  });
  /** A request and its signing bytes; a transaction xrpl.js cannot encode is paired with the good one's bytes. */
  const single = (tx: Record<string, unknown>) => {
    let msg: Uint8Array;
    try {
      msg = Uint8Array.from(Buffer.from(encodeForSigning(tx as unknown as Transaction), 'hex'));
    } catch {
      msg = Uint8Array.from(Buffer.from(encodeForSigning(accept() as unknown as Transaction), 'hex'));
    }
    return { req: { kind: 'xrpl-single', tx } as SignRequest, msg };
  };

  it('allows exactly the sealed acceptance of each client slot', () => {
    for (const slot of ['A', 'B'] as const) {
      const { req, msg } = single(accept(slot));
      expect(messageAllowed(req, msg, deal, slot), slot).toEqual({ ok: true });
    }
  });

  it('refuses every variant', () => {
    const good = accept();
    const bad: [string, Record<string, unknown>, SlotName?][] = [
      ['another account', { ...good, Account: signerOf('B') }],
      ['another issuer', { ...good, Issuer: deal.payoutA.account }],
      ['the other side type', { ...good, CredentialType: partyType('B') }],
      ['LEGX_ATTORNEY', { ...good, CredentialType: Buffer.from('LEGX_ATTORNEY').toString('hex').toUpperCase() }],
      ['an extra field', { ...good, Memos: [{ Memo: { MemoData: '00' } }] }],
      ['a ticket', { ...good, TicketSequence: 5 }],
      ['another type', { ...good, TransactionType: 'CredentialDelete' }],
      ['a multisign (empty SigningPubKey)', { ...good, SigningPubKey: '' }],
      ['another key', { ...good, SigningPubKey: hex(slotPubs.B).toUpperCase() }],
      ['a fee above the limit', { ...good, Fee: '250001' }],
      ['flags', { ...good, Flags: 1 }],
      ['a lawyer slot', { ...accept('LA'), CredentialType: partyType('A') }, 'LA'],
    ];
    for (const [what, tx, slot] of bad) {
      const { req, msg } = single(tx);
      expect(messageAllowed(req, msg, deal, slot ?? 'A').ok, what).toBe(false);
    }
    // the request is this transaction, but the bytes to sign are another one's
    const { req } = single(good);
    const other = single({ ...good, Sequence: 2 }).msg;
    expect(messageAllowed(req, other, deal, 'A').ok).toBe(false);
    // the same transaction as a multisign request is still refused
    expect(messageAllowed({ kind: 'xrpl-multisign', tx: good }, single(good).msg, deal, 'A').ok).toBe(false);
  });
});

describe('cosign: allow-list plus approval, as checkMessage', () => {
  const lb = slots[3]!;
  const m = multisign(payBob, 'LB');
  it('the firm HSM refuses without the lawyer approval and the nonce stays unused; signs with it', () => {
    const s = SigningSession.open(lb.keys[1]!.secret, lb.pub, m.msg);
    const t = SigningSession.open(lb.keys[0]!.secret, lb.pub, m.msg);
    const list = [s.commitment, t.commitment];
    const base = { request: m.req, msg: m.msg, deal, slot: 'LB' as const, role: 'firm-hsm' as const, approver };
    const err = (() => {
      try {
        s.signShare(m.msg, list, () => cosign(base));
      } catch (e) {
        return (e as FrostError).message;
      }
    })();
    expect(err).toBe('MESSAGE_REFUSED: APPROVAL_MISSING');
    expect(cosign({ ...base, approver: undefined, approval: assertion(sha256(m.msg)) })).toEqual({
      ok: false,
      reason: 'APPROVAL_MISSING',
    });
    expect(cosign({ ...base, approval: assertion(sha256(m.msg), { uv: false }) })).toEqual({
      ok: false,
      reason: 'APPROVAL_NOT_UV',
    });
    expect(s.signShare(m.msg, list, () => cosign({ ...base, approval: assertion(sha256(m.msg)) }))).toHaveLength(32);
  });
  it('a console holder needs no approval but still the allow-list', () => {
    expect(cosign({ request: m.req, msg: m.msg, deal, slot: 'LB', role: 'console' })).toEqual({ ok: true });
    expect(cosign({ request: m.req, msg: randomBytes(10), deal, slot: 'LB', role: 'console' }).ok).toBe(false);
  });
});

describe('T-U-31c nonce ledger', () => {
  it('two concurrent requests for one commitment: exactly one share is released, the other NONCE_USED', async () => {
    const s = slots[0]!;
    const msg = enc('m');
    const a = SigningSession.open(s.keys[0]!.secret, s.pub, msg);
    const b = SigningSession.open(s.keys[1]!.secret, s.pub, msg);
    const list = [a.commitment, b.commitment];
    const ledger = new MemoryNonceLedger();
    const id = commitmentId(a.commitment);
    const results = await Promise.allSettled(
      [0, 1].map(() => releaseShare(ledger, id, () => a.signShare(msg, list, allow))),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((r) => r.status === 'rejected') as PromiseRejectedResult;
    expect((rejected.reason as FrostError).code).toBe('NONCE_USED');
    expect((rejected.reason as FrostError).message).toContain('signing nonces already used');
    expect(commitmentId(b.commitment)).not.toBe(id);
  });
});

describe('T-U-31d recovery rules', () => {
  const now = 1_800_000_000_000;
  const client = {
    kind: 'client' as const,
    slot: 'A' as const,
    at: now,
    proof: { identifier: '123', provedAt: now - 1000 },
    onboardingIdentifier: '123',
    faceMatch: true,
  };
  const rc = (f: () => unknown) => {
    try {
      f();
    } catch (e) {
      return (e as RecoveryError).code;
    }
    return 'NO_THROW';
  };

  it('client recovery needs the onboarding identifier, a fresh proof and a face match', () => {
    expect(rc(() => recoveryStart({ ...client, proof: { identifier: '999', provedAt: now } }))).toBe(
      'IDENTIFIER_MISMATCH',
    );
    expect(rc(() => recoveryStart({ ...client, faceMatch: false }))).toBe('FACE_MATCH_MISSING');
    expect(
      rc(() => recoveryStart({ ...client, proof: { identifier: '123', provedAt: now - PROOF_FRESH_MS - 1 } })),
    ).toBe('PROOF_STALE');
    expect(rc(() => recoveryStart({ ...client, proof: { identifier: '123', provedAt: now + 1 } }))).toBe('PROOF_STALE');
    const { state, notices } = recoveryStart(client);
    expect(notices).toEqual(['old-device', 'lawyerA', 'lawyerB']);
    expect(state.records[0]!.kind).toBe('frost.recovery.requested');
  });

  it('lawyer recovery needs a request signed by the operations account', () => {
    const sk = ed25519.utils.randomSecretKey();
    const opsPub = new Uint8Array([0xed, ...ed25519.getPublicKey(sk)]);
    const opsAccount = deriveAddress(hex(opsPub).toUpperCase());
    const fields = {
      dealId: '0192f1a0-7b3c-7d4e-8f00-0000000000a1',
      newKeyId: 'LB/console/ed#2',
      ledgerIndex: 90_000_000,
    };
    const signed = lawyerRecoveryMessage(fields.dealId, 'LB', fields.newKeyId, fields.ledgerIndex);
    const req = {
      kind: 'lawyer' as const,
      slot: 'LB' as const,
      at: now,
      ...fields,
      sig: ed25519.sign(signed, sk),
      opsPub,
      opsAccount,
    };
    expect(recoveryStart(req).state.status).toBe('pending');
    // I-S-F1: the signature covers this deal, slot, new key and ledger index, and nothing else
    expect(LAWYER_RECOVERY_TAG).toBe('legx/lawyer-recovery/v1');
    for (const over of [
      { dealId: 'another deal' },
      { newKeyId: 'evil' },
      { ledgerIndex: 90_000_001 },
      { slot: 'LA' as const },
    ]) {
      expect(rc(() => recoveryStart({ ...req, ...over }))).toBe('OPS_SIGNATURE_INVALID');
    }
    expect(rc(() => recoveryStart({ ...req, sig: ed25519.sign(enc('recover LB'), sk) }))).toBe('OPS_SIGNATURE_INVALID');
    expect(rc(() => recoveryStart({ ...req, ledgerIndex: -1 }))).toBe('OPS_SIGNATURE_INVALID');
    expect(rc(() => recoveryStart({ ...req, sig: new Uint8Array(64) }))).toBe('OPS_SIGNATURE_INVALID');
    expect(rc(() => recoveryStart({ ...req, opsAccount: wallet }))).toBe('OPS_SIGNATURE_INVALID');
    expect(rc(() => recoveryStart({ ...req, opsPub: new Uint8Array(32) }))).toBe('OPS_SIGNATURE_INVALID');
  });

  it('a 72-hour delay: 72 h minus 1 s refused, 72 h exactly allowed; the old device can cancel only during it', () => {
    const { state } = recoveryStart(client);
    expect(rc(() => recoveryAuthorize(state, now + RECOVERY_DELAY_MS - 1000))).toBe('RECOVERY_DELAY');
    const auth = recoveryAuthorize(state, now + RECOVERY_DELAY_MS);
    expect(auth.status).toBe('authorized');
    expect(auth.records.map((r) => r.kind)).toEqual(['frost.recovery.requested', 'frost.recovery.authorized']);

    const oldSk = ed25519.utils.randomSecretKey();
    const oldDevicePub = new Uint8Array([0xed, ...ed25519.getPublicKey(oldSk)]);
    const cancel = { sig: ed25519.sign(recoveryCancelMessage(state), oldSk), oldDevicePub };
    expect(rc(() => recoveryCancel(state, now + 1, { ...cancel, sig: new Uint8Array(64) }))).toBe('CANCEL_SIG_INVALID');
    // I-S-F2: a cancel for another recovery of the same slot at the same time does not cancel this one
    const other = recoveryStart(client).state;
    expect(other.recoveryId).not.toBe(state.recoveryId);
    expect(other.recoveryId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(rc(() => recoveryCancel(other, now + 1, cancel))).toBe('CANCEL_SIG_INVALID');
    const cancelled = recoveryCancel(state, now + RECOVERY_DELAY_MS - 1, cancel);
    expect(cancelled.records.at(-1)!.kind).toBe('frost.recovery.cancelled');
    expect(rc(() => recoveryAuthorize(cancelled, now + RECOVERY_DELAY_MS * 2))).toBe('CANCELLED');
    // I-E6: the signed record names the two holders; only after authorization, two distinct roles.
    expect(rc(() => recoverySigned(state, now, ['second-authenticator', 'recovery-agent']))).toBe('RECOVERY_DELAY');
    expect(rc(() => recoverySigned(cancelled, now, ['second-authenticator', 'recovery-agent']))).toBe('CANCELLED');
    expect(recoverySigned(auth, now + RECOVERY_DELAY_MS, ['phone', 'recovery-agent']).records.at(-1)).toEqual({
      kind: 'frost.recovery.signed',
      at: now + RECOVERY_DELAY_MS,
      slot: auth.slot,
      detail: 'signed by phone,recovery-agent',
    });
    expect(() => recoverySigned(auth, now, ['phone', 'phone'])).toThrow('ROLE_INVALID');
    expect(rc(() => recoveryCancel(cancelled, now + 2, cancel))).toBe('CANCELLED');
    expect(rc(() => recoveryCancel(state, now + RECOVERY_DELAY_MS, cancel))).toBe('CANCEL_TOO_LATE');
  });
});
