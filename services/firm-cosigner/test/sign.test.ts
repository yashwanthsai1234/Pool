// P3.10-01 to 12: the HSM signs only a message it decoded and matched to the seal, only with the lawyer's user-verified
// approval over the same hash, and only once per nonce commitment.
import { bytesToHex, sha256, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import { commitmentId, releaseShare } from '@legx/core/frostRules';
import { PgNonceLedger } from '@legx/recovery-agent/nonces';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FixtureAuthenticator } from './support/authenticator.ts';
import { type FirmWorld, makeFirmWorld, verifies } from './support/firm.ts';

let fw: FirmWorld;
beforeAll(async () => {
  fw = await makeFirmWorld();
});
afterAll(async () => {
  await fw.w.close();
});

const sha = (m: Uint8Array) => bytesToHex(sha256(m));
const refusedWith = async (p: Promise<unknown>) =>
  (await p.then(
    () => 'signed',
    (e) => e.code ?? e.message,
  )) as string;
const lastAudit = async () => (await fw.audit.entries(fw.w.dealId)).at(-1);

describe('P3.10-01 a good exit transaction', () => {
  it('is decoded, matched to the seal, signed, and logged', async () => {
    const { msg } = fw.exit();
    const before = (await fw.audit.entries()).length;
    const { sig } = await fw.signNormal(msg);
    expect(verifies(fw, sig, msg)).toBe(true);
    const rows = (await fw.audit.entries()).slice(before);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      decision: 'share_released',
      reason: 'signed',
      messageHash: sha(msg),
      seal: fw.seal,
      dealId: fw.w.dealId,
    });
    expect(fw.evidence.events.some((e) => e.kind === ('frost.share.released' as never))).toBe(true);
  });
});

describe('P3.10-02 to 05 only the transactions the service can rebuild', () => {
  const cases: [string, () => ReturnType<FirmWorld['exit']>][] = [
    ['changed account', () => fw.exit({ Destination: 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe' })],
    ['changed tag', () => fw.exit({ DestinationTag: 99 })],
    ['another deal wallet', () => fw.exit({ Account: 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe' })],
    ['another amount', () => fw.exit({ Amount: '5000000001' })],
    ['an extra memo', () => fw.exit({ Memos: [{ Memo: { MemoData: 'AA' } }] })],
    [
      'SetRegularKey',
      () =>
        fw.exit({
          TransactionType: 'SetRegularKey',
          Destination: undefined,
          Amount: undefined,
          RegularKey: 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe',
        }),
    ],
    [
      'SignerListSet',
      () => fw.exit({ TransactionType: 'SignerListSet', Destination: undefined, Amount: undefined, SignerQuorum: 0 }),
    ],
    ['AccountDelete to Bob', () => fw.exit({ TransactionType: 'AccountDelete', Amount: undefined })],
    ['a fee above the cap', () => fw.exit({ Fee: '5000' })],
    ['flags', () => fw.exit({ Flags: 1 })],
  ];
  for (const [name, make] of cases) {
    it(`refuses ${name}; nothing is signed`, async () => {
      const { msg } = make();
      const nonces = async () =>
        (await sql<{ n: string }>`select count(*) as n from frost_nonce_use`.execute(fw.w.db.kysely)).rows[0]?.n;
      const before = await nonces();
      expect(await refusedWith(fw.signNormal(msg))).toBe('NOT_ALLOWED');
      expect(await nonces()).toBe(before); // refused before any nonce was used
      const row = await lastAudit();
      expect(row).toMatchObject({ decision: 'refused', reason: 'NOT_ALLOWED', messageHash: sha(msg) });
    });
  }

  it('refuses a seal that is not the stored one', async () => {
    const { msg } = fw.exit();
    const code = await refusedWith(fw.signNormal(msg, { seal: 'ab'.repeat(32) }));
    expect(code).toBe('SEAL_MISMATCH');
    expect(await lastAudit()).toMatchObject({ decision: 'refused', reason: 'SEAL_MISMATCH', seal: fw.seal });
  });

  it('refuses a blob that does not decode, and a hash that is not the transaction', async () => {
    expect(await refusedWith(fw.signNormal(new Uint8Array(48).fill(7)))).toBe('NOT_ALLOWED');
    const { msg } = fw.exit();
    const other = fw.exit({ Sequence: 6 }).msg;
    // the approval is for `other` but the begin carries `msg` with a mismatched hash claim
    expect(await refusedWith(fw.signNormal(msg, { approval: fw.lawyer.assert(sha256(other)) }))).toBe(
      'APPROVAL_HASH_MISMATCH',
    );
  });
});

describe('P3.10-08 the request must come from the firm operations account', () => {
  it('refuses another key, another account, and a signature over another session', async () => {
    const { msg } = fw.exit();
    const stranger = await import('xrpl').then((x) => x.Wallet.generate(x.ECDSA.ed25519));
    const strangerSecret = new Uint8Array(Buffer.from(stranger.privateKey.slice(2), 'hex'));
    const strangerPub = new Uint8Array(Buffer.from(stranger.publicKey, 'hex'));
    for (const make of [
      (sid: string) => fw.operator(sid, [1, 2], { secret: strangerSecret, pub: strangerPub }),
      (sid: string) => fw.operator(sid, [1, 2], { secret: strangerSecret }),
      (sid: string) => fw.operator(`${sid}x`, [1, 2]),
      (sid: string) => fw.operator(sid, [1, 3]),
    ]) {
      const sid = await fw.sessionFor([1, 2]);
      expect(
        await refusedWith(
          fw.cos.sign({
            dealId: fw.w.dealId,
            slot: 'LA',
            sessionId: sid,
            pair: [1, 2],
            seal: fw.seal,
            operator: make(sid),
          }),
        ),
      ).toBe('OPERATOR_UNAUTHORIZED');
      void msg;
    }
    expect(await lastAudit()).toMatchObject({ decision: 'refused', reason: 'OPERATOR_UNAUTHORIZED' });
  });
});

describe('P3.10-09 and 10 the lawyer approval', () => {
  const hash = () => sha256(fw.exit().msg);
  it('refuses a request with no approval', async () => {
    const { msg } = fw.exit();
    const sid = await fw.sessionFor([1, 2]);
    const run = Promise.all([
      fw.w.holder(1).sign(sid, {
        msg,
        kind: 'xrpl-multisign',
        share: fw.keys[0]?.secret as never,
        pub: fw.keys[0]?.public as never,
        pair: [1, 2],
        check: () => ({ ok: true }),
      }),
      fw.cos.sign({
        dealId: fw.w.dealId,
        slot: 'LA',
        sessionId: sid,
        pair: [1, 2],
        seal: fw.seal,
        operator: fw.operator(sid, [1, 2]),
      }),
    ]);
    expect(await refusedWith(run)).toBe('APPROVAL_MISSING');
    expect(await lastAudit()).toMatchObject({ decision: 'refused', reason: 'APPROVAL_MISSING' });
  });

  const bad: [string, string, () => ReturnType<FixtureAuthenticator['assert']>][] = [
    [
      'a different message hash',
      'APPROVAL_HASH_MISMATCH',
      () => fw.lawyer.assert(hash(), { challengeHash: sha256(utf8ToBytes('other')) }),
    ],
    [
      'a claimed hash that is not this message',
      'APPROVAL_HASH_MISMATCH',
      () => fw.lawyer.assert(hash(), { claimedHash: sha256(utf8ToBytes('other')) }),
    ],
    ['user verification not set', 'APPROVAL_NOT_UV', () => fw.lawyer.assert(hash(), { uv: false })],
    ['another credential', 'APPROVAL_CREDENTIAL_UNKNOWN', () => new FixtureAuthenticator().assert(hash())],
    ['another relying party', 'APPROVAL_INVALID', () => fw.lawyer.assert(hash(), { rpId: 'evil.example' })],
    ['another origin', 'APPROVAL_INVALID', () => fw.lawyer.assert(hash(), { origin: 'https://evil.example' })],
  ];
  for (const [name, code, make] of bad) {
    it(`refuses ${name}`, async () => {
      expect(await refusedWith(fw.signNormal(fw.exit().msg, { approval: make() }))).toBe(code);
    });
  }

  it('refuses a registered credential whose signature is by another key', async () => {
    const forged = new FixtureAuthenticator().assert(hash(), { counter: 1_000_000 });
    const a = { ...forged, credential_id: Buffer.from(fw.lawyer.credentialId).toString('base64') } as typeof forged;
    expect(await refusedWith(fw.signNormal(fw.exit().msg, { approval: a }))).toBe('APPROVAL_INVALID');
  });

  it('refuses an assertion used twice (the challenge is the hash, so a replay is the risk)', async () => {
    const { msg } = fw.exit({ Sequence: 11 });
    const a = fw.lawyer.assert(sha256(msg));
    expect(verifies(fw, (await fw.signNormal(msg, { approval: a })).sig, msg)).toBe(true);
    expect(await refusedWith(fw.signNormal(msg, { approval: a }))).toBe('APPROVAL_REUSED');
  });

  it('refuses a replayed assertion of an authenticator with no counter (the used-assertion table)', async () => {
    const noCounter = new FixtureAuthenticator();
    await fw.approvals.register(
      fw.w.dealId,
      'LA',
      Buffer.from(noCounter.credentialId).toString('base64'),
      noCounter.cosePublicKey(),
    );
    const { msg } = fw.exit({ Sequence: 21 });
    const a = noCounter.assert(sha256(msg), { counter: 0 });
    expect(verifies(fw, (await fw.signNormal(msg, { approval: a })).sig, msg)).toBe(true);
    expect(await refusedWith(fw.signNormal(msg, { approval: a }))).toBe('APPROVAL_REUSED');
  });

  it('refuses an assertion whose counter went backwards', async () => {
    const { msg } = fw.exit({ Sequence: 12 });
    await fw.signNormal(msg, { approval: fw.lawyer.assert(sha256(msg), { counter: 500 }) });
    const m2 = fw.exit({ Sequence: 13 }).msg;
    expect(await refusedWith(fw.signNormal(m2, { approval: fw.lawyer.assert(sha256(m2), { counter: 400 }) }))).toBe(
      'APPROVAL_REUSED',
    );
  });

  it('a refused approval leaves no nonce marked: the next good request signs', async () => {
    const { msg } = fw.exit({ Sequence: 14 });
    expect(await refusedWith(fw.signNormal(msg, { approval: fw.lawyer.assert(sha256(msg), { uv: false }) }))).toBe(
      'APPROVAL_NOT_UV',
    );
    expect(
      verifies(fw, (await fw.signNormal(msg, { approval: fw.lawyer.assert(sha256(msg), { counter: 900 }) })).sig, msg),
    ).toBe(true);
  });
});

describe('P3.10-11 the allow-list', () => {
  const part = (s: string) => utf8ToBytes(s);
  it('signs the allowed tagged messages with an approval, and refuses the rest even with one', async () => {
    const s = fw.deal.sealed;
    const sign = async (tag: string, parts: Uint8Array[], over?: Uint8Array) => {
      const msg = over ?? tupleHash(tag, parts);
      return await refusedWith(fw.signNormal(msg, { kind: 'tagged', tagged: { tag, parts } }));
    };
    // 6.12 contract signature [contractRoot, wallet, role]
    expect(await sign('legx/contract-sign/v1', [s.contractRoot, part(s.walletAddress), part('LA')])).toBe('signed');
    // 6.14 operations binding [contractRoot, opsAccount, lawyerPub, LC, role]
    expect(
      await sign('legx/ops-binding/v1', [
        s.contractRoot,
        part(fw.ops.classicAddress),
        s.slotPubs.LA,
        part('lc'),
        part('LA'),
      ]),
    ).toBe('signed');
    // 6.13 post-quantum cross-signature [dealSeal, slotPub, pqKeyHash]
    expect(await sign('legx/pq-binding/v1', [s.dealSeal as Uint8Array, s.slotPubs.LA, new Uint8Array(32)])).toBe(
      'signed',
    );
    // off the list: an unknown tag, a listed tag for another deal, the wrong role, a message that is not the tupleHash
    expect(await sign('legx/unknown/v1', [s.contractRoot])).toBe('NOT_ALLOWED');
    expect(await sign('legx/contract-sign/v1', [new Uint8Array(32), part(s.walletAddress), part('LA')])).toBe(
      'NOT_ALLOWED',
    );
    expect(await sign('legx/contract-sign/v1', [s.contractRoot, part(s.walletAddress), part('LB')])).toBe(
      'NOT_ALLOWED',
    );
    expect(
      await sign('legx/passport-presence/v1', [
        s.dealSeal as Uint8Array,
        part('LA'),
        new Uint8Array(32),
        new Uint8Array(32),
      ]),
    ).toBe('NOT_ALLOWED');
    expect(
      await sign(
        'legx/contract-sign/v1',
        [s.contractRoot, part(s.walletAddress), part('LA')],
        new Uint8Array(32).fill(1),
      ),
    ).toBe('SESSION_MISMATCH'); // the follower's own preimage check
    // a raw message: neither a sealed multisign nor a tagged message
    expect(await refusedWith(fw.signNormal(new Uint8Array(32).fill(9)))).toBe('NOT_ALLOWED');
  });
});

describe('P3.10-12 atomic nonce marking', () => {
  it('releases exactly one share when 20 requests use one commitment', async () => {
    const mk = () =>
      new PgNonceLedger(fw.w.deps.db, { keyId: 'hsm', dealId: fw.w.dealId, messageHash: '00'.repeat(32) });
    const id = commitmentId({
      identifier: '02',
      hiding: new Uint8Array(33).fill(2),
      binding: new Uint8Array(33).fill(3),
    } as never);
    const out = await Promise.allSettled(
      Array.from({ length: 20 }, () => releaseShare(mk(), id, () => new Uint8Array([1]))),
    );
    expect(out.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  });

  it('a crash after the mark and before the release leaves the commitment used', async () => {
    const ledger = new PgNonceLedger(fw.w.deps.db, { keyId: 'hsm', dealId: fw.w.dealId, messageHash: '11'.repeat(32) });
    await expect(
      releaseShare(ledger, 'cc'.repeat(32), () => {
        throw new Error('crash');
      }),
    ).rejects.toThrow('crash');
    await expect(releaseShare(ledger, 'cc'.repeat(32), () => new Uint8Array([1]))).rejects.toMatchObject({
      code: 'NONCE_USED',
    });
  });
});

describe('P3.10-06 and 07 no share material in logs, a chained audit log', () => {
  it('finds no share, nonce or key bytes in the audit rows or the evidence events', async () => {
    const blob = JSON.stringify([await fw.audit.entries(), fw.evidence.events]);
    const share = bytesToHex(fw.keys[0]?.secret.signingShare as Uint8Array);
    expect(blob).not.toContain(share);
    expect(blob.toLowerCase()).not.toContain('signingshare');
    expect(
      Buffer.from((await fw.vault.raw(fw.w.dealId, 'LA')) as Uint8Array).includes(Buffer.from('signingShare')),
    ).toBe(false);
  });

  it('the chain verifies, and a changed or deleted row is refused by the database', async () => {
    expect(await fw.audit.verifyChain()).toBe(true);
    const k = fw.w.db.kysely;
    await expect(sql`update firm_cosigner_audit set reason = 'x'`.execute(k)).rejects.toThrow(/append-only/);
    await expect(sql`delete from firm_cosigner_audit`.execute(k)).rejects.toThrow(/append-only/);
  });
});
