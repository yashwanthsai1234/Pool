// Task 2.3: transaction builders (DESIGN 7.3). P2.3-01 to P2.3-09, snapshots, and a property test.
import { domain, sha256 } from '@legx/core/dealcore';
import { escrowFinishFee } from '@legx/core/fees';
import { MINT_MEMO_TYPE } from '@legx/core/signedContract';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { decode, encode, validate } from 'xrpl';
import {
  build0a,
  build0b,
  build0c,
  build1,
  build2,
  build3,
  build5a,
  build5b,
  build5c,
  build5Domain,
  build5d,
  build5dUnauthorize,
  build5e,
  build5f,
  build7,
  build8,
  build9,
  buildAnchor,
  buildEscrowCancel,
  buildSignerListRotation,
  buildTicketCreate,
  DISALLOW_KINDS,
} from '../../src/builders/index.ts';
import { A, ADDRESSES, ALL, CLOSE, CONDITION, CTX, edPub, FULFILLMENT, fill, MEMO } from './fixtures.ts';

const up = (b: Uint8Array) => Buffer.from(b).toString('hex').toUpperCase();
const txt = (s: string) => up(new TextEncoder().encode(s));
const all = ALL();
type Tx = Record<string, unknown>;
const t = (k: keyof typeof all) => all[k] as unknown as Tx;
const memoOf = (tx: Tx) => (tx.Memos as { Memo: { MemoType: string; MemoData: string } }[]).map((m) => m.Memo);

describe('P2.3-01 / 02 every builder: xrpl.js validate() and a binary codec round trip', () => {
  for (const [name, tx] of Object.entries(all)) {
    it(`${name}`, () => {
      expect(() => validate(tx as unknown as Tx)).not.toThrow();
      expect(decode(encode(tx as never))).toEqual(tx);
    });
  }
});

describe('P2.3-03 snapshots (committed JSON)', () => {
  for (const [name, tx] of Object.entries(all)) {
    it(`${name}`, async () => {
      await expect(`${JSON.stringify(tx, null, 2)}\n`).toMatchFileSnapshot(`./snapshots/${name}.json`);
    });
  }
});

describe('P2.3-04 build1: 75-byte URI and the 195-byte memo', () => {
  const tx = t('1');
  it('exact', () => {
    expect((tx.URI as string).length / 2).toBe(75);
    expect(tx.URI).toMatch(/^[0-9A-F]+$/);
    const [m] = memoOf(tx);
    expect(memoOf(tx)).toHaveLength(1);
    expect(m?.MemoType).toBe(MINT_MEMO_TYPE);
    expect(m?.MemoType).toBe(txt('legx/contract-sigs/v1'));
    expect((m?.MemoData ?? '').length / 2).toBe(195);
    expect(m?.MemoData.startsWith(`01${MEMO.lawyerPubA}`)).toBe(true);
    expect(tx.NFTokenTaxon).toBe(0);
    expect(tx.Flags).toBe(0);
    expect(tx.Account).toBe(A.lawyerA);
  });
});

describe('P2.3-05 build7: one gate memo, no CredentialIDs', () => {
  it('exact', () => {
    const tx = t('7');
    const leaf = sha256(fill(5));
    expect(memoOf(tx)).toEqual([{ MemoType: txt('legx/release-gate/v1'), MemoData: up(leaf) }]);
    expect('CredentialIDs' in tx).toBe(false);
    expect(tx).toMatchObject({ Owner: A.alice, OfferSequence: 42, Condition: CONDITION, Fulfillment: FULFILLMENT });
  });
});

describe('P2.3-06 build5b: Domain is 01 || root || seal', () => {
  it('exact', () => {
    const tx = t('5b');
    const want = up(domain(fill(0x11), fill(0x22)));
    expect(tx.Domain).toBe(want);
    expect(want).toBe(`01${'11'.repeat(32)}${'22'.repeat(32)}`);
    expect((tx.Domain as string).length / 2).toBe(65);
    expect(tx.SetFlag).toBe(9);
  });
});

describe('P2.3-07 build0a: Expiration and URI', () => {
  it('exact', () => {
    const tx = t('0a');
    expect(tx.Expiration).toBe(CLOSE + 90 * 86_400);
    expect((tx.URI as string).length / 2).toBe(76);
    expect(tx.URI).toBe(txt(`legx:bar:v1:${'07'.repeat(32)}`));
    expect(tx.CredentialType).toBe(txt('LEGX_ATTORNEY'));
    expect(tx.Subject).toBe(A.lawyerA);
  });
});

describe('P2.3-08 fees at a 10-drop base', () => {
  it('7, 8 and 9', () => {
    expect(t('7').Fee).toBe('350');
    expect(escrowFinishFee(10, 36, 0)).toBe(350);
    expect(t('8').Fee).toBe('50');
    expect(t('9').Fee).toBe('200000');
  });
  it('every setup-key transaction pays the base fee, multisigned ones base x 5', () => {
    for (const k of [
      '0a',
      '0b',
      '1',
      '2',
      '3',
      '5a',
      '5b',
      '5c-check',
      '5d',
      '5e-A',
      '5f-A',
      '5g',
      'exp',
      'anchor',
    ] as const) {
      expect(t(k).Fee, k).toBe('10');
    }
    expect(t('rotation').Fee).toBe('50');
    expect(t('ticket').Fee).toBe('50');
  });
});

describe('P2.3-09 Mainnet is refused', () => {
  const mainnet = { network: 'mainnet' } as never;
  it('a Mainnet or unknown network throws, in every builder', () => {
    for (const bad of [mainnet, { network: 'livenet' } as never, { network: undefined } as never]) {
      expect(() => build2({ alice: A.alice, shell: A.shell, amount: '1' }, bad)).toThrow(/Mainnet|refuses network/);
      expect(() => build9({ shell: A.shell, destination: A.alice, ownerReserveDrops: '1' }, bad)).toThrow();
      expect(() =>
        buildAnchor({ anchorAccount: A.anchor, originHash: fill(1), treeSize: 1n, root: fill(2) }, bad),
      ).toThrow();
      expect(() => build0b({ subject: A.alice, issuer: A.issuer }, bad)).toThrow();
      expect(() => build0c({ subject: A.alice, issuer: A.issuer }, bad)).toThrow();
    }
  });
  it('a Mainnet X-address throws, and so does any other X-address', () => {
    const xMain = 'XVLhHMPHU98es4dbozjVtdWzVrDjtV5fdx1mHp98tDMoQXb';
    const xTest = 'T7YChPFWifjCAXLEtg5N74c7fSAYsvSokwcmBPBUZWhxH5P';
    expect(() => build2({ alice: xMain, shell: A.shell, amount: '1' }, CTX)).toThrow(/Mainnet X-address/);
    expect(() => build2({ alice: xTest, shell: A.shell, amount: '1' }, CTX)).toThrow(/X-addresses/);
  });
  it('paying, preauthorizing or closing into oneself throws', () => {
    expect(() => build2({ alice: A.shell, shell: A.shell, amount: '1' }, CTX)).toThrow(/differ/);
    expect(() => build5d({ shell: A.shell, releaser: A.shell }, CTX)).toThrow(/differ/);
    expect(() => build9({ shell: A.shell, destination: A.shell, ownerReserveDrops: '1' }, CTX)).toThrow(/differ/);
    expect(() => build8({ shell: A.shell, payout: A.shell, amount: '1', slot: { sequence: 1 } }, CTX)).toThrow(
      /differ/,
    );
  });
  it('a bad checksum throws', () => {
    expect(() =>
      build2(
        { alice: `${A.alice.slice(0, -1)}${A.alice.endsWith('a') ? 'b' : 'a'}`, shell: A.shell, amount: '1' },
        CTX,
      ),
    ).toThrow();
  });
  it('a bad base fee throws', () => {
    expect(() =>
      build2({ alice: A.alice, shell: A.shell, amount: '1' }, { network: 'testnet', baseFeeDrops: 0 }),
    ).toThrow();
  });
});

describe('the other rows, field by field', () => {
  it('5a and rotation: four weight-1 entries, quorum 4, never the wallet itself', () => {
    for (const k of ['5a', 'rotation'] as const) {
      expect(t(k).SignerQuorum).toBe(4);
      expect(t(k).SignerEntries).toHaveLength(4);
    }
    expect(() => build5a({ shell: A.shell, signers: [A.x1, A.x2, A.x3, A.shell] }, CTX)).toThrow();
    expect(() => build5a({ shell: A.shell, signers: [A.x1, A.x2, A.x3, A.x3] }, CTX)).toThrow();
    expect(() => build5a({ shell: A.shell, signers: [A.x1, A.x2, A.x3] }, CTX)).toThrow();
  });
  it('5c: one flag per transaction, 12 to 15', () => {
    expect(DISALLOW_KINDS.map((kind) => build5c({ shell: A.shell, kind }, CTX).SetFlag)).toEqual([12, 13, 14, 15]);
    expect(() => build5c({ shell: A.shell, kind: 'x' as never }, CTX)).toThrow();
  });
  it('5g sets DisableMaster (4); 5d authorizes exactly the releaser', () => {
    expect(t('5g').SetFlag).toBe(4);
    expect(t('5d').Authorize).toBe(A.lawyerB);
  });
  it('5e / 5f: party credential types and the binding URI', () => {
    expect(t('5e-A').CredentialType).toBe(txt('LEGX_PARTY_A'));
    expect(t('5e-B').CredentialType).toBe(txt('LEGX_PARTY_B'));
    expect(t('5e-A').URI).toBe(txt(`legx:bind:v1:${up(sha256(fill(9, 64)))}`));
    expect(t('5f-B')).toMatchObject({ Account: A.bob, Issuer: A.shell, CredentialType: txt('LEGX_PARTY_B') });
    expect(() => build5e({ shell: A.shell, subject: A.alice, side: 'A', bindingSig: fill(1, 63) }, CTX)).toThrow();
  });
  it('3: CancelAfter is close_time + days', () => {
    expect(t('3').CancelAfter).toBe(CLOSE + 3 * 86_400);
    expect(() =>
      build3({ alice: A.alice, shell: A.shell, amount: '1', condition: 'zz', closeTime: CLOSE, days: 3 }, CTX),
    ).toThrow();
  });
  it('8: payout tag becomes DestinationTag; slot S or a ticket', () => {
    expect(t('8')).toMatchObject({ Destination: A.payout, DestinationTag: 12345, Sequence: 77 });
    const untagged = build8({ shell: A.shell, payout: A.payout, amount: '1', slot: { ticketSequence: 9 } }, CTX);
    expect(untagged).toMatchObject({ Sequence: 0, TicketSequence: 9 });
    expect('DestinationTag' in untagged).toBe(false);
    for (const bad of [`${A.payout}:01`, `${A.payout}:4294967296`, `${A.payout}:1:2`]) {
      expect(() => build8({ shell: A.shell, payout: bad, amount: '1', slot: { sequence: 1 } }, CTX)).toThrow();
    }
  });
  it('anchor: 72-byte checkpoint memo', () => {
    const [m] = memoOf(t('anchor'));
    expect(m?.MemoType).toBe(txt('legx/ckpt/v1'));
    expect(m?.MemoData).toBe(`${'01'.repeat(32)}00000000000004D2${'02'.repeat(32)}`);
    expect(() =>
      buildAnchor({ anchorAccount: A.anchor, originHash: fill(1), treeSize: -1n, root: fill(2) }, CTX),
    ).toThrow();
    expect(() =>
      buildAnchor({ anchorAccount: A.anchor, originHash: fill(1, 31), treeSize: 1n, root: fill(2) }, CTX),
    ).toThrow();
  });
  it('a base fee other than 10 scales the fees (standalone 200)', () => {
    const c = { network: 'standalone', baseFeeDrops: 200 } as const;
    expect(build8({ shell: A.shell, payout: A.payout, amount: '1', slot: { sequence: 1 } }, c).Fee).toBe('1000');
    expect(build2({ alice: A.alice, shell: A.shell, amount: '1' }, c).Fee).toBe('200');
  });
});

describe('property: random valid inputs always give valid transactions', () => {
  const addrArb = fc.constantFrom(...ADDRESSES);
  const bytes = (n: number) => fc.uint8Array({ minLength: n, maxLength: n });
  const dropsArb = fc.bigInt({ min: 1n, max: 10n ** 17n }).map(String);
  const u32 = fc.integer({ min: 1, max: 2 ** 31 });
  const netArb = fc.record({
    network: fc.constantFrom('standalone', 'testnet', 'devnet'),
    baseFeeDrops: fc.constantFrom(10, 200),
  });
  const check = (tx: unknown) => {
    expect(() => validate(tx as Tx)).not.toThrow();
    expect(decode(encode(tx as never))).toEqual(tx);
  };
  it('credentials, mint, escrow, lock', () => {
    fc.assert(
      fc.property(
        addrArb,
        addrArb,
        bytes(32),
        bytes(64),
        bytes(32),
        u32,
        dropsArb,
        netArb,
        (a, b, h32, h64, h32b, n, amt, ctx) => {
          fc.pre(a !== b);
          const c = ctx as never;
          check(build0a({ issuer: a, subject: b, barVerificationSha256: h32, closeTime: n }, c));
          check(build0b({ subject: b, issuer: a }, c));
          check(build0c({ subject: b, issuer: a }, c));
          check(
            build1(
              {
                lawyerOpsA: a,
                signedContractSeal: h32,
                memo: {
                  ...MEMO,
                  sigLA: h64,
                  sigLB: h64,
                  lawyerPubA: edPub(h32[0] ?? 1),
                  lawyerPubB: edPub(h32b[0] ?? 2),
                },
              },
              c,
            ),
          );
          check(build2({ alice: a, shell: b, amount: amt }, c));
          check(
            build3({ alice: a, shell: b, amount: amt, condition: CONDITION, closeTime: n, days: 1 + (n % 400) }, c),
          );
          check(build5b({ shell: a, contractRoot: h32, dealSeal: h32b }, c));
          check(build5d({ shell: a, releaser: b }, c));
          check(build5e({ shell: a, subject: b, side: n % 2 ? 'A' : 'B', bindingSig: h64 }, c));
          check(build5f({ subject: b, shell: a, side: n % 2 ? 'A' : 'B' }, c));
          check(
            build7(
              {
                releaser: a,
                owner: b,
                offerSequence: n,
                condition: CONDITION,
                fulfillment: FULFILLMENT,
                gateLeafHash: h32,
              },
              c,
            ),
          );
          check(buildEscrowCancel({ account: a, owner: b, offerSequence: n }, c));
          check(buildAnchor({ anchorAccount: a, originHash: h32, treeSize: BigInt(n) * 4096n, root: h32b }, c));
        },
      ),
    );
  });
  it('payments, closes, tickets and signer lists', () => {
    fc.assert(
      fc.property(
        fc.shuffledSubarray(
          ADDRESSES.filter((x) => x !== A.shell),
          { minLength: 4, maxLength: 4 },
        ),
        fc.option(fc.integer({ min: 0, max: 2 ** 32 - 1 }), { nil: undefined }),
        u32,
        dropsArb,
        fc.boolean(),
        netArb,
        (signers, tag, n, amt, ticket, ctx) => {
          const c = ctx as never;
          const slot = ticket ? { ticketSequence: n } : { sequence: n };
          const payout = tag === undefined ? A.payout : `${A.payout}:${tag}`;
          check(build8({ shell: A.shell, payout, amount: amt, slot }, c));
          check(build9({ shell: A.shell, destination: A.alice, ownerReserveDrops: amt, slot }, c));
          check(build5a({ shell: A.shell, signers }, c));
          check(buildSignerListRotation({ shell: A.shell, signers }, c));
          check(buildTicketCreate({ shell: A.shell, count: 1 + (n % 250), sequence: n }, c));
        },
      ),
    );
  });
});

describe('I-2.5-b: builders for key rotation and lawyer replacement', () => {
  it('build5dUnauthorize revokes the preauth; with signers the fee is base x (1 + signers)', () => {
    const tx = build5dUnauthorize({ shell: A.shell, releaser: A.lawyerB }, CTX);
    expect(tx).toMatchObject({ TransactionType: 'DepositPreauth', Unauthorize: A.lawyerB });
    expect(tx).not.toHaveProperty('Authorize');
    expect(validate(tx as never)).toBeUndefined();
    const multi = build5dUnauthorize({ shell: A.shell, releaser: A.lawyerB, signers: 4 }, CTX);
    expect(multi.Fee).toBe(String(5 * (CTX.baseFeeDrops ?? 10)));
    expect(() => build5dUnauthorize({ shell: A.shell, releaser: A.shell }, CTX)).toThrow(/differ/);
  });
  it('build5d with signers is the multisigned variant (fee base x 5)', () => {
    const multi = build5d({ shell: A.shell, releaser: A.lawyerB, signers: 4 }, CTX);
    expect(multi.Fee).toBe(String(5 * (CTX.baseFeeDrops ?? 10)));
    expect(multi.Authorize).toBe(A.lawyerB);
  });
  it('build5Domain sets only Domain (no flag), single or multisigned', () => {
    const tx = build5Domain({ shell: A.shell, contractRoot: fill(1), dealSeal: fill(2), signers: 4 }, CTX);
    expect(Object.keys(tx).sort()).toEqual(['Account', 'Domain', 'Fee', 'TransactionType']);
    expect(tx.Domain).toBe(build5b({ shell: A.shell, contractRoot: fill(1), dealSeal: fill(2) }, CTX).Domain);
    expect(tx.Fee).toBe(String(5 * (CTX.baseFeeDrops ?? 10)));
    expect(validate(tx as never)).toBeUndefined();
  });
});
