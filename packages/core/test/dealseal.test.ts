// Task 1.6: deal seal (29 fields) and the Domain value (DESIGN 6.6, IMPLEMENTATION 1.6).
import { execFileSync } from 'node:child_process';
import type { PublicDealData } from '@legx/contracts/deal';
import { SEAL_FIELD_ORDER } from '@legx/contracts/deal';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import * as xrpl from 'xrpl';
import { dealSeal, domain, SEAL_FIELDS, tupleHash } from '../src/dealcore.ts';
import { pyVector } from './helpers/pyref.ts';

const h32 = (n: number) => bytesToHex(new Uint8Array(32).fill(n));
const pub = (n: number) => `ED${h32(n).toUpperCase()}`;
const addr = (n: number) => xrpl.encodeAccountID(new Uint8Array(20).fill(n));
const seal = (d: PublicDealData) => bytesToHex(dealSeal(d));
const deal = (fields: Record<string, unknown>) => fields as unknown as PublicDealData;

// A realistic fixed deal: real classic addresses, payout tags at both ends of the range.
const BASE = deal({
  contractRoot: h32(1),
  signedContractSeal: h32(2),
  walletAddress: addr(0x10),
  xPubA: pub(3),
  xPubB: pub(4),
  commitmentA: h32(5),
  commitmentB: h32(6),
  idMethodA: 'zkpassport',
  idMethodB: 'zkpassport',
  identityPolicy: 'zk-or-chip',
  lawyerPubA: pub(7),
  lawyerPubB: pub(8),
  lawyerCommitmentA: h32(9),
  lawyerCommitmentB: h32(10),
  lawyerOpsA: addr(0x11),
  lawyerOpsB: addr(0x12),
  releaserAccount: addr(0x12),
  slotPolicyA: h32(11),
  slotPolicyLA: h32(12),
  slotPolicyB: h32(13),
  slotPolicyLB: h32(14),
  pqKeyHashA: h32(15),
  pqKeyHashLA: h32(16),
  pqKeyHashB: h32(17),
  pqKeyHashLB: h32(18),
  signerAccounts: [addr(0x24), addr(0x21), addr(0x23), addr(0x22)],
  quorum: 4,
  payoutA: `${addr(0x31)}:0`,
  payoutB: `${addr(0x32)}:4294967295`,
});

// One mutation per field, in DESIGN 6.6 order. lawyerOpsB and releaserAccount must stay equal (T-U-14c), so each
// of those two mutates both; SEAL_FIELDS proves each one still has its own tuple part.
const flip = (h: string) => (h.slice(0, -1) + (h.endsWith('0') ? '1' : '0')) as never;
const NEW_OPS = addr(0x13);
const MUTATE: Record<keyof PublicDealData, (d: PublicDealData) => PublicDealData> = {
  contractRoot: (d) => ({ ...d, contractRoot: flip(d.contractRoot) }),
  signedContractSeal: (d) => ({ ...d, signedContractSeal: flip(d.signedContractSeal) }),
  walletAddress: (d) => ({ ...d, walletAddress: addr(0x19) as never }),
  xPubA: (d) => ({ ...d, xPubA: flip(d.xPubA) }),
  xPubB: (d) => ({ ...d, xPubB: flip(d.xPubB) }),
  commitmentA: (d) => ({ ...d, commitmentA: flip(d.commitmentA) }),
  commitmentB: (d) => ({ ...d, commitmentB: flip(d.commitmentB) }),
  idMethodA: (d) => ({ ...d, idMethodA: 'nfc-chip' }),
  idMethodB: (d) => ({ ...d, idMethodB: 'nfc-chip' }),
  identityPolicy: (d) => ({ ...d, identityPolicy: 'zk' }),
  lawyerPubA: (d) => ({ ...d, lawyerPubA: flip(d.lawyerPubA) }),
  lawyerPubB: (d) => ({ ...d, lawyerPubB: flip(d.lawyerPubB) }),
  lawyerCommitmentA: (d) => ({ ...d, lawyerCommitmentA: flip(d.lawyerCommitmentA) }),
  lawyerCommitmentB: (d) => ({ ...d, lawyerCommitmentB: flip(d.lawyerCommitmentB) }),
  lawyerOpsA: (d) => ({ ...d, lawyerOpsA: NEW_OPS as never }),
  lawyerOpsB: (d) => ({ ...d, lawyerOpsB: NEW_OPS as never, releaserAccount: NEW_OPS as never }),
  releaserAccount: (d) => ({ ...d, releaserAccount: NEW_OPS as never, lawyerOpsB: NEW_OPS as never }),
  slotPolicyA: (d) => ({ ...d, slotPolicyA: flip(d.slotPolicyA) }),
  slotPolicyLA: (d) => ({ ...d, slotPolicyLA: flip(d.slotPolicyLA) }),
  slotPolicyB: (d) => ({ ...d, slotPolicyB: flip(d.slotPolicyB) }),
  slotPolicyLB: (d) => ({ ...d, slotPolicyLB: flip(d.slotPolicyLB) }),
  pqKeyHashA: (d) => ({ ...d, pqKeyHashA: flip(d.pqKeyHashA) }),
  pqKeyHashLA: (d) => ({ ...d, pqKeyHashLA: flip(d.pqKeyHashLA) }),
  pqKeyHashB: (d) => ({ ...d, pqKeyHashB: flip(d.pqKeyHashB) }),
  pqKeyHashLB: (d) => ({ ...d, pqKeyHashLB: flip(d.pqKeyHashLB) }),
  signerAccounts: (d) => ({ ...d, signerAccounts: [...d.signerAccounts.slice(1), addr(0x25)] as never }),
  quorum: (d) => ({ ...d, quorum: 3 as never }),
  payoutA: (d) => ({ ...d, payoutA: `${addr(0x31)}:1` as never }),
  payoutB: (d) => ({ ...d, payoutB: `${addr(0x32)}:4294967294` as never }),
};

describe('T-U-14 the seal commits to every field', () => {
  it('SEAL_FIELDS is the 29 fields of DESIGN 6.6, in the order @legx/contracts freezes', () => {
    expect(SEAL_FIELDS.map(([name]) => name)).toEqual([...SEAL_FIELD_ORDER]);
    expect(SEAL_FIELDS).toHaveLength(29);
  });

  const s0 = seal(BASE);
  for (const [i, [field]] of SEAL_FIELDS.entries()) {
    it(`T-U-14a changing ${field} changes the seal (and tuple part ${i})`, () => {
      const m = MUTATE[field](BASE);
      expect(seal(m)).not.toBe(s0);
      const enc = SEAL_FIELDS[i]?.[1];
      expect(enc && bytesToHex(enc(m))).not.toBe(enc && bytesToHex(enc(BASE)));
    });
  }

  it('T-U-14b shuffling signerAccounts keeps the seal', () => {
    fc.assert(
      fc.property(fc.shuffledSubarray([...BASE.signerAccounts], { minLength: 4, maxLength: 4 }), (accts) => {
        expect(seal({ ...BASE, signerAccounts: accts })).toBe(s0);
      }),
    );
  });

  it('T-U-14c releaserAccount !== lawyerOpsB throws', () => {
    expect(() => dealSeal({ ...BASE, releaserAccount: BASE.lawyerOpsA })).toThrow(/releaserAccount/);
    expect(() => dealSeal({ ...BASE, lawyerOpsB: NEW_OPS as never })).toThrow(/releaserAccount/);
  });
});

describe('T-U-06 seal sensitivity, and the new golden value', () => {
  it('same inputs give the same seal; swapping A and B, the quorum, a payout address or a payout tag change it', () => {
    const s0 = seal(BASE);
    expect(seal(deal({ ...BASE }))).toBe(s0);
    const swapped = deal({
      ...BASE,
      xPubA: BASE.xPubB,
      xPubB: BASE.xPubA,
      commitmentA: BASE.commitmentB,
      commitmentB: BASE.commitmentA,
      lawyerPubA: BASE.lawyerPubB,
      lawyerPubB: BASE.lawyerPubA,
    });
    for (const d of [
      swapped,
      deal({ ...BASE, xPubA: BASE.xPubB, xPubB: BASE.xPubA }),
      deal({ ...BASE, quorum: 3 }),
      deal({ ...BASE, payoutB: `${addr(0x33)}:4294967295` }),
      deal({ ...BASE, payoutB: addr(0x32) }), // tag removed
      deal({ ...BASE, payoutA: `${addr(0x31)}:10` }),
    ])
      expect(seal(d)).not.toBe(s0);
  });

  it('P1.6-02 golden vector: the fixed deal gives the committed seal and Domain', () => {
    // Computed by tools/py-ref/legx_ref.py (written from DESIGN alone) from these exact inputs; see the status file.
    expect(seal(BASE)).toBe(GOLDEN_SEAL);
    expect(bytesToHex(domain(hexToBytes(BASE.contractRoot), hexToBytes(GOLDEN_SEAL))).toUpperCase()).toBe(
      GOLDEN_DOMAIN,
    );
  });

  it('matches tools/py-ref/vectors/deal_seal.json (dealSeal and domain)', () => {
    const v = pyVector<Record<string, unknown>>('deal_seal', 'dealSeal');
    const i = v.inputs;
    const d = deal({
      ...i,
      commitmentA: i.C_A,
      commitmentB: i.C_B,
      lawyerCommitmentA: i.LC_A,
      lawyerCommitmentB: i.LC_B,
      C_A: undefined,
      C_B: undefined,
      LC_A: undefined,
      LC_B: undefined,
    });
    expect(seal(d)).toBe(v.output);
    const dv = pyVector('deal_seal', 'domain');
    expect(
      bytesToHex(domain(hexToBytes(dv.inputs.root as string), hexToBytes(dv.inputs.seal as string))).toUpperCase(),
    ).toBe(dv.output);
  });
});

describe('P1.6 Domain and input rules', () => {
  it('P1.6-01 domain(root, seal) is 65 bytes: 0x01, then the root, then the seal', () => {
    const root = hexToBytes(h32(0xaa));
    const s = dealSeal(BASE);
    const dom = domain(root, s);
    expect(dom).toHaveLength(65);
    expect(dom[0]).toBe(0x01);
    expect(bytesToHex(dom.subarray(1, 33))).toBe(h32(0xaa));
    expect(bytesToHex(dom.subarray(33))).toBe(bytesToHex(s));
    expect(() => domain(root.subarray(1), s)).toThrow();
    expect(() => domain(root, s.subarray(1))).toThrow();
  });

  it('P1.6-03 an unknown idMethod or identityPolicy throws', () => {
    for (const bad of ['', 'zk', 'ZKPASSPORT', 'nfc', 'chip'])
      expect(() => dealSeal(deal({ ...BASE, idMethodA: bad })), bad).toThrow(/idMethod/);
    for (const bad of ['', 'zkpassport', 'ZK', 'zk-or-chip ', 'any'])
      expect(() => dealSeal(deal({ ...BASE, identityPolicy: bad })), bad).toThrow(/identityPolicy/);
  });

  it('P1.6-04 an idMethod that the identityPolicy does not allow throws', () => {
    expect(() => dealSeal(deal({ ...BASE, identityPolicy: 'zk', idMethodB: 'nfc-chip' }))).toThrow(/not allowed/);
    expect(() => dealSeal(deal({ ...BASE, identityPolicy: 'chip' }))).toThrow(/not allowed/);
    expect(() =>
      dealSeal(deal({ ...BASE, identityPolicy: 'chip', idMethodA: 'nfc-chip', idMethodB: 'nfc-chip' })),
    ).not.toThrow();
    expect(() => dealSeal(deal({ ...BASE, identityPolicy: 'zk' }))).not.toThrow();
  });

  it('P1.6-05 a slot policy, pqKeyHash or other 32-byte field that is not 32 bytes throws; keys must be ED + 32 bytes', () => {
    for (const f of [
      'slotPolicyA',
      'slotPolicyLB',
      'pqKeyHashA',
      'pqKeyHashLB',
      'contractRoot',
      'commitmentB',
    ] as const) {
      expect(() => dealSeal(deal({ ...BASE, [f]: h32(1).slice(2) })), f).toThrow(/32 bytes/);
      expect(() => dealSeal(deal({ ...BASE, [f]: `${h32(1)}00` })), f).toThrow(/32 bytes/);
      expect(() => dealSeal(deal({ ...BASE, [f]: 'zz' })), f).toThrow();
    }
    expect(() => dealSeal(deal({ ...BASE, xPubA: pub(3).slice(2) }))).toThrow(/xPubA/);
    expect(() => dealSeal(deal({ ...BASE, lawyerPubB: `02${h32(8)}` }))).toThrow(/lawyerPubB/);
  });

  it('P1.6-06 payout tags: leading zero, sign, or above 4294967295 throw; 0 and 4294967295 pass', () => {
    const a = addr(0x31);
    for (const bad of [
      `${a}:01`,
      `${a}:-1`,
      `${a}:+1`,
      `${a}:4294967296`,
      `${a}:99999999999`,
      `${a}:`,
      `${a}:1.0`,
      `${a}: 1`,
      `${a}:1:2`,
      ':5',
      '',
      `${a}:0x10`,
    ])
      expect(() => dealSeal(deal({ ...BASE, payoutA: bad })), bad).toThrow(/payout/);
    for (const good of [`${a}:0`, `${a}:4294967295`, a, `${a}:42`])
      expect(() => dealSeal(deal({ ...BASE, payoutB: good })), good).not.toThrow();
  });

  it('a quorum outside uint32 throws', () => {
    for (const q of [-1, 1.5, 2 ** 32, Number.NaN])
      expect(() => dealSeal(deal({ ...BASE, quorum: q })), String(q)).toThrow(/quorum/);
  });

  it('P1.6-07 two seals that differ only in the zkSalt32 behind C_A differ', () => {
    const cA = (salt: number) =>
      bytesToHex(
        tupleHash('legx/zk-identity/v1', [new Uint8Array(32).fill(salt), new TextEncoder().encode('123456789')]),
      );
    expect(seal(deal({ ...BASE, commitmentA: cA(1) }))).not.toBe(seal(deal({ ...BASE, commitmentA: cA(2) })));
  });
});

describe('properties', () => {
  const pairs: [keyof PublicDealData, keyof PublicDealData][] = [
    ['lawyerOpsA', 'lawyerOpsB'],
    ['slotPolicyA', 'slotPolicyB'],
    ['slotPolicyLA', 'slotPolicyLB'],
    ['pqKeyHashA', 'pqKeyHashLA'],
    ['xPubA', 'lawyerPubA'],
    ['commitmentA', 'lawyerCommitmentB'],
    ['payoutA', 'payoutB'],
    ['contractRoot', 'signedContractSeal'],
  ];

  it('swapping two different fields of the same type changes the seal', () => {
    fc.assert(
      fc.property(fc.constantFrom(...pairs), ([a, b]) => {
        const d = deal({ ...BASE, [a]: BASE[b], [b]: BASE[a] });
        if (a === 'lawyerOpsA') Object.assign(d, { releaserAccount: BASE.lawyerOpsA });
        expect(seal(d)).not.toBe(seal(BASE));
      }),
    );
  });

  it('random 32-byte values: seal is deterministic and a one-bit change in any of them changes it', () => {
    const b32 = fc.uint8Array({ minLength: 32, maxLength: 32 }).map(bytesToHex);
    fc.assert(
      fc.property(fc.array(b32, { minLength: 4, maxLength: 4 }), fc.nat(31), (v, byte) => {
        const d = deal({ ...BASE, slotPolicyA: v[0], slotPolicyLB: v[1], pqKeyHashB: v[2], contractRoot: v[3] });
        expect(seal(d)).toBe(seal(deal({ ...d })));
        const bytes = hexToBytes(v[0] as string);
        bytes[byte] = (bytes[byte] ?? 0) ^ 0x80;
        expect(seal(deal({ ...d, slotPolicyA: bytesToHex(bytes) }))).not.toBe(seal(d));
      }),
      { numRuns: 50 },
    );
  });

  it('depends on nothing but its inputs: a fresh process with another locale and time zone gives the same seal', () => {
    const script = `import { dealSeal } from './src/dealcore.ts';
      process.stdout.write(Buffer.from(dealSeal(${JSON.stringify(BASE)})).toString('hex'));`;
    const out = execFileSync(process.execPath, ['--input-type=module', '-e', script], {
      cwd: new URL('..', import.meta.url),
      env: { ...process.env, TZ: 'Pacific/Kiritimati', LANG: 'tr_TR.UTF-8', LC_ALL: 'tr_TR.UTF-8' },
      encoding: 'utf8',
    });
    expect(out).toBe(seal(BASE));
  });
});

const GOLDEN_SEAL = 'f72f607d585b66513312a32600ac0cdd106b7371da26382ec81d2fc8b835dbb3';
const GOLDEN_DOMAIN =
  '010101010101010101010101010101010101010101010101010101010101010101F72F607D585B66513312A32600AC0CDD106B7371DA26382EC81D2FC8B835DBB3';
