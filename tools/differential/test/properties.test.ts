// P5.3-03, P5.3-08 and P5.3-09: each seal field, key order and salt/identifier changes, TypeScript against Python.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { address, edKey, hex, Prng, PyRef, type RefCase, randomSealFields, tsRef } from '../src/index.ts';

let py: PyRef;
beforeAll(() => {
  py = new PyRef();
});
afterAll(() => py.close());

const both = async (cases: RefCase[]): Promise<string[]> => {
  const got = await py.call<string>('ref', cases);
  for (const [i, c] of cases.entries()) expect(tsRef(c), JSON.stringify(c).slice(0, 300)).toBe(got[i]);
  return got;
};
const flip = (h: string, at = 0): string => {
  const b = h.split('');
  b[at] = b[at] === '0' ? '1' : '0';
  return b.join('');
};

describe('P5.3-03 the 29 seal fields', () => {
  it('changing any one field changes the seal, and both languages agree', async () => {
    const r = new Prng(53);
    const base: Record<string, unknown> = {
      ...randomSealFields(r),
      idMethodA: 'nfc-chip',
      idMethodB: 'nfc-chip',
      identityPolicy: 'zk-or-chip',
    };
    const text = ['walletAddress', 'lawyerOpsA', 'payoutA', 'payoutB'];
    const mutate = (k: string): Record<string, unknown> => {
      const v = base[k];
      if (k === 'lawyerOpsB' || k === 'releaserAccount') {
        const a = address(r);
        return { ...base, lawyerOpsB: a, releaserAccount: a };
      }
      if (text.includes(k)) return { ...base, [k]: address(r) };
      if (k === 'idMethodA' || k === 'idMethodB') return { ...base, [k]: 'zkpassport' };
      if (k === 'identityPolicy') return { ...base, [k]: 'chip' };
      if (k === 'quorum') return { ...base, [k]: 5 };
      if (k === 'signerAccounts') return { ...base, [k]: [...(v as string[]).slice(1), address(r)] };
      if (k.startsWith('xPub') || k.startsWith('lawyerPub')) return { ...base, [k]: edKey(r) };
      return { ...base, [k]: flip(v as string, 63) };
    };
    const keys = Object.keys(base);
    expect(keys).toHaveLength(29);
    const cases: RefCase[] = [base, ...keys.map(mutate)].map((fields) => ({ fn: 'dealSeal', args: { fields } }));
    const seals = await both(cases);
    expect(seals.every((s) => s !== 'ERR')).toBe(true);
    for (const [i, k] of keys.entries()) expect(seals[i + 1], `field ${k}`).not.toBe(seals[0]);
    // The releaser alone is refused by both languages.
    const lone = await both([{ fn: 'dealSeal', args: { fields: { ...base, releaserAccount: address(r) } } }]);
    expect(lone).toEqual(['ERR']);
    // Signer order does not matter.
    const rev = await both([
      {
        fn: 'dealSeal',
        args: { fields: { ...base, signerAccounts: [...(base.signerAccounts as string[])].reverse() } },
      },
    ]);
    expect(rev[0]).toBe(seals[0]);
  });
});

describe('P5.3-08 pqKeyHash', () => {
  it('another key order gives another hash in both languages', async () => {
    const r = new Prng(58);
    const cases: RefCase[] = [];
    for (let i = 0; i < 50; i++) {
      const k = [hex(r.bytes(1952)), hex(r.bytes(1952)), hex(r.bytes(1952))];
      cases.push({ fn: 'pqKeyHash', args: { pubs: k } }, { fn: 'pqKeyHash', args: { pubs: [k[1], k[0], k[2]] } });
    }
    const out = await both(cases);
    for (let i = 0; i < 100; i += 2) expect(out[i]).not.toBe(out[i + 1]);
  });
});

describe('P5.3-09 the salted C_side', () => {
  it('changes with every salt byte and identifier byte; equal identifiers with other salts differ', async () => {
    const r = new Prng(59);
    const salt = hex(r.bytes(32));
    const N = '12345678901234567890';
    const cases: RefCase[] = [{ fn: 'zk', args: { salt, N } }];
    for (let i = 0; i < 32; i++)
      cases.push({
        fn: 'zk',
        args: {
          salt:
            salt.slice(0, 2 * i) +
            (Number.parseInt(salt.slice(2 * i, 2 * i + 2), 16) ^ 1).toString(16).padStart(2, '0') +
            salt.slice(2 * i + 2),
          N,
        },
      });
    for (let i = 0; i < N.length; i++)
      cases.push({ fn: 'zk', args: { salt, N: N.slice(0, i) + (N[i] === '9' ? '8' : '9') + N.slice(i + 1) } });
    cases.push({ fn: 'zk', args: { salt: hex(r.bytes(32)), N } });
    const out = await both(cases);
    expect(new Set(out).size).toBe(out.length);
  });
});
