// Task 1.10: bar records (DESIGN 6.16, 6.2). T-U-17a to h, P1.10-01, P1.10-02 and the mutation properties.
// Source: DESIGN 6.2 (LC), 6.16; vector from tools/py-ref/vectors/identity.json.
import { ATTEST_PAYLOAD_TYPE } from '@legx/contracts/records';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import * as xrpl from 'xrpl';
import {
  BAR_MAX_AGE_SECONDS,
  type BarDealLinkInput,
  type BarTrust,
  barNumberSha256,
  normalizeBarNumber,
  openBarCommitment,
  verifyBarDealLink,
  verifyBarVerification,
} from '../src/bar.ts';
import type { Envelope } from '../src/evidence.ts';
import { type KeyRegistry, signHybrid, verifyHybrid } from '../src/hybridEnvelope.ts';
import { nobleHybridSigner, pqKeygen } from '../src/pq.ts';
import { pyVector } from './helpers/pyref.ts';

const VERIFIER = { ed25519: 'verifier:ed', mlDsa65: 'verifier:pq' };
// Test double for task 1.16's verifyHybrid: the "signature" names the key ids, `bad` makes the signature fail.
const verify: BarTrust['verify'] = (env) => {
  const [a, b] = env.signatures;
  if (!a || !b || a.sig === 'bad') return { ok: false, code: 'ED_SIGNATURE_INVALID' };
  return {
    ok: true,
    payload: new Uint8Array(Buffer.from(env.payload, 'base64')),
    keyIds: { ed25519: a.keyid, mlDsa65: b.keyid },
  };
};
const trust: BarTrust = { verify, verifierKeyIds: VERIFIER };
const seal = (payload: unknown, ids = VERIFIER, sig = 'ok'): Uint8Array => {
  const env: Envelope = {
    payloadType: ATTEST_PAYLOAD_TYPE,
    payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
    signatures: [
      { keyid: ids.ed25519, sig },
      { keyid: ids.mlDsa65, sig: 'ok' },
    ],
  };
  return utf8ToBytes(JSON.stringify(env));
};

const OPS = xrpl.Wallet.generate().classicAddress;
const OTHER_OPS = xrpl.Wallet.generate().classicAddress;
const lawyerPub = (n: string) => `ED${n.repeat(64)}`;
const SALT = new Uint8Array(32).fill(7);
const JUR = 'US-CA';
const BAR = 'ab-123456';
const DEAL = '0190a2b4-7c1d-7e3f-8a9b-0c1d2e3f4a5b';
const ROOT = '11'.repeat(32);
const LC = bytesToHex(openBarCommitment(SALT, JUR, BAR));
const CHECKED = 800_000_000;
const NOW = CHECKED + BAR_MAX_AGE_SECONDS;

const verification = {
  jurisdiction: JUR,
  bar_number_sha256: barNumberSha256(BAR),
  status: 'active',
  source: { kind: 'manual', url: 'https://example.org/page', evidence_sha256: '22'.repeat(32) },
  ops_account: OPS,
  checked_at_ledger: { ledger_index: 123456, ledger_hash: 'AB'.repeat(32) },
  verifier_key_id: VERIFIER.ed25519,
  sig_algs: ['ed25519', 'ml-dsa-65'],
};
const vBytes = (over: Record<string, unknown> = {}) => seal({ ...verification, ...over });
const link = (over: Record<string, unknown> = {}, vb = vBytes()) => ({
  deal_id: DEAL,
  contract_root: ROOT,
  role: 'LA',
  lawyer_pub: lawyerPub('A'),
  bar_commitment: LC,
  ops_account: OPS,
  verification_sha256: bytesToHex(sha256(vb)),
  sig_algs: ['ed25519', 'ml-dsa-65'],
  ...over,
});
const input = (o: Partial<BarDealLinkInput> = {}): BarDealLinkInput => {
  const verificationBytes = vBytes();
  return {
    linkBytes: seal(link({}, verificationBytes)),
    verificationBytes,
    trust,
    sealed: {
      dealId: DEAL,
      contractRoot: ROOT,
      role: 'LA',
      lawyerPub: lawyerPub('A'),
      barCommitment: LC,
      opsAccount: OPS,
    },
    checkedAtCloseTime: CHECKED,
    nowCloseTime: NOW,
    ...o,
  };
};
const code = (r: { ok: boolean; code?: string }) => (r.ok ? 'OK' : r.code);

describe('T-U-17 bar records', () => {
  it('T-U-17a a good verification and link pass', () => {
    expect(verifyBarDealLink(input()).ok).toBe(true);
    expect(verifyBarDealLink(input({ opening: { salt32: SALT, barNumber: ' ab-123456 ' } })).ok).toBe(true);
    expect(verifyBarVerification({ ...input(), opsAccount: OPS, envelopeBytes: vBytes() }).ok).toBe(true);
  });
  it('T-U-17b signed by a key that is not the verifier key', () => {
    const other = { ed25519: 'x:ed', mlDsa65: VERIFIER.mlDsa65 };
    expect(code(verifyBarDealLink(input({ linkBytes: seal(link(), other) })))).toBe('WRONG_SIGNER');
    expect(
      code(
        verifyBarDealLink(
          input({ verificationBytes: vBytes(), linkBytes: seal(link()), trust: { ...trust, verifierKeyIds: other } }),
        ),
      ),
    ).toBe('WRONG_SIGNER');
  });
  it('an invalid signature, a wrong payload type and garbage bytes are ENVELOPE_INVALID', () => {
    expect(code(verifyBarDealLink(input({ linkBytes: seal(link(), VERIFIER, 'bad') })))).toBe('ENVELOPE_INVALID');
    expect(code(verifyBarDealLink(input({ linkBytes: utf8ToBytes('nope') })))).toBe('ENVELOPE_INVALID');
    const env = JSON.parse(new TextDecoder().decode(seal(link())));
    env.payloadType = 'application/vnd.legx.event+json;v=1';
    expect(code(verifyBarDealLink(input({ linkBytes: utf8ToBytes(JSON.stringify(env)) })))).toBe('ENVELOPE_INVALID');
  });
  it('a payload of the wrong shape (extra key, wrong type) is MALFORMED', () => {
    expect(code(verifyBarDealLink(input({ linkBytes: seal({ ...link(), extra: 1 }) })))).toBe('MALFORMED');
    expect(code(verifyBarVerification({ ...input(), opsAccount: OPS, envelopeBytes: seal(link()) }))).toBe('MALFORMED');
  });
  it('T-U-17c wrong bar commitment', () => {
    expect(code(verifyBarDealLink(input({ linkBytes: seal(link({ bar_commitment: '33'.repeat(32) })) })))).toBe(
      'COMMITMENT_MISMATCH',
    );
    // The salt or number the lawyer opened does not give the sealed LC.
    expect(code(verifyBarDealLink(input({ opening: { salt32: new Uint8Array(32), barNumber: BAR } })))).toBe(
      'COMMITMENT_MISMATCH',
    );
  });
  it('T-U-17d wrong operations account', () => {
    expect(code(verifyBarDealLink(input({ linkBytes: seal(link({ ops_account: OTHER_OPS })) })))).toBe('OPS_MISMATCH');
    // The verification names another account than the sealed one.
    const vb = vBytes({ ops_account: OTHER_OPS });
    expect(code(verifyBarDealLink(input({ verificationBytes: vb, linkBytes: seal(link({}, vb)) })))).toBe(
      'OPS_MISMATCH',
    );
  });
  it('T-U-17e wrong lawyer key', () => {
    expect(code(verifyBarDealLink(input({ linkBytes: seal(link({ lawyer_pub: lawyerPub('B') })) })))).toBe(
      'LAWYER_KEY_MISMATCH',
    );
  });
  it('T-U-17f a link for another deal (id or contract root), or the other role', () => {
    expect(
      code(verifyBarDealLink(input({ linkBytes: seal(link({ deal_id: '0190a2b4-7c1d-7e3f-8a9b-0c1d2e3f4a5c' })) }))),
    ).toBe('WRONG_DEAL');
    expect(code(verifyBarDealLink(input({ linkBytes: seal(link({ contract_root: '44'.repeat(32) })) })))).toBe(
      'WRONG_DEAL',
    );
    expect(code(verifyBarDealLink(input({ linkBytes: seal(link({ role: 'LB' })) })))).toBe('ROLE_MISMATCH');
  });
  it('T-U-17g status is not active', () => {
    const vb = vBytes({ status: 'not_active' });
    expect(code(verifyBarDealLink(input({ verificationBytes: vb, linkBytes: seal(link({}, vb)) })))).toBe('NOT_ACTIVE');
  });
  it('T-U-17h older than 30 days by ledger time: exactly 30 days passes, plus 1 second fails', () => {
    const at = (now: number) => code(verifyBarDealLink(input({ nowCloseTime: now })));
    expect(at(CHECKED + BAR_MAX_AGE_SECONDS)).toBe('OK');
    expect(at(CHECKED + BAR_MAX_AGE_SECONDS + 1)).toBe('STALE');
    expect(BAR_MAX_AGE_SECONDS).toBe(2_592_000);
  });
  it('a ledger time in the future or not an integer is TIME_INVALID', () => {
    expect(code(verifyBarDealLink(input({ nowCloseTime: CHECKED - 1 })))).toBe('TIME_INVALID');
    expect(code(verifyBarDealLink(input({ nowCloseTime: Number.NaN })))).toBe('TIME_INVALID');
  });
  it('P1.10-01 verification_sha256 does not match the named envelope', () => {
    expect(
      code(verifyBarDealLink(input({ verificationBytes: vBytes({ status: 'active', verifier_key_id: 'other' }) }))),
    ).toBe('VERIFICATION_HASH_MISMATCH');
    expect(code(verifyBarDealLink(input({ linkBytes: seal(link({ verification_sha256: '55'.repeat(32) })) })))).toBe(
      'VERIFICATION_HASH_MISMATCH',
    );
  });
  it('an opened bar number that differs from the verified one is BAR_NUMBER_MISMATCH', () => {
    expect(code(verifyBarDealLink(input({ opening: { salt32: SALT, barNumber: 'ZZ-1' } })))).toBe(
      'BAR_NUMBER_MISMATCH',
    );
  });
});

describe('P1.10-02 openBarCommitment', () => {
  it('equals the Python reference LC', () => {
    const v = pyVector<{ salt: string; jurisdiction: string; bar: string }>('identity', 'bar');
    expect(bytesToHex(openBarCommitment(hexToBytes(v.inputs.salt), v.inputs.jurisdiction, v.inputs.bar))).toBe(
      v.output,
    );
  });
  it('refuses a jurisdiction that is not an ISO 3166 code with an optional subdivision', () => {
    for (const j of ['US:CA', 'US-CA:1', 'us', 'USA', 'US-', '', 'US-CALI', 'U S']) {
      expect(() => openBarCommitment(SALT, j, BAR), j).toThrow();
    }
  });
  it('trims and uppercases the bar number, and refuses anything else', () => {
    expect(normalizeBarNumber('  ab-12 \n')).toBe('AB-12');
    expect(bytesToHex(openBarCommitment(SALT, JUR, ' ab-12 '))).toBe(bytesToHex(openBarCommitment(SALT, JUR, 'AB-12')));
    for (const b of ['', ' ', 'A B', 'A:1', 'A_1', 'ıı1', 'ß', 'A\u0000', '１２', 'x'.repeat(33)]) {
      expect(() => normalizeBarNumber(b), JSON.stringify(b)).toThrow();
    }
  });
  it('refuses a salt that is not 32 bytes', () => {
    expect(() => openBarCommitment(new Uint8Array(31), JUR, BAR)).toThrow();
  });
  it('a different salt, jurisdiction or number gives a different LC', () => {
    const base = bytesToHex(openBarCommitment(SALT, JUR, BAR));
    expect(bytesToHex(openBarCommitment(new Uint8Array(32), JUR, BAR))).not.toBe(base);
    expect(bytesToHex(openBarCommitment(SALT, 'US-NY', BAR))).not.toBe(base);
    expect(bytesToHex(openBarCommitment(SALT, JUR, 'AB-1234567'))).not.toBe(base);
  });
});

describe('every single-field mutation fails with exactly one code', () => {
  const linkMutations: [string, unknown, string][] = [
    ['deal_id', '0190a2b4-7c1d-7e3f-8a9b-0c1d2e3f4a5c', 'WRONG_DEAL'],
    ['contract_root', '44'.repeat(32), 'WRONG_DEAL'],
    ['role', 'LB', 'ROLE_MISMATCH'],
    ['lawyer_pub', lawyerPub('B'), 'LAWYER_KEY_MISMATCH'],
    ['bar_commitment', '33'.repeat(32), 'COMMITMENT_MISMATCH'],
    ['ops_account', OTHER_OPS, 'OPS_MISMATCH'],
    ['verification_sha256', '55'.repeat(32), 'VERIFICATION_HASH_MISMATCH'],
  ];
  it.each(linkMutations)('link field %s', (field, value, expected) => {
    expect(code(verifyBarDealLink(input({ linkBytes: seal(link({ [field]: value })) })))).toBe(expected);
  });
  it('verification fields: status and ops_account', () => {
    for (const [over, expected] of [
      [{ status: 'not_active' }, 'NOT_ACTIVE'],
      [{ ops_account: OTHER_OPS }, 'OPS_MISMATCH'],
    ] as const) {
      const vb = vBytes(over);
      expect(code(verifyBarDealLink(input({ verificationBytes: vb, linkBytes: seal(link({}, vb)) })))).toBe(expected);
    }
  });
  it('verification fields the gate cannot see (number hash, jurisdiction) fail when the verifier opens LC', () => {
    for (const over of [{ bar_number_sha256: '66'.repeat(32) }, { jurisdiction: 'US-NY' }]) {
      const vb = vBytes(over);
      const r = verifyBarDealLink(
        input({ verificationBytes: vb, linkBytes: seal(link({}, vb)), opening: { salt32: SALT, barNumber: BAR } }),
      );
      expect(['BAR_NUMBER_MISMATCH', 'COMMITMENT_MISMATCH']).toContain(code(r));
    }
  });
  it('property: any one wrong sealed value gives exactly the one code of its field', () => {
    const wrong: Record<string, [string, string]> = {
      dealId: ['0190a2b4-7c1d-7e3f-8a9b-0c1d2e3f4a5d', 'WRONG_DEAL'],
      contractRoot: ['77'.repeat(32), 'WRONG_DEAL'],
      role: ['LB', 'ROLE_MISMATCH'],
      lawyerPub: [lawyerPub('C'), 'LAWYER_KEY_MISMATCH'],
      barCommitment: ['88'.repeat(32), 'COMMITMENT_MISMATCH'],
      opsAccount: [OTHER_OPS, 'OPS_MISMATCH'],
    };
    fc.assert(
      fc.property(fc.constantFrom(...Object.keys(wrong)), (k) => {
        const [value, expected] = wrong[k] as [string, string];
        const base = input();
        return code(verifyBarDealLink({ ...base, sealed: { ...base.sealed, [k]: value } })) === expected;
      }),
    );
  });
  it('property: age is checked exactly at 30 days of ledger time', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 5_000_000 }), (age) => {
        const r = verifyBarVerification({
          ...input(),
          opsAccount: OPS,
          envelopeBytes: vBytes(),
          nowCloseTime: CHECKED + age,
        });
        return age <= BAR_MAX_AGE_SECONDS ? r.ok : !r.ok && r.code === 'STALE';
      }),
    );
  });
});

describe('with the real hybrid envelope verifier (task 1.16)', () => {
  const sk = new Uint8Array(32).fill(1);
  const pk = ed25519.getPublicKey(sk);
  const pq = pqKeygen(new Uint8Array(32).fill(2));
  const ids = { ed25519: 'verifier:real:ed', mlDsa65: 'verifier:real:pq' };
  const signer = nobleHybridSigner(
    { keyId: ids.ed25519 as never, publicKey: pk, sign: async (m) => ed25519.sign(m, sk) },
    { keyId: ids.mlDsa65 as never, secretKey: pq.secretKey },
  );
  const registry: KeyRegistry = (id) =>
    id === ids.ed25519
      ? { alg: 'ed25519', publicKey: pk, validFrom: 1, logged: true, pair: 'verifier' }
      : id === ids.mlDsa65
        ? { alg: 'ml-dsa-65', publicKey: pq.publicKey, validFrom: 1, logged: true, pair: 'verifier' }
        : undefined;
  const real: BarTrust = { verify: (env) => verifyHybrid(env, registry, NOW), verifierKeyIds: ids };
  const signed = async (payload: unknown) =>
    utf8ToBytes(JSON.stringify(await signHybrid(ATTEST_PAYLOAD_TYPE, utf8ToBytes(JSON.stringify(payload)), signer)));

  it('passes a genuinely signed pair, and any flipped byte fails', async () => {
    const verificationBytes = await signed(verification);
    const linkBytes = await signed(link({}, verificationBytes));
    const base = input({ trust: real, verificationBytes, linkBytes });
    expect(verifyBarDealLink(base).ok).toBe(true);
    fc.assert(
      fc.property(fc.nat(linkBytes.length - 1), fc.integer({ min: 1, max: 255 }), (pos, x) => {
        const bytes = linkBytes.slice();
        bytes[pos] = (bytes[pos] as number) ^ x;
        return !verifyBarDealLink({ ...base, linkBytes: bytes }).ok;
      }),
      { numRuns: 100 },
    );
  });
});
