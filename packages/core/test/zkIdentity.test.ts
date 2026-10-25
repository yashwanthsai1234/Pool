// Task 1.17: zero-knowledge identity checks (DESIGN 6.2, 6.10, 6.15; IMPLEMENTATION 1.17).
// Core never loads the ZKPassport SDK: these tests read the recorded files in packages/zk/fixtures/.
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { tupleHash } from '../src/dealcore.ts';
import {
  BIND_MAX_BYTES,
  checkBindLength,
  onboardingBoundValue,
  releaseBoundValue,
  zkIdentityCommitment,
  zkScope,
} from '../src/zkIdentity.ts';
import { pyVector } from './helpers/pyref.ts';

const SALT = new Uint8Array(32).fill(0x11);
const N = '6123429442696369728235356647833392668942785382370857452000552430866800017939';

describe('P1.17-01 zkIdentityCommitment (DESIGN 6.2)', () => {
  it('matches the independent Python vector', () => {
    const v = pyVector<{ salt: string; N: string }>('identity', 'zk');
    expect(bytesToHex(zkIdentityCommitment(hexToBytes(v.inputs.salt), v.inputs.N))).toBe(v.output);
  });

  it('matches a golden vector for a decimal SDK identifier (computed with Python hashlib)', () => {
    expect(bytesToHex(zkIdentityCommitment(SALT, N))).toBe(
      '46c7e28baafea8b3245acece5b073ab729afee19e4789fe0ff9bdb8ec0bbdce4',
    );
  });

  it('equals the recipe tupleHash("legx/zk-identity/v1", [zkSalt32, utf8(N)])', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.stringMatching(/^[0-9]{1,78}$/), (s, n) => {
        expect(zkIdentityCommitment(s, n)).toEqual(tupleHash('legx/zk-identity/v1', [s, utf8ToBytes(n)]));
      }),
    );
  });

  it('a different N or a different salt gives a different C_side', () => {
    const c = bytesToHex(zkIdentityCommitment(SALT, N));
    expect(bytesToHex(zkIdentityCommitment(SALT, `${N.slice(0, -1)}8`))).not.toBe(c);
    expect(bytesToHex(zkIdentityCommitment(new Uint8Array(32).fill(0x12), N))).not.toBe(c);
  });

  it('refuses a salt that is not 32 bytes, and an empty identifier', () => {
    for (const n of [0, 16, 31, 33, 64]) expect(() => zkIdentityCommitment(new Uint8Array(n), N)).toThrow(/32 bytes/);
    expect(() => zkIdentityCommitment(SALT, '')).toThrow(/identifier/);
  });
});

describe('bound values (DESIGN 6.10)', () => {
  const root = new Uint8Array(32).fill(0x22);
  const slotPub = new Uint8Array([0xed, ...new Uint8Array(32).fill(0x33)]);

  it('onboarding: hex(tupleHash("legx/zk-onboard/v1", [contractRoot, slotPub_side])), golden from Python', () => {
    expect(onboardingBoundValue(root, slotPub)).toBe(
      '3f35b70962c8882a88bbed0a8c3cdd13ae2966b85e6bc9284e81f87d00d54176',
    );
  });

  it('onboarding refuses a root that is not 32 bytes and a slot key that is not the 33-byte ED form', () => {
    expect(() => onboardingBoundValue(new Uint8Array(31), slotPub)).toThrow(/contractRoot/);
    expect(() => onboardingBoundValue(root, slotPub.slice(1))).toThrow(/slotPub/);
    expect(() => onboardingBoundValue(root, new Uint8Array([0x02, ...slotPub.slice(1)]))).toThrow(/slotPub/);
  });

  it('release: hex(presenceMsg), with presenceMsg from the Python presence vector', () => {
    const v = pyVector<{ dealSeal: string; side: string; ledgerHash: string; nonce: string }>(
      'presence',
      'presenceMsg',
    );
    const msg = tupleHash('legx/passport-presence/v1', [
      hexToBytes(v.inputs.dealSeal),
      utf8ToBytes(v.inputs.side),
      hexToBytes(v.inputs.ledgerHash),
      hexToBytes(v.inputs.nonce),
    ]);
    expect(releaseBoundValue(msg)).toBe(v.output);
    expect(() => releaseBoundValue(msg.slice(1))).toThrow(/32 bytes/);
  });

  it('the scope is "legx/v1/" + dealId', () => {
    expect(zkScope('0192f0a0-0000-7000-8000-000000000001')).toBe('legx/v1/0192f0a0-0000-7000-8000-000000000001');
    expect(() => zkScope('')).toThrow(/dealId/);
  });
});

describe('P1.17-08 checkBindLength (the SDK does not check at request time)', () => {
  it('a release bound value (64 hex characters) fits', () => {
    expect(checkBindLength(releaseBoundValue(new Uint8Array(32)))).toEqual({ ok: true });
  });

  it('506 bytes pass and 507 are refused, counted in UTF-8 bytes', () => {
    expect(BIND_MAX_BYTES).toBe(506);
    expect(checkBindLength('a'.repeat(506))).toEqual({ ok: true });
    expect(checkBindLength('a'.repeat(507))).toEqual({ ok: false, code: 'BOUND_TOO_LONG' });
    // 253 two-byte characters are 506 bytes; one more ASCII byte is 507
    expect(checkBindLength('é'.repeat(253))).toEqual({ ok: true });
    expect(checkBindLength(`${'é'.repeat(253)}a`)).toEqual({ ok: false, code: 'BOUND_TOO_LONG' });
  });
});
