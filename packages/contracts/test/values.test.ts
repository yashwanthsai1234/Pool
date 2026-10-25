import { describe, expect, it } from 'vitest';
import {
  Base64Bytes,
  DealId,
  Drops,
  Ed25519SigHex,
  Hex32,
  HexBytes,
  Jurisdiction,
  LedgerIndex,
  MlDsa65PublicKey,
  MlDsa65Signature,
  Payout,
  RippleTime,
  Role,
  Side,
  Slot,
  XrplAddress,
  XrplEd25519PublicKey,
  XrplHash,
  XrplPublicKey,
} from '../src/values.ts';

// Real addresses and keys made with xrpl.js 5.3.0 (build/tmp/1.2/gen.mjs).
const ALICE = 'r3sNTMefq5gsRumMYsNznnX6yzzxVH6dTC';
const ED_KEY = 'ED06895BEC3FDE4090F06D840770D888D49E3089B3757C4285E3851BC33964E0F9';
const SECP_KEY = '038DC251C57CB83DC3CCC10E432F2E59397DB02B7E91FD4186C8B7DA549FB050DF';

const ok = (s: { safeParse: (v: unknown) => { success: boolean } }, v: unknown) =>
  expect(s.safeParse(v).success).toBe(true);
const bad = (s: { safeParse: (v: unknown) => { success: boolean } }, v: unknown) =>
  expect(s.safeParse(v).success).toBe(false);

describe('value types', () => {
  it('Hex32 is exactly 64 lowercase hex characters', () => {
    ok(Hex32, 'ab'.repeat(32));
    bad(Hex32, 'ab'.repeat(31));
    bad(Hex32, `${'ab'.repeat(32)}0`);
    bad(Hex32, 'AB'.repeat(32));
    bad(Hex32, 'zz'.repeat(32));
  });

  it('HexBytes(n) checks the byte length', () => {
    ok(HexBytes(4), '00ff00ff');
    bad(HexBytes(4), '00ff00');
    bad(HexBytes(4), '00ff00ff00');
  });

  it('XrplHash is 64 uppercase hex characters (ledger-facing)', () => {
    ok(XrplHash, 'AB'.repeat(32));
    bad(XrplHash, 'ab'.repeat(32));
  });

  it('XrplAddress checks the alphabet, the length and the base58 checksum', () => {
    ok(XrplAddress, ALICE);
    bad(XrplAddress, `${ALICE.slice(0, -1)}D`); // one changed character breaks the checksum
    bad(XrplAddress, ALICE.replace('r', 'x'));
    bad(XrplAddress, `${ALICE}0`); // 0 is not in the XRPL alphabet
    bad(XrplAddress, 'r');
  });

  it('XrplPublicKey accepts ED + 64 hex and 02/03 + 64 hex, uppercase', () => {
    ok(XrplPublicKey, ED_KEY);
    ok(XrplPublicKey, SECP_KEY);
    bad(XrplPublicKey, ED_KEY.toLowerCase());
    bad(XrplPublicKey, `04${SECP_KEY.slice(2)}`);
    bad(XrplPublicKey, ED_KEY.slice(0, -2));
    ok(XrplEd25519PublicKey, ED_KEY);
    bad(XrplEd25519PublicKey, SECP_KEY);
  });

  it('Drops is a decimal string with no leading zeros, at most 10^17', () => {
    ok(Drops, '0');
    ok(Drops, '2500000');
    ok(Drops, '100000000000000000');
    bad(Drops, '100000000000000001');
    bad(Drops, '0100');
    bad(Drops, '-1');
    bad(Drops, 1);
  });

  it('RippleTime and LedgerIndex are unsigned 32-bit integers', () => {
    ok(RippleTime, 0);
    ok(RippleTime, 4294967295);
    bad(RippleTime, 4294967296);
    bad(RippleTime, 1.5);
    ok(LedgerIndex, 1);
    bad(LedgerIndex, 0);
  });

  it('Payout is "rAddr" or "rAddr:tag" with a base-10 tag up to 2^32-1 and no leading zeros', () => {
    ok(Payout, ALICE);
    ok(Payout, `${ALICE}:0`);
    ok(Payout, `${ALICE}:4294967295`);
    bad(Payout, `${ALICE}:4294967296`);
    bad(Payout, `${ALICE}:01`);
    bad(Payout, `${ALICE}:`);
    bad(Payout, `${ALICE.slice(0, -1)}D:1`);
  });

  it('roles, sides and slots are closed sets', () => {
    expect(Role.options).toEqual(['alice', 'lawyerA', 'bob', 'lawyerB']);
    expect(Side.options).toEqual(['A', 'B']);
    expect(Slot.options).toEqual(['A', 'LA', 'B', 'LB']);
  });

  it('DealId is a UUIDv7', () => {
    ok(DealId, '0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8c9d');
    bad(DealId, '0192f0c8-3c4e-4a2b-8c3d-4e5f6a7b8c9d');
  });

  it('base64 byte strings have the exact decoded length (ML-DSA-65: 1,952 B key, 3,309 B signature)', () => {
    const b64 = (n: number) => Buffer.alloc(n, 7).toString('base64');
    ok(Base64Bytes(64), b64(64));
    bad(Base64Bytes(64), b64(63));
    bad(Base64Bytes(64), b64(65));
    ok(MlDsa65PublicKey, b64(1952));
    bad(MlDsa65PublicKey, b64(1951));
    ok(MlDsa65Signature, b64(3309));
    bad(MlDsa65Signature, b64(3308));
    ok(Ed25519SigHex, 'ab'.repeat(64));
  });

  it('Jurisdiction is ISO 3166 alpha-2 with an optional subdivision, never containing ":"', () => {
    ok(Jurisdiction, 'US-CA');
    ok(Jurisdiction, 'GB');
    bad(Jurisdiction, 'US:CA');
    bad(Jurisdiction, 'usa');
  });
});

describe('shared constants', () => {
  it('pin the DESIGN 6.10 values and the release code secret', async () => {
    const { SEPOLIA_CHAIN_ID, ZK_DOMAIN, ReleasePreimage } = await import('../src/records.ts');
    const { secretPaths } = await import('../src/secret.ts');
    expect(ZK_DOMAIN).toBe('legx.app');
    expect(SEPOLIA_CHAIN_ID).toBe(11155111);
    expect(secretPaths(ReleasePreimage)).toEqual(['/']);
  });
});
