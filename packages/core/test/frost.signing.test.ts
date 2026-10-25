// T-U-22 (signing rules) and P1.15-06 to 09, 11, 12, 17, 21 (policy part), 22, 23.
import { readFileSync } from 'node:fs';
import { ed25519, ed25519_FROST } from '@noble/curves/ed25519.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it, vi } from 'vitest';
import {
  aggregateChecked,
  canonicalRoles,
  canSign,
  enrollmentSigned,
  type FrostError,
  holderId,
  isSingleDeviceMode,
  onePerHolder,
  openEnrollmentMessage,
  parsePoint,
  parseScalar,
  SigningSession,
  slotAddress,
  slotPolicy,
  slotPubkey,
  verifyEd25519Strict,
  verifyShares,
} from '../src/frost.ts';
import { allow, dkgKeys, enc, frostSign, hex, slotSetup } from './helpers/frost.ts';

// DKG and X-Wing are slow when the whole suite runs in parallel.
vi.setConfig({ testTimeout: 60_000 });

const code = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    return (e as FrostError).code;
  }
  return 'NO_THROW';
};

const slot = await dkgKeys('A');
const [k1, k2, k3] = slot.keys.map((k) => k.secret);
const pub = slot.pub;
const pairs = [
  [k1!, k2!],
  [k1!, k3!],
  [k2!, k3!],
];

describe('T-U-22 signing rules', () => {
  it('T-U-22a every 2-of-3 pair signs; each aggregate passes strict verification', () => {
    const msg = enc('pay bob');
    for (const p of pairs) {
      const sig = frostSign(pub, p, msg);
      expect(verifyEd25519Strict(sig, msg, slotPubkey(pub))).toBe(true);
      expect(ed25519.verify(sig, msg, pub.commitments[0]!, { zip215: false })).toBe(true);
    }
  });

  it('T-U-22b a second signShare for the same commitment throws NONCE_USED and returns no share', () => {
    const msg = enc('m');
    const a = SigningSession.open(k1!, pub, msg);
    const b = SigningSession.open(k2!, pub, msg);
    const list = [a.commitment, b.commitment];
    expect(a.signShare(msg, list, allow)).toHaveLength(32);
    expect(code(() => a.signShare(msg, list, allow))).toBe('NONCE_USED');
    expect(() => a.signShare(msg, list, allow)).toThrow('signing nonces already used'); // P2.8-07 wording (I-2.8-b)
  });

  it('T-U-22c a different message or a different commitment list for a held commitment: SESSION_MISMATCH', () => {
    const msg = enc('m');
    const a = SigningSession.open(k1!, pub, msg);
    const b = SigningSession.open(k2!, pub, msg);
    const c = SigningSession.open(k3!, pub, msg);
    expect(code(() => a.signShare(enc('other'), [a.commitment, b.commitment], allow))).toBe('SESSION_MISMATCH');
    a.signShare(msg, [a.commitment, b.commitment], allow);
    expect(code(() => a.signShare(msg, [a.commitment, c.commitment], allow))).toBe('SESSION_MISMATCH');
    // A list that drops or replaces our own commitment is refused too.
    expect(code(() => b.signShare(msg, [c.commitment, a.commitment], allow))).toBe('SESSION_MISMATCH');
    const forged = { ...b.commitment, hiding: c.commitment.hiding };
    expect(code(() => b.signShare(msg, [a.commitment, forged], allow))).toBe('SESSION_MISMATCH');
  });

  it('T-U-22d a corrupted signature share is named by verifyShare and aggregate is not called', () => {
    const msg = enc('m');
    const s = [k1!, k3!].map((k) => SigningSession.open(k, pub, msg));
    const list = s.map((x) => x.commitment);
    const shares = Object.fromEntries([k1!, k3!].map((k, i) => [k.identifier, s[i]!.signShare(msg, list, allow)]));
    const bad = { ...shares, [k3!.identifier]: shares[k1!.identifier]! };
    expect(verifyShares(pub, list, msg, bad)).toEqual([k3!.identifier]);
    let err: FrostError | undefined;
    try {
      aggregateChecked(pub, list, msg, bad);
    } catch (e) {
      err = e as FrostError;
    }
    expect(err?.code).toBe('SHARE_INVALID');
    expect(err?.culprit).toBe(3);
    expect(verifyShares(pub, list, msg, { ...shares, [k1!.identifier]: new Uint8Array(31) })).toEqual([k1!.identifier]);
    expect(hex(aggregateChecked(pub, list, msg, shares))).toHaveLength(128);
  });

  it('T-U-22e a message with a bad enrollment signature is refused before its content is used', () => {
    const { ctx, holders } = slotSetup('LA');
    const m = enrollmentSigned(holders[0]!.signer, {
      session: ctx.sessionId,
      kind: 'dkg-r1',
      from: 1,
      to: 0,
      fields: [enc('x')],
    });
    expect(openEnrollmentMessage(ctx, m, 'dkg-r1', 2)).toBe(m);
    const flip = (b: Uint8Array) => b.map((x, i) => (i === 0 ? x ^ 1 : x));
    expect(code(() => openEnrollmentMessage(ctx, { ...m, sig: flip(m.sig) }, 'dkg-r1', 2))).toBe(
      'ENROLLMENT_SIG_INVALID',
    );
    expect(code(() => openEnrollmentMessage(ctx, { ...m, fields: [enc('y')] }, 'dkg-r1', 2))).toBe(
      'ENROLLMENT_SIG_INVALID',
    );
    expect(code(() => openEnrollmentMessage(ctx, { ...m, from: 2 }, 'dkg-r1', 3))).toBe('ENROLLMENT_SIG_INVALID');
    expect(code(() => openEnrollmentMessage(ctx, { ...m, from: 7 }, 'dkg-r1', 3))).toBe('ENROLLMENT_SIG_INVALID');
    // Signed by a key that is not the pinned one for holder 1.
    const other = enrollmentSigned(holders[1]!.signer, { ...m });
    expect(code(() => openEnrollmentMessage(ctx, other, 'dkg-r1', 2))).toBe('ENROLLMENT_SIG_INVALID');
    expect(code(() => openEnrollmentMessage(ctx, m, 'dkg-echo', 2))).toBe('INPUT_INVALID');
    expect(code(() => onePerHolder(ctx, 1, [m, m]))).toBe('INPUT_INVALID');
  });
});

describe('session object', () => {
  it('P1.15-06 there is no way to build a session from serialized state', () => {
    // @ts-expect-error the constructor is private: a session cannot be rebuilt
    expect(() => new SigningSession(k1, pub, enc('m'), undefined)).toBeDefined();
    // @ts-expect-error there is no deserializer
    expect(SigningSession.fromJSON).toBeUndefined();
    const s = SigningSession.open(k1!, pub, enc('m'));
    expect(code(() => JSON.stringify(s))).toBe('NOT_SERIALIZABLE');
    const clone = structuredClone(s) as unknown as Record<string, unknown>;
    expect(Object.keys(clone)).toEqual([]);
  });

  it('P1.15-07 the same message in two sessions gives two different signatures, both valid', () => {
    const msg = enc('same');
    const a = frostSign(pub, [k1!, k2!], msg);
    const b = frostSign(pub, [k1!, k2!], msg);
    expect(hex(a)).not.toBe(hex(b));
    expect(verifyEd25519Strict(a, msg, slotPubkey(pub)) && verifyEd25519Strict(b, msg, slotPubkey(pub))).toBe(true);
  });

  it('refuses a share that does not match its verifying share, and an off-list message without using the nonce', () => {
    expect(code(() => SigningSession.open({ ...k1!, signingShare: k2!.signingShare }, pub, enc('m')))).toBe(
      'SHARE_INVALID',
    );
    expect(code(() => SigningSession.open({ ...k1!, identifier: holderId(9) }, pub, enc('m')))).toBe('SHARE_INVALID');
    const msg = enc('m');
    const a = SigningSession.open(k1!, pub, msg);
    const b = SigningSession.open(k2!, pub, msg);
    const list = [a.commitment, b.commitment];
    expect(code(() => a.signShare(msg, list, () => ({ ok: false, reason: 'no' })))).toBe('MESSAGE_REFUSED');
    expect(a.signShare(msg, list, allow)).toHaveLength(32); // the refusal did not use the nonce
  });

  it('P1.15-17 a slot that lost two shares cannot sign: canSign is false and signing throws BELOW_THRESHOLD', () => {
    expect(canSign(pub, [k1!.identifier])).toBe(false);
    expect(canSign(pub, [k1!.identifier, k1!.identifier])).toBe(false);
    expect(canSign(pub, [k1!.identifier, k3!.identifier])).toBe(true);
    const msg = enc('m');
    const a = SigningSession.open(k1!, pub, msg);
    expect(code(() => a.signShare(msg, [a.commitment], allow))).toBe('BELOW_THRESHOLD');
    expect(code(() => aggregateChecked(pub, [a.commitment], msg, {}))).toBe('BELOW_THRESHOLD');
  });

  it('rejects hostile inputs with typed errors: duplicates, unknown ids, bad points, mismatched shares', () => {
    const msg = enc('m');
    const a = SigningSession.open(k1!, pub, msg);
    const b = SigningSession.open(k2!, pub, msg);
    expect(code(() => a.signShare(msg, [a.commitment, a.commitment], allow))).toBe('INPUT_INVALID');
    expect(code(() => a.signShare(msg, [a.commitment, { ...b.commitment, identifier: holderId(7) }], allow))).toBe(
      'INPUT_INVALID',
    );
    expect(code(() => a.signShare(msg, [a.commitment, { ...b.commitment, hiding: new Uint8Array(32) }], allow))).toBe(
      'INPUT_INVALID',
    );
    const list = [a.commitment, b.commitment];
    expect(code(() => aggregateChecked(pub, list, msg, { [k1!.identifier]: new Uint8Array(32) }))).toBe(
      'INPUT_INVALID',
    );
    expect(code(() => parsePoint(new Uint8Array(32)))).toBe('INPUT_INVALID'); // not on the curve as y = 0
    expect(code(() => parsePoint(ed25519.Point.ZERO.toBytes()))).toBe('INPUT_INVALID'); // identity
    expect(code(() => parsePoint(new Uint8Array(31)))).toBe('INPUT_INVALID');
    expect(code(() => parsePoint(new Uint8Array(32).fill(0xff)))).toBe('INPUT_INVALID'); // non-canonical encoding
    expect(verifyEd25519Strict(new Uint8Array(64), msg, new Uint8Array([0xed, ...new Uint8Array(32).fill(0xff)]))).toBe(
      false,
    );
    // A small-order point (order 8 torsion) is refused.
    const torsion = Uint8Array.from(
      Buffer.from('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'hex'),
    );
    expect(code(() => parsePoint(torsion))).toBe('INPUT_INVALID');
    expect(code(() => parseScalar(new Uint8Array(32)))).toBe('INPUT_INVALID'); // zero
    expect(code(() => parseScalar(new Uint8Array(32).fill(255)))).toBe('INPUT_INVALID'); // >= L
    expect(code(() => parseScalar(new Uint8Array(33)))).toBe('INPUT_INVALID');
    expect(code(() => slotPubkey({ ...pub, commitments: [] }))).toBe('INPUT_INVALID');
    expect(verifyEd25519Strict(new Uint8Array(64), msg, new Uint8Array(32))).toBe(false);
    expect(verifyEd25519Strict(new Uint8Array(64), msg, slotPubkey(pub))).toBe(false);
  });
});

describe('slotPolicy and roles', () => {
  const golden = JSON.parse(
    readFileSync(new URL('../../../tools/py-ref/vectors/slot_policy.json', import.meta.url), 'utf8'),
  ) as { inputs: { slot: 'A' | 'LA'; roles: string }; output: string }[];

  it('P1.15-08 equals the golden hash of the independent Python reference; slot and roles change it', () => {
    for (const g of golden) expect(hex(slotPolicy(g.inputs.slot, g.inputs.roles.split(',')))).toBe(g.output);
    const a = hex(slotPolicy('A', ['phone', 'second-authenticator', 'recovery-agent']));
    expect(hex(slotPolicy('B', ['phone', 'second-authenticator', 'recovery-agent']))).not.toBe(a);
    expect(hex(slotPolicy('A', ['phone', 'passkey-same-device', 'recovery-agent']))).not.toBe(a);
    // @ts-expect-error slotPolicy takes the slot and the roles only, never verifying shares
    slotPolicy('A', ['phone', 'second-authenticator', 'recovery-agent'], pub.verifyingShares);
  });

  it('P1.15-09 a shuffled list gives the canonical hash; duplicates and unknown roles are ROLE_INVALID', () => {
    expect(hex(slotPolicy('LB', ['partner', 'console', 'firm-hsm']))).toBe(
      hex(slotPolicy('LB', ['console', 'firm-hsm', 'partner'])),
    );
    expect(canonicalRoles('B', ['recovery-agent', 'phone', 'second-authenticator'])).toEqual([
      'phone',
      'second-authenticator',
      'recovery-agent',
    ]);
    expect(code(() => slotPolicy('A', ['phone', 'phone', 'recovery-agent']))).toBe('ROLE_INVALID');
    expect(code(() => slotPolicy('A', ['phone', 'second-authenticator', 'recovery-agent', 'phone']))).toBe(
      'ROLE_INVALID',
    );
    expect(code(() => slotPolicy('A', ['phone', 'security-key', 'recovery-agent']))).toBe('ROLE_INVALID');
    expect(code(() => slotPolicy('LA', ['phone', 'second-authenticator', 'recovery-agent']))).toBe('ROLE_INVALID');
    expect(code(() => slotPolicy('A', ['console', 'firm-hsm', 'partner']))).toBe('ROLE_INVALID');
    expect(code(() => slotPolicy('X' as 'A', ['console', 'firm-hsm', 'partner']))).toBe('ROLE_INVALID');
  });

  it('P1.15-21 single-device mode has its own policy and is labelled', () => {
    expect(isSingleDeviceMode(['phone', 'passkey-same-device', 'recovery-agent'])).toBe(true);
    expect(isSingleDeviceMode(['phone', 'second-authenticator', 'recovery-agent'])).toBe(false);
  });
});

describe('group key and address', () => {
  it('P1.15-11 the slot key is 0xED || group key, and an independent address derivation matches xrpl.js', () => {
    const pk = slotPubkey(pub);
    expect(pk[0]).toBe(0xed);
    expect(hex(pk.subarray(1))).toBe(hex(pub.commitments[0]!));
    // Independent: base58check(0x00 || RIPEMD160(SHA-256(pubkey))) with the XRPL alphabet.
    const ALPHA = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
    const payload = new Uint8Array([0, ...ripemd160(sha256(pk))]);
    const full = new Uint8Array([...payload, ...sha256(sha256(payload)).subarray(0, 4)]);
    let n = BigInt(`0x${hex(full)}`);
    let s = '';
    while (n > 0n) {
      s = ALPHA[Number(n % 58n)] + s;
      n /= 58n;
    }
    expect(slotAddress(pub)).toBe(`r${s}`);
  });

  it('P1.15-12 60 signatures across all 3 pairs pass strict verification (repeats the r7 run)', () => {
    let ok = 0;
    for (let i = 0; i < 60; i++) {
      const msg = enc(`r7 regression ${i}`);
      const sig = frostSign(pub, pairs[i % 3]!, msg);
      if (ed25519.verify(sig, msg, pub.commitments[0]!, { zip215: false })) ok++;
    }
    expect(ok).toBe(60);
  }, 60_000);
});

describe('budgets and imports', () => {
  it('P1.15-22 one DKG under 1 s and one signing round under 250 ms (best of 3, so a busy machine does not fail it)', async () => {
    const dkgTimes: number[] = [];
    const signTimes: number[] = [];
    for (let i = 0; i < 3; i++) {
      let t = performance.now();
      const s = await dkgKeys('B');
      dkgTimes.push(performance.now() - t);
      t = performance.now();
      frostSign(s.pub, [s.keys[0]!.secret, s.keys[2]!.secret], enc('budget'));
      signTimes.push(performance.now() - t);
    }
    expect(Math.min(...dkgTimes)).toBeLessThan(1000);
    expect(Math.min(...signTimes)).toBeLessThan(250);
  }, 60_000); // I-9: a loaded machine needs a longer test budget; the 1 s and 250 ms assertions stay

  it('P1.15-23 frost.ts and xrpl 5.3.0 load in one process with static imports (Node 24)', async () => {
    const xrpl = await import('xrpl');
    const frost = await import('../src/frost.ts');
    expect(typeof xrpl.deriveAddress).toBe('function');
    expect(frost.slotAddress(pub)).toBe(xrpl.deriveAddress(hex(slotPubkey(pub)).toUpperCase()));
    expect(process.versions.node.split('.')[0]).toBe('24');
    expect(typeof ed25519_FROST.commit).toBe('function');
  });
});
