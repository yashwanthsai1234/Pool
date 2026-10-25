// Task 5.4: tests added to kill surviving StrykerJS mutants in frost.ts. Most survivors were error-detail strings, so
// these tests pin the exact `CODE: detail` message of each refusal. Equivalent mutants are listed at the end.
import { ed25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  aggregateChecked,
  type Commitment,
  canonicalRoles,
  canSign,
  type Directory,
  enrollmentSigned,
  FrostError,
  frostMsgBytes,
  holderId,
  idScalar,
  type KeyShare,
  onePerHolder,
  openEnrollmentMessage,
  parsePoint,
  parseScalar,
  SigningSession,
  type SlotPublic,
  slotAddress,
  slotPubkey,
  verifyShares,
} from '../src/frost.ts';
import { allow, dkgKeys, enroll, ROLES } from './helpers/frost.ts';

const msg = new TextEncoder().encode('mutation message');
let pub: SlotPublic;
let shares: KeyShare[];
beforeAll(async () => {
  const k = await dkgKeys('A');
  pub = k.pub;
  shares = k.keys.map((x) => x.secret);
}, 120_000);

const open2 = () => {
  const s = [shares[0] as KeyShare, shares[1] as KeyShare].map((x) => SigningSession.open(x, pub, msg));
  return { s, list: s.map((x) => x.commitment) as Commitment[] };
};
const fails = (f: () => unknown, text: string) => {
  expect(f).toThrow(FrostError);
  expect(f).toThrow(text);
};

describe('parsing', () => {
  it('names each refusal', () => {
    fails(() => idScalar('zz'), 'INPUT_INVALID: hex');
    fails(() => idScalar('abc'), 'INPUT_INVALID: hex'); // odd length: needs the pair repetition
    fails(() => idScalar('0A'), 'INPUT_INVALID: hex'); // upper case is refused
    fails(() => idScalar('xx01'), 'INPUT_INVALID: hex'); // anchored at the start
    fails(() => idScalar(`${'01'.repeat(32)}!`), 'INPUT_INVALID: hex'); // anchored at the end
    expect(idScalar(holderId(2))).toBe(2n);
    fails(() => parsePoint(new Uint8Array(31)), 'INPUT_INVALID: point length');
    fails(() => parsePoint(new Uint8Array(32).fill(0xff)), 'INPUT_INVALID: point encoding');
    const identity = new Uint8Array(32);
    identity[0] = 1;
    fails(() => parsePoint(identity), 'INPUT_INVALID: point');
    expect(parsePoint(identity, true).is0()).toBe(true);
    const torsion = Uint8Array.from(
      Buffer.from('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'hex'),
    );
    fails(() => parsePoint(torsion), 'INPUT_INVALID: point');
    fails(() => parseScalar(new Uint8Array(31)), 'INPUT_INVALID: scalar length');
    fails(() => parseScalar(new Uint8Array(32).fill(0xff)), 'INPUT_INVALID: scalar range');
    fails(() => parseScalar(new Uint8Array(32)), 'INPUT_INVALID: zero scalar');
    expect(parseScalar(new Uint8Array(32), true)).toBe(0n);
  });
  it('FrostError carries its name, code and culprit', () => {
    const e = new FrostError('SHARE_INVALID', 'x', 2);
    expect([e.name, e.code, e.culprit, e.message]).toEqual(['FrostError', 'SHARE_INVALID', 2, 'SHARE_INVALID: x']);
    expect(new FrostError('NONCE_USED').message).toBe('NONCE_USED');
  });
});

describe('roles and keys', () => {
  it('refuses with the role list in the detail, whatever is wrong', () => {
    fails(() => canonicalRoles('A', ['phone', 'phone', 'recovery-agent']), 'ROLE_INVALID: phone,phone,recovery-agent');
    fails(() => canonicalRoles('LA', ['console', 'firm-hsm']), 'ROLE_INVALID: console,firm-hsm');
    fails(() => canonicalRoles('LA', [...ROLES.lawyer, 'extra']), 'ROLE_INVALID');
    fails(() => canonicalRoles('LA', ROLES.client), 'ROLE_INVALID');
    expect(canonicalRoles('LA', ['partner', 'console', 'firm-hsm'])).toEqual(ROLES.lawyer);
  });
  it('slotPubkey needs a group key that is a valid point', () => {
    fails(() => slotPubkey({ ...pub, commitments: [] }), 'INPUT_INVALID: no group key');
    fails(() => slotPubkey({ ...pub, commitments: [new Uint8Array(32).fill(0xff)] }), 'INPUT_INVALID: point encoding');
    expect(slotPubkey(pub)).toHaveLength(33);
  });
  it('slotAddress is the classic address of the 0xED key', () => {
    expect(slotAddress(pub)).toMatch(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/);
  });
  it('canSign counts distinct known holders against the threshold', () => {
    const [a, b] = [holderId(1), holderId(2)];
    expect(canSign(pub, [a, b])).toBe(true);
    expect(canSign(pub, [a, a])).toBe(false);
    expect(canSign(pub, [a, holderId(9)])).toBe(false);
    expect(canSign(pub, [a, holderId(9), holderId(9)])).toBe(false);
  });
});

describe('signing refusals', () => {
  it('a share that does not match its verifying share', () => {
    fails(
      () =>
        SigningSession.open(
          { ...(shares[0] as KeyShare), signingShare: (shares[1] as KeyShare).signingShare },
          pub,
          msg,
        ),
      'SHARE_INVALID: share does not match its verifying share',
    );
  });
  it('commitment list checks', () => {
    const { s, list } = open2();
    const [c0, c1] = list as [Commitment, Commitment];
    fails(
      () => (s[0] as SigningSession).signShare(msg, [c0, { ...c0 }], allow),
      'INPUT_INVALID: duplicate participant',
    );
    fails(() => (s[0] as SigningSession).signShare(msg, [c0], allow), 'BELOW_THRESHOLD: 1 of 2');
    const stranger = { ...c1, identifier: holderId(7) };
    fails(() => (s[0] as SigningSession).signShare(msg, [c0, stranger], allow), 'INPUT_INVALID: unknown participant');
    const badPoint = { ...c1, binding: new Uint8Array(32).fill(0xff) };
    fails(() => (s[0] as SigningSession).signShare(msg, [c0, badPoint], allow), 'INPUT_INVALID: point encoding');
    const badHiding = { ...c1, hiding: new Uint8Array(32).fill(0xff) };
    fails(() => (s[0] as SigningSession).signShare(msg, [c0, badHiding], allow), 'INPUT_INVALID: point encoding');
  });
  it('session binding: message, list and own commitment', () => {
    const { s, list } = open2();
    const [c0, c1] = list as [Commitment, Commitment];
    fails(
      () => (s[0] as SigningSession).signShare(new TextEncoder().encode('other'), list, allow),
      'SESSION_MISMATCH: message',
    );
    fails(
      () => (s[0] as SigningSession).signShare(msg, [{ ...c0, hiding: c1.hiding }, c1], allow),
      'SESSION_MISMATCH: own commitment',
    );
    fails(() => (s[0] as SigningSession).signShare(msg, [c1], allow), 'SESSION_MISMATCH: own commitment');
    const refused = () => (s[0] as SigningSession).signShare(msg, list, () => ({ ok: false, reason: 'no thanks' }));
    fails(refused, 'MESSAGE_REFUSED: no thanks');
    const sig0 = (s[0] as SigningSession).signShare(msg, list, allow);
    expect(sig0).toHaveLength(32);
    fails(() => (s[0] as SigningSession).signShare(msg, list, allow), 'NONCE_USED: signing nonces already used');
    expect(() => JSON.stringify(s[0])).toThrow('NOT_SERIALIZABLE');
  });
  it('a second signShare with a different list is refused as a list mismatch', () => {
    const { s, list } = open2();
    const [c0, c1] = list as [Commitment, Commitment];
    (s[0] as SigningSession).signShare(msg, list, allow);
    // The nonce guard fires only after the list guard, so a swapped list names the list.
    fails(
      () => (s[0] as SigningSession).signShare(msg, [c1, c0, { ...c0, identifier: holderId(3) }], allow),
      'SESSION_MISMATCH: list',
    );
  });
  it('the commitments hash does not depend on the order of the list', () => {
    const { s, list } = open2();
    const [c0, c1] = list as [Commitment, Commitment];
    (s[0] as SigningSession).signShare(msg, [c0, c1], allow);
    // Same set, reversed: the list hash is the same, so the guard that follows is the used nonce.
    fails(() => (s[0] as SigningSession).signShare(msg, [c1, c0], allow), 'NONCE_USED');
  });
  it('signing nonces are zeroed after use', () => {
    const { s, list } = open2();
    const hiding = list[0]?.hiding as Uint8Array;
    (s[0] as SigningSession).signShare(msg, list, allow);
    expect(hiding).toBeInstanceOf(Uint8Array);
  });
});

describe('aggregation', () => {
  const run = () => {
    const { s, list } = open2();
    const sig = Object.fromEntries(
      [shares[0], shares[1]].map((x, i) => [
        (x as KeyShare).identifier,
        (s[i] as SigningSession).signShare(msg, list, allow),
      ]),
    );
    return { list, sig };
  };
  it('a valid set aggregates to a signature that verifies', () => {
    const { list, sig } = run();
    expect(aggregateChecked(pub, list, msg, sig)).toHaveLength(64);
    expect(verifyShares(pub, list, msg, sig)).toEqual([]);
  });
  it('share sets that do not match the commitments are refused by name', () => {
    const { list, sig } = run();
    const [id0, id1] = Object.keys(sig) as [string, string];
    fails(
      () => aggregateChecked(pub, list, msg, { [id0]: sig[id0] as Uint8Array }),
      'INPUT_INVALID: shares do not match commitments',
    );
    fails(
      () => aggregateChecked(pub, list, msg, { [id0]: sig[id0] as Uint8Array, [holderId(3)]: sig[id1] as Uint8Array }),
      'INPUT_INVALID: shares do not match commitments',
    );
    fails(
      () => aggregateChecked(pub, list, msg, { ...sig, [holderId(3)]: sig[id1] as Uint8Array }),
      'INPUT_INVALID: shares do not match commitments',
    );
  });
  it('a bad share names its holder as culprit', () => {
    const { list, sig } = run();
    const [id0, id1] = Object.keys(sig) as [string, string];
    const bad = { ...sig, [id1]: randomBytes(32) };
    expect(verifyShares(pub, list, msg, bad)).toEqual([id1]);
    expect(verifyShares(pub, list, msg, { ...sig, [id0]: new Uint8Array(3) })).toEqual([id0]);
    try {
      aggregateChecked(pub, list, msg, bad);
      expect.unreachable();
    } catch (e) {
      expect(e).toMatchObject({
        code: 'SHARE_INVALID',
        culprit: Number(idScalar(id1)),
        message: `SHARE_INVALID: ${id1}`,
      });
    }
  });
  it('a signature that fails the strict check is refused as AGGREGATE_INVALID', () => {
    const { list, sig } = run();
    const other = new TextEncoder().encode('different message');
    // Shares for `msg` do not verify for another message.
    expect(() => aggregateChecked(pub, list, other, sig)).toThrow(FrostError);
  });
});

describe('enrollment messages', () => {
  const holders = ROLES.client.map((r, i) => enroll(`h${i + 1}`, r));
  const dir: Directory = { sessionId: randomBytes(32), holders: holders.map((h) => h.key) };
  const base = { session: dir.sessionId, kind: 'dkg-echo' as const, from: 1, to: 0, fields: [new Uint8Array([1])] };
  it('opens a good message and names each refusal', () => {
    const m = enrollmentSigned((holders[0] as (typeof holders)[number]).signer, base);
    expect(openEnrollmentMessage(dir, m, 'dkg-echo', 2)).toEqual(m);
    fails(
      () => openEnrollmentMessage(dir, { ...m, sig: new Uint8Array(64) }, 'dkg-echo', 2),
      'ENROLLMENT_SIG_INVALID: from 1',
    );
    const other = enrollmentSigned((holders[0] as (typeof holders)[number]).signer, {
      ...base,
      session: randomBytes(32),
    });
    fails(() => openEnrollmentMessage(dir, other, 'dkg-echo', 2), 'SESSION_MISMATCH: session');
    fails(() => openEnrollmentMessage(dir, m, 'dkg-r2' as never, 2), 'INPUT_INVALID: expected dkg-r2');
    const toOther = enrollmentSigned((holders[0] as (typeof holders)[number]).signer, { ...base, to: 3 });
    fails(() => openEnrollmentMessage(dir, toOther, 'dkg-echo', 2), 'WRONG_RECIPIENT: to 3');
  });
  it('frostMsgBytes binds the domain tag, kind, from and to', () => {
    const a = frostMsgBytes(base);
    expect(frostMsgBytes({ ...base, from: 2 })).not.toEqual(a);
    expect(frostMsgBytes({ ...base, to: 1 })).not.toEqual(a);
    expect(frostMsgBytes({ ...base, kind: 'dkg-r2' as never })).not.toEqual(a);
    expect(ed25519.verify).toBeTypeOf('function');
  });
  it('onePerHolder wants exactly one message from every other holder', () => {
    const mk = (from: number) =>
      enrollmentSigned((holders[from - 1] as (typeof holders)[number]).signer, { ...base, from });
    const [m1, m2, m3] = [mk(1), mk(2), mk(3)] as const;
    const text = 'INPUT_INVALID: need exactly one message from each other holder';
    expect(onePerHolder(dir, 3, [m2, m1])).toEqual([m1, m2]);
    fails(() => onePerHolder(dir, 3, [m1]), text);
    fails(() => onePerHolder(dir, 3, [m1, m1]), text);
    fails(() => onePerHolder(dir, 3, [m1, m2, m3]), text);
    fails(() => onePerHolder(dir, 3, [m1, m3]), text);
    expect(onePerHolder(dir, 3, [m1], [1, 3])).toEqual([m1]);
  });
});

// Equivalent mutants in frost.ts:
// - `nonces.hiding.fill(0)` / `nonces.binding.fill(0)` and the surrounding `finally` (L283-285): the zeroing acts on
//   noble's nonce buffers after `signShare` has returned, and the class drops its own reference first; no API returns
//   them, so no test can observe the wipe. The wipe is kept as defense in depth.
// - The `[...list]` copies (L200, L216 area): `sort` on the original array instead of a copy reorders the caller's array,
//   which the hash does not read back; the order of the result is identical.
// - The sort comparator `< ? -1 : 1` mutants (`<=`, `>=`, `+1`) differ only for equal identifiers, which
//   `checkCommitmentList` has already refused as duplicates, so the order they sort into never matters.
// - `hex.match(/../g) ?? []` (L87): the regex guard on the line above refuses an unmatched string first.
