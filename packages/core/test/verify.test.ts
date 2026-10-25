// Task 1.4: strict XRPL-key signature checks (DESIGN 6.8, IMPLEMENTATION 1.4).
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes, numberToBytesLE } from '@noble/curves/utils.js';
import { sha512 } from '@noble/hashes/sha2.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import * as xrpl from 'xrpl';
import { verifyMultisigned, verifyXrplKeySig } from '../src/verify.ts';
import { readJson } from './helpers/vectors.ts';

const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();
const edPub = (raw: Uint8Array) => `ED${up(raw)}`;
const utf8 = (s: string) => new TextEncoder().encode(s);

// Universal ZIP-215 forgery: with a small-order key A, sB = R + kA holds for R = sB on any message.
// Source: https://zips.z.cash/zip-0215 (cofactored equation, small-order keys allowed) and
// https://github.com/novifinancial/ed25519-speccheck (cases 0 and 1: small-order A).
const IDENTITY = hexToBytes(`01${'00'.repeat(31)}`); // canonical encoding of the identity point
const IDENTITY_NONCANON = hexToBytes(`ee${'ff'.repeat(30)}7f`); // y = p + 1: the identity, non-canonical (case 10/11 style)
const forgedSig = (s = 123456789n) =>
  new Uint8Array([...ed25519.Point.BASE.multiply(s).toBytes(), ...numberToBytesLE(s, 32)]);

function nodeEd25519(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pk]),
      format: 'der',
      type: 'spki',
    });
    return nodeVerify(null, msg, key, sig);
  } catch {
    return false;
  }
}

describe('T-U-20a verifyXrplKeySig rejects Ed25519 signatures that only ZIP-215 accepts', () => {
  type Spec = { message: string; pub_key: string; signature: string };
  const spec = readJson<Spec[]>('ed25519', 'speccheck-cases.json');

  it('speccheck cases 0, 1, 9, 10, 11: ZIP-215 accepts, verifyXrplKeySig rejects', () => {
    for (const [i, c] of spec.entries()) {
      if (![0, 1, 9, 10, 11].includes(i)) continue;
      const [m, pk, sig] = [hexToBytes(c.message), hexToBytes(c.pub_key), hexToBytes(c.signature)];
      expect(ed25519.verify(sig, m, pk, { zip215: true }), `zip215 case ${i}`).toBe(true);
      expect(verifyXrplKeySig(edPub(pk), m, c.signature), `strict case ${i}`).toBe(false);
    }
  });

  it('speccheck cases 2 to 5 (valid under both equations) still pass with the ED prefix', () => {
    for (const [i, c] of spec.entries()) {
      if (![2, 3, 4, 5].includes(i)) continue;
      expect(verifyXrplKeySig(edPub(hexToBytes(c.pub_key)), hexToBytes(c.message), c.signature), `case ${i}`).toBe(
        true,
      );
    }
  });

  it('noble zip215.json: all 196 entries are rejected', () => {
    type Z = { vk_bytes: string; sig_bytes: string };
    const zs = readJson<Z[]>('ed25519', 'noble-zip215.json');
    expect(zs).toHaveLength(196);
    const accepted = zs.filter((z) => verifyXrplKeySig(edPub(hexToBytes(z.vk_bytes)), utf8('Zcash'), z.sig_bytes));
    expect(accepted).toEqual([]);
  });

  it('the universal forgery with a small-order key (canonical and non-canonical identity) is rejected', () => {
    const msg = utf8('pay everything to mallory');
    for (const A of [IDENTITY, IDENTITY_NONCANON]) {
      expect(ed25519.verify(forgedSig(), msg, A, { zip215: true })).toBe(true);
      expect(verifyXrplKeySig(edPub(A), msg, up(forgedSig()))).toBe(false);
    }
  });
});

describe('T-U-20b verifyMultisigned rejects the same signature inside a multisigned blob', () => {
  it('three honest signers plus one ZIP-215-only forged signer: ok is false', () => {
    const deal = xrpl.Wallet.generate();
    const honest = [0, 1, 2].map(() => xrpl.Wallet.generate(xrpl.ECDSA.ed25519));
    const forgedPub = edPub(IDENTITY);
    const forgedAccount = xrpl.deriveAddress(forgedPub);
    const tx = {
      TransactionType: 'Payment' as const,
      Account: deal.classicAddress,
      Destination: xrpl.Wallet.generate().classicAddress,
      Amount: '1000000',
      Fee: '60',
      Sequence: 5,
      LastLedgerSequence: 1000,
      SigningPubKey: '',
    };
    const combined = xrpl.decode(xrpl.multisign(honest.map((w) => w.sign(tx, true).tx_blob))) as Record<
      string,
      unknown
    >;
    const msg = hexToBytes(xrpl.encodeForMultiSigning(tx, forgedAccount));
    expect(ed25519.verify(forgedSig(), msg, IDENTITY, { zip215: true })).toBe(true); // the lenient rule would pass it
    const forged = { Signer: { Account: forgedAccount, SigningPubKey: forgedPub, TxnSignature: up(forgedSig()) } };
    const signers = [...(combined.Signers as unknown[]), forged];
    const blob = xrpl.encode({ ...combined, Signers: signers } as never);
    const want = [...honest.map((w) => w.classicAddress), forgedAccount];
    expect(verifyMultisigned(blob, want).ok).toBe(false);
  });
});

describe('P1.4 key forms and secp256k1 rules', () => {
  const msg = utf8('legx test message');

  it('P1.4-01 Ed25519: the ED-prefixed key passes, the bare 32-byte key is rejected', () => {
    const w = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const sig = up(ed25519.sign(msg, hexToBytes(w.privateKey.slice(2))));
    expect(verifyXrplKeySig(w.publicKey, msg, sig)).toBe(true);
    expect(verifyXrplKeySig(w.publicKey.toLowerCase(), msg, sig.toLowerCase())).toBe(true);
    expect(verifyXrplKeySig(w.publicKey.slice(2), msg, sig)).toBe(false);
  });

  const secpCase = () => {
    const sk = secp256k1.utils.randomSecretKey();
    const pub = up(secp256k1.getPublicKey(sk, true));
    const h = sha512(msg).subarray(0, 32); // SHA-512Half
    return { sk, pub, h, der: secp256k1.sign(h, sk, { prehash: false, format: 'der' }) };
  };

  it('P1.4-02 secp256k1 DER low-S over SHA-512Half passes', () => {
    const { pub, der } = secpCase();
    expect(verifyXrplKeySig(pub, msg, up(der))).toBe(true);
  });

  it('P1.4-02 an xrpl.js secp256k1 wallet signature verifies (differential)', () => {
    const w = xrpl.Wallet.generate(xrpl.ECDSA.secp256k1);
    const tx = { TransactionType: 'AccountSet' as const, Account: w.classicAddress, Fee: '12', Sequence: 1 };
    const signed = xrpl.decode(w.sign(tx).tx_blob) as { TxnSignature: string };
    const signingMsg = hexToBytes(xrpl.encodeForSigning({ ...tx, SigningPubKey: w.publicKey }));
    expect(verifyXrplKeySig(w.publicKey, signingMsg, signed.TxnSignature)).toBe(true);
  });

  it('P1.4-03 the same secp256k1 signature with high S fails', () => {
    const { pub, der } = secpCase();
    const s = secp256k1.Signature.fromBytes(der, 'der');
    const high = new secp256k1.Signature(s.r, secp256k1.Point.Fn.ORDER - s.s).toBytes('der');
    expect(verifyXrplKeySig(pub, msg, up(high))).toBe(false);
  });

  it('P1.4-04 a compact (64-byte) secp256k1 signature fails', () => {
    const { sk, pub, h } = secpCase();
    expect(verifyXrplKeySig(pub, msg, up(secp256k1.sign(h, sk, { prehash: false })))).toBe(false);
  });

  it('P1.4-05 an unknown key type (uncompressed 04 key) returns false and does not throw', () => {
    const { sk, h } = secpCase();
    const der = up(secp256k1.sign(h, sk, { prehash: false, format: 'der' }));
    const uncompressed = up(secp256k1.getPublicKey(sk, false));
    expect(() => verifyXrplKeySig(uncompressed, msg, der)).not.toThrow();
    expect(verifyXrplKeySig(uncompressed, msg, der)).toBe(false);
    expect(verifyXrplKeySig(`04${uncompressed.slice(2, 66)}`, msg, der)).toBe(false); // 33 bytes, prefix 04
  });

  it('hostile input returns false, never throws', () => {
    const w = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const hostile = [
      '',
      'zz',
      'ED',
      'E',
      `ED${'00'.repeat(31)}`,
      `${w.publicKey}00`,
      ' '.repeat(66),
      `0x${w.publicKey}`,
    ];
    for (const h of hostile) {
      expect(verifyXrplKeySig(h, msg, '00'.repeat(64))).toBe(false);
      expect(verifyXrplKeySig(w.publicKey, msg, h)).toBe(false);
    }
    expect(verifyXrplKeySig(`02${'ff'.repeat(32)}`, msg, '3006020101020101')).toBe(false); // not on the curve
  });

  it('programmer errors (wrong argument types) throw a TypeError', () => {
    expect(() => verifyXrplKeySig(1 as never, msg, '')).toThrow(TypeError);
    expect(() => verifyXrplKeySig('', 'msg' as never, '')).toThrow(TypeError);
    expect(() => verifyXrplKeySig('', msg, null as never)).toThrow(TypeError);
  });
});

describe('verifyMultisigned on hostile blobs', () => {
  it('garbage, a single-signed blob and a malformed Signer entry give ok: false without throwing', () => {
    const w = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    const tx = { TransactionType: 'AccountSet' as const, Account: w.classicAddress, Fee: '12', Sequence: 1 };
    for (const blob of ['', 'ZZ', '1200', w.sign(tx).tx_blob]) {
      expect(() => verifyMultisigned(blob, [w.classicAddress])).not.toThrow();
      expect(verifyMultisigned(blob, [w.classicAddress]).ok).toBe(false);
    }
    const bad = {
      ...tx,
      SigningPubKey: '',
      Signers: [{ Signer: { Account: w.classicAddress, SigningPubKey: 'ED', TxnSignature: '00' } }],
    };
    expect(verifyMultisigned(xrpl.encode(bad as never), [w.classicAddress]).ok).toBe(false);
  });

  it('a duplicated signer fails even when both copies verify', () => {
    const deal = xrpl.Wallet.generate();
    const ws = [0, 1, 2].map(() => xrpl.Wallet.generate(xrpl.ECDSA.ed25519));
    const tx = {
      TransactionType: 'AccountSet' as const,
      Account: deal.classicAddress,
      Fee: '48',
      Sequence: 2,
      SigningPubKey: '',
    };
    const dec = xrpl.decode(xrpl.multisign(ws.map((w) => w.sign(tx, true).tx_blob))) as { Signers: unknown[] };
    const dup = xrpl.encode({ ...dec, Signers: [...dec.Signers, dec.Signers[0]] } as never);
    expect(
      verifyMultisigned(dup, [...ws.map((w) => w.classicAddress), ...ws.slice(0, 1).map((w) => w.classicAddress)]).ok,
    ).toBe(false);
  });
});

describe('properties', () => {
  const bytes = (n: number) => fc.uint8Array({ minLength: n, maxLength: n });
  const flip = (b: Uint8Array, bit: number) => {
    const c = b.slice();
    const i = (bit >> 3) % c.length;
    c[i] = (c[i] ?? 0) ^ (1 << (bit & 7));
    return c;
  };

  it('Ed25519: sign then verify is true; flipping one bit of message, signature or key gives false', () => {
    fc.assert(
      fc.property(bytes(32), fc.uint8Array({ minLength: 1, maxLength: 64 }), fc.nat(), (seed, m, bit) => {
        const pub = ed25519.getPublicKey(seed);
        const sig = ed25519.sign(m, seed);
        expect(verifyXrplKeySig(edPub(pub), m, up(sig))).toBe(true);
        expect(verifyXrplKeySig(edPub(pub), flip(m, bit), up(sig))).toBe(false);
        expect(verifyXrplKeySig(edPub(pub), m, up(flip(sig, bit)))).toBe(false);
        expect(verifyXrplKeySig(edPub(flip(pub, bit)), m, up(sig))).toBe(false);
        // Differential: Node crypto (OpenSSL) agrees on the honest signature.
        expect(nodeEd25519(pub, m, sig)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('secp256k1: sign then verify is true; flipping one bit of message, signature or key gives false', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 64 }), fc.nat(), (m, bit) => {
        const sk = secp256k1.utils.randomSecretKey();
        const pub = secp256k1.getPublicKey(sk, true);
        const der = secp256k1.sign(sha512(m).subarray(0, 32), sk, { prehash: false, format: 'der' });
        expect(verifyXrplKeySig(up(pub), m, up(der))).toBe(true);
        expect(verifyXrplKeySig(up(pub), flip(m, bit), up(der))).toBe(false);
        expect(verifyXrplKeySig(up(pub), m, up(flip(der, bit)))).toBe(false);
        expect(verifyXrplKeySig(up(flip(pub, bit)), m, up(der))).toBe(false);
      }),
      { numRuns: 50 },
    );
  });

  it('random strings never make it throw', () => {
    fc.assert(
      fc.property(fc.string(), fc.uint8Array(), fc.string(), (p, m, s) => {
        expect(typeof verifyXrplKeySig(p, m, s)).toBe('boolean');
      }),
    );
  });
});
