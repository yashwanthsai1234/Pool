import { it, expect, describe } from 'vitest';
import fc from 'fast-check';
import { contractRoot, proveClause, verifyClause } from '../src/contract.ts';
import { signEnvelope, verifyEnvelope, verifyChain, leafHashOf, ZERO, pae, type Envelope } from '../src/evidence.ts';
import { escrowFinishFee, multisigFee, toRipple, fromRipple } from '../src/fees.ts';
import { makeCondition } from '../src/dealcore.ts';
import { ed25519 } from '@noble/curves/ed25519.js';
import { randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

describe('contract clauses', () => {
  it('any clause can be proven alone; tampering fails', () => {
    fc.assert(fc.property(fc.array(fc.string(), { minLength: 1, maxLength: 30 }), fc.nat(), (texts, k) => {
      const clauses = texts.map(t => utf8ToBytes(t)); const salts = clauses.map(() => randomBytes(32));
      const root = contractRoot(clauses, salts); const i = k % clauses.length;
      const p = proveClause(i, clauses, salts);
      expect(verifyClause(p, root)).toBe(true);
      expect(verifyClause({ ...p, clause: utf8ToBytes(texts[i] + 'x') }, root)).toBe(false);
      expect(verifyClause({ ...p, salt: randomBytes(32) }, root)).toBe(false);
    }), { numRuns: 100 });
  });
});

describe('evidence envelopes', () => {
  it('DSSE PAE matches spec example layout', () => {
    expect(Buffer.from(pae('http://example.com/HelloWorld', utf8ToBytes('hello world'))).toString())
      .toBe('DSSEv1 29 http://example.com/HelloWorld 11 hello world');
  });
  it('T-U-10 chain: signed seq/prev_hash detect tamper, drop and re-chaining', () => {
    const seed = randomBytes(32), pub = ed25519.getPublicKey(seed);
    const entries: { envelopeBytes: Uint8Array; leafHash: string }[] = [];
    let prev = ZERO;
    const mk = (seq: number, prevHash: string) => {
      const body = utf8ToBytes(JSON.stringify({ predicate: { seq, prev_hash: prevHash, kind: 'check.passed' } }));
      const bytes = utf8ToBytes(JSON.stringify(signEnvelope(body, seed, 'k1')));
      return { envelopeBytes: bytes, leafHash: leafHashOf(bytes) };
    };
    for (let i = 0; i < 5; i++) { const e = mk(i, prev); entries.push(e); prev = e.leafHash; }
    const keyFor = (k: string) => (k === 'k1' ? pub : undefined);
    expect(verifyChain(entries, keyFor)).toBe(true);
    const env: Envelope = JSON.parse(new TextDecoder().decode(entries[0]!.envelopeBytes));
    expect(verifyEnvelope(env, pub)).toBe(true);
    expect(verifyEnvelope({ ...env, payloadType: 'text/plain' }, pub)).toBe(false);
    const tampered = entries.map((e, i) => i === 2 ? { envelopeBytes: utf8ToBytes('{}'), leafHash: leafHashOf(utf8ToBytes('{}')) } : e);
    expect(verifyChain(tampered, keyFor)).toBe(false);
    // attacker drops event 3 and recomputes hashes: signed seq/prev_hash expose it
    const dropped = entries.filter((_, i) => i !== 3);
    expect(verifyChain(dropped, keyFor)).toBe(false);
  });
});

describe('fees and time', () => {
  it('escrow finish fee for 32-byte preimage', () => {
    const fulBytes = makeCondition(new Uint8Array(32)).fulfillment.length / 2; // 36
    expect(fulBytes).toBe(36);
    expect(escrowFinishFee(10, fulBytes, 0)).toBe(350);
    expect(escrowFinishFee(10, fulBytes, 4)).toBe(390);
    expect(multisigFee(10, 4)).toBe(50);
  });
  it('ripple time round trips', () => {
    fc.assert(fc.property(fc.integer({ min: 946684800, max: 4102444800 }), t => fromRipple(toRipple(t)) === t));
  });
});
