import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import * as xrpl from 'xrpl';
import * as d from '../src/dealcore.ts';

const hex = d.bytesToHex;
describe('condition', () => {
  it('T-U-01 matches known vector for all-zero preimage', () => {
    const { condition, fulfillment } = d.makeCondition(new Uint8Array(32));
    expect(condition).toBe('A025802066687AADF862BD776C8FC18B8E9F8E20089714856EE233B3902A591D0D5F2925810120');
    expect(fulfillment).toBe('A0228020' + '00'.repeat(32));
  });
  it('I-25 parseCondition and parseFulfillment read back exactly what makeCondition writes', () => {
    fc.assert(fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (pre) => {
      const { condition, fulfillment } = d.makeCondition(pre);
      expect(d.parseCondition(condition)).toEqual(d.sha256(pre));
      expect(d.parseCondition(condition.toLowerCase())).toEqual(d.sha256(pre));
      expect(d.parseFulfillment(fulfillment)).toEqual(pre);
    }));
    const { condition, fulfillment } = d.makeCondition(new Uint8Array(32));
    for (const bad of [condition.slice(0, -2) + '21', condition + '00', 'A1' + condition.slice(2), fulfillment, '', 'zz']) {
      expect(d.parseCondition(bad), bad).toBeUndefined();
    }
    for (const bad of [condition, fulfillment + '00', 'A0218020' + '00'.repeat(31), fulfillment.slice(0, -2)]) {
      expect(d.parseFulfillment(bad), bad).toBeUndefined();
    }
  });
});

describe('x-key and binding', () => {
  it('deterministic, deal-bound, side-bound', () => {
    fc.assert(fc.property(fc.uint8Array({minLength:32,maxLength:32}), fc.uint8Array({minLength:32,maxLength:32}), (secret, ch) => {
      const c = d.passportCommitment(d.utf8ToBytes('P<UTO...'), new Uint8Array(32).fill(7));
      const a1 = d.deriveXKey(secret, d.dealStamp(ch, 'A'), c, 'A').publicKeyHex;
      const a2 = d.deriveXKey(secret, d.dealStamp(ch, 'A'), c, 'A').publicKeyHex;
      const b = d.deriveXKey(secret, d.dealStamp(ch, 'B'), c, 'B').publicKeyHex;
      expect(a1).toBe(a2); expect(a1).not.toBe(b);
    }), { numRuns: 50 });
  });
  it('binding signature verifies and fails on tamper', () => {
    const secret = d.randomBytes(32), ch = d.sha256(d.utf8ToBytes('contract'));
    const c = d.passportCommitment(d.utf8ToBytes('record'), d.randomBytes(32));
    const { wallet } = d.deriveXKey(secret, d.dealStamp(ch, 'A'), c, 'A');
    const msg = d.bindingMessage(ch, c, wallet.publicKey, 'A');
    const sig = d.signBinding(wallet.privateKey, msg);
    expect(d.verifyBinding(wallet.publicKey, msg, sig)).toBe(true);
    const bad = d.bindingMessage(ch, d.sha256(c), wallet.publicKey, 'A');
    expect(d.verifyBinding(wallet.publicKey, bad, sig)).toBe(false);
  });
});

// T-U-06 (deal seal) moved to dealseal.test.ts with the 29-field seal of DESIGN 6.6 (task 1.6).

describe('merkle', () => {
  it('inclusion proofs verify for all leaves (property)', () => {
    fc.assert(fc.property(fc.array(fc.uint8Array({maxLength:40}), {minLength:1, maxLength:40}), (leaves) => {
      const root = d.mth(leaves);
      leaves.forEach((l, i) => expect(d.verifyInclusion(l, i, leaves.length, d.inclusionPath(i, leaves), root)).toBe(true));
    }), { numRuns: 100 });
  });
  it('empty tree root is SHA-256 of empty string (RFC 9162)', () => {
    expect(hex(d.mth([]))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

describe('xrpl multisign 4-of-4 offline', () => {
  it('combines four signatures into one valid blob', () => {
    const deal = xrpl.Wallet.generate();
    const signers = Array.from({length:4}, () => xrpl.Wallet.generate('ed25519' as any));
    const tx: any = { TransactionType: 'Payment', Account: deal.classicAddress, Destination: signers[1]!.classicAddress,
      Amount: '1000000', Fee: String(12 * (1 + 4)), Sequence: 5, LastLedgerSequence: 1000, SigningPubKey: '' };
    const blobs = signers.map(w => w.sign(tx, true).tx_blob);
    const combined = xrpl.multisign(blobs);
    const decoded: any = xrpl.decode(combined);
    expect(decoded.Signers.length).toBe(4);
    const order = decoded.Signers.map((s: any) => s.Signer.Account);
    const ids = order.map((a: string) => Buffer.from(xrpl.decodeAccountID(a)).toString('hex'));
    expect(ids).toEqual([...ids].sort()); // T-U-08 sorted by numeric AccountID
    expect(decoded.SigningPubKey).toBe('');
  });
});
