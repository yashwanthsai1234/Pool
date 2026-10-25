// "Test in all directions": the service signs only transactions equal to a plan it can rebuild. The decision is the
// recovery agent's `cosignCheck` over the sealed deal (task 1.15 allow-list), which the HSM runs before it asks for
// the approval; here it is attacked with random bytes and with random changes to a good transaction.
import { bytesToHex } from '@legx/core/dealcore';
import type { SealedDeal } from '@legx/core/frostRules';
import { cosignCheck } from '@legx/recovery-agent/policy';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { decode, deriveAddress, ECDSA, encodeForMultiSigning, Wallet } from 'xrpl';

const addr = () => Wallet.generate(ECDSA.ed25519).classicAddress;
const slotPub = new Uint8Array([0xed, ...Array.from({ length: 32 }, (_, i) => i + 1)]);
const deal: SealedDeal = {
  walletAddress: addr(),
  contractRoot: new Uint8Array(32).fill(1),
  dealSeal: new Uint8Array(32).fill(2),
  payoutA: { account: addr(), tag: 7 },
  payoutB: { account: addr() },
  exitAmountDrops: '5000000000',
  maxFeeDrops: '1000',
  slotPubs: { A: new Uint8Array(33), B: new Uint8Array(33), LA: slotPub, LB: new Uint8Array(33) },
};
const signerAddr = deriveAddress(bytesToHex(slotPub).toUpperCase());
const check = cosignCheck(deal, 'LA', 'console');
const decide = (msg: Uint8Array) =>
  check(msg, [], { request: undefined, begin: { message_kind: 'xrpl-multisign' } as never });
const stranger = addr();

const base = (): Record<string, unknown> => ({
  TransactionType: 'Payment',
  Account: deal.walletAddress,
  Destination: deal.payoutB.account,
  Amount: deal.exitAmountDrops,
  Fee: '120',
  Sequence: 5,
  SigningPubKey: '',
});

describe('the decoder and checker', () => {
  it('refuses random and malformed blobs and never throws', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 300 }), (b) => decide(b).ok === false),
      { numRuns: 500 },
    );
  });

  it('refuses a blob that carries a good transaction under the wrong signer, prefix or tail', () => {
    const good = Buffer.from(encodeForMultiSigning(base() as never, signerAddr), 'hex');
    expect(decide(new Uint8Array(good)).ok).toBe(true);
    const otherSigner = Buffer.from(encodeForMultiSigning(base() as never, addr()), 'hex');
    expect(decide(new Uint8Array(otherSigner)).ok).toBe(false);
    expect(decide(new Uint8Array(good.subarray(0, good.length - 1))).ok).toBe(false);
    expect(decide(new Uint8Array([...good, 0])).ok).toBe(false);
    fc.assert(
      fc.property(fc.nat(good.length - 1), fc.integer({ min: 1, max: 255 }), (i, x) => {
        const b = new Uint8Array(good);
        b[i] = (b[i] as number) ^ x;
        if (!decide(b).ok) return true;
        // Sequence, fee (under the cap) and ledger limits are not sealed; whatever else is signed must still be the plan
        const tx = decode(bytesToHex(b).toUpperCase().slice(8, -40)) as unknown as Record<string, string>;
        return (
          tx.Account === deal.walletAddress &&
          tx.Destination === deal.payoutB.account &&
          tx.Amount === deal.exitAmountDrops
        );
      }),
      { numRuns: 300 },
    );
  });

  it('property: a random change to a good transaction is signed only if it is still the plan', () => {
    const change = fc.record({
      dest: fc.constantFrom('b', 'a', 'x'),
      tag: fc.constantFrom(undefined, 7, 8),
      amount: fc.constantFrom('5000000000', '4999999999', '5000000001', '1'),
      fee: fc.constantFrom('120', '1000', '1001', '0'),
      type: fc.constantFrom('Payment', 'AccountDelete', 'TrustSet', 'SetRegularKey'),
      flags: fc.constantFrom(undefined, 0, 0x80000000, 1),
      account: fc.constantFrom('wallet', 'other'),
    });
    fc.assert(
      fc.property(change, (c) => {
        const dest = c.dest === 'b' ? deal.payoutB.account : c.dest === 'a' ? deal.payoutA.account : stranger;
        const tx: Record<string, unknown> = {
          ...base(),
          TransactionType: c.type,
          Account: c.account === 'wallet' ? deal.walletAddress : stranger,
          Destination: dest,
          Fee: c.fee,
          ...(c.tag !== undefined ? { DestinationTag: c.tag } : {}),
          ...(c.flags !== undefined ? { Flags: c.flags } : {}),
          Amount: c.amount,
        };
        if (c.type !== 'Payment') delete tx.Amount;
        let msg: Uint8Array;
        try {
          msg = new Uint8Array(Buffer.from(encodeForMultiSigning(tx as never, signerAddr), 'hex'));
        } catch {
          return true; // not encodable: nothing to sign
        }
        const payoutOk = (c.dest === 'b' && c.tag === undefined) || (c.dest === 'a' && c.tag === 7);
        const plan =
          c.account === 'wallet' &&
          Number(c.fee) <= 1000 &&
          (c.flags === undefined || c.flags === 0 || c.flags === 0x80000000) &&
          ((c.type === 'Payment' && payoutOk && c.amount === deal.exitAmountDrops) ||
            (c.type === 'AccountDelete' && c.dest === 'a' && c.tag === 7));
        return decide(msg).ok === plan;
      }),
      { numRuns: 600 },
    );
    expect(true).toBe(true);
  });
});
