import { describe, expect, it } from 'vitest';
// The enrollment anchor: valid for xrpl.js, never for Mainnet fees.
import xrpl, { validate } from 'xrpl';
import { buildEnrollmentAnchor } from '../src/enrollment.ts';

const a = xrpl.Wallet.generate().classicAddress;
const b = xrpl.Wallet.generate().classicAddress;

describe('builders', () => {
  it('the anchor memo carries exactly the 32-byte list hash and refuses another length', () => {
    const tx = buildEnrollmentAnchor({ account: a, listSha256: new Uint8Array(32).fill(7) }, { network: 'standalone' });
    expect(() => validate(tx as never)).not.toThrow();
    expect(tx.Memos?.[0]?.Memo.MemoData).toBe('07'.repeat(32));
    expect(() =>
      buildEnrollmentAnchor({ account: a, listSha256: new Uint8Array(31) }, { network: 'standalone' }),
    ).toThrow();
  });
});
