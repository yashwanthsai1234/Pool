import { describe, expect, it } from 'vitest';
import { Wallet } from 'xrpl';

// Proves xrpl.js runs in the browser with no Node polyfills (the Vite config has none).
// Source: https://github.com/XRPLF/xrpl.js/blob/main/UNIQUE_SETUPS.md
describe('xrpl.js smoke import', () => {
  it('derives a wallet and signs without Node polyfills', () => {
    const wallet = Wallet.fromSeed('sEdTM1uX8pu2do5XvTnutH6HsouMaM2'); // public XRPL docs example seed
    expect(wallet.classicAddress).toMatch(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/);
    const { hash } = wallet.sign({
      TransactionType: 'Payment',
      Account: wallet.classicAddress,
      Destination: 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe',
      Amount: '1',
      Sequence: 1,
      Fee: '10',
    });
    expect(hash).toMatch(/^[0-9A-F]{64}$/);
    expect(
      'process' in globalThis && typeof (globalThis as { process?: { versions?: unknown } }).process?.versions,
    ).not.toBe('object');
  });
});
