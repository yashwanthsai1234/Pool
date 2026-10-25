// A LedgerPort stub for the unit tests: a controllable validated ledger, canned transactions and snapshots, and a
// submit that records what it was given. The real-ledger tests (test-int) use `ledgerPort` from @legx/xrpl instead.

import type {
  AccountSnapshot,
  LedgerHeader,
  LedgerPort,
  SubmitResult,
  ValidatedTx,
  XrplJson,
} from '@legx/contracts/ports';
import { decode, hashes } from 'xrpl';

export class StubLedger implements LedgerPort {
  readonly network = 'standalone' as const;
  index = 1000;
  closeTime = 800_000_000;
  readonly txs = new Map<string, ValidatedTx>();
  readonly accounts = new Map<string, AccountSnapshot>();
  readonly submitted: string[] = [];
  readonly autofillCalls: { tx: XrplJson; signersCount: number }[] = [];
  nextSubmit: (blob: string) => SubmitResult = () => {
    throw new Error('no submit result set');
  };
  nextSequence = 5;
  fail: { validatedLedger?: boolean } = {};

  async validatedLedger(): Promise<LedgerHeader> {
    return { ledgerIndex: this.index, ledgerHash: this.hash(this.index), closeTime: this.closeTime as never };
  }
  hash(i: number): never {
    return i.toString(16).toUpperCase().padStart(64, 'A') as never;
  }
  async ledgerHeader(i: number): Promise<LedgerHeader> {
    return { ledgerIndex: i, ledgerHash: this.hash(i), closeTime: this.closeTime as never };
  }
  async snapshot(accounts: readonly string[], ledgerIndex?: number) {
    const i = ledgerIndex ?? this.index;
    return {
      ledger: { ledgerIndex: i, ledgerHash: this.hash(i), closeTime: this.closeTime },
      accounts: Object.fromEntries(accounts.map((a) => [a, this.accounts.get(a) as AccountSnapshot])),
    } as never;
  }
  async tx(hash: string) {
    return this.txs.get(hash);
  }
  async autofill(tx: XrplJson, signersCount: number) {
    this.autofillCalls.push({ tx, signersCount });
    return {
      ...tx,
      Sequence: tx.Sequence ?? this.nextSequence,
      LastLedgerSequence: tx.LastLedgerSequence ?? this.index + 20,
      Fee: tx.Fee ?? String(10 * (1 + signersCount)),
    };
  }
  async submitReliable(blob: string) {
    this.submitted.push(blob);
    const r = this.nextSubmit(blob);
    // A validated result means the transaction is now on the ledger: `tx` finds it from then on.
    if (r.status === 'validated')
      this.txs.set(hashes.hashSignedTx(blob), {
        hash: r.hash,
        ledgerIndex: r.ledgerIndex,
        closeTime: this.closeTime as never,
        tx: decode(blob),
        meta: r.meta,
      });
    return r;
  }
  async fees() {
    return { baseFee: '10', reserveBase: '1000000', reserveInc: '200000' } as never;
  }
  advance(n = 1) {
    this.index += n;
    this.closeTime += 4 * n;
  }
}
