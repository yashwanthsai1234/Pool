// The coordinator's read-only ledger relay (contracts `ledger.*`; I-31, task 4.4): validated `account_info` and a
// reliable submit for clients without their own XRPL connection. It only forwards: a submitted blob is already
// signed, and every answer comes from a validated ledger (LedgerPort reads nothing else).
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_info
import type { LedgerPort, SubmitResult } from '@legx/contracts/ports';
import type { XrplAddress } from '@legx/contracts/values';

/** rippled's `actNotFound`: the account does not exist at that ledger. */
const notFound = (e: unknown): boolean => (e as { data?: { error?: unknown } } | null)?.data?.error === 'actNotFound';

export async function accountInfo(ledger: LedgerPort, address: string) {
  const at = (await ledger.validatedLedger()).ledgerIndex;
  try {
    const snap = await ledger.snapshot([address as XrplAddress], at);
    const d = snap.accounts[address]?.accountData;
    if (!d) return { exists: false as const, ledgerIndex: at };
    return {
      exists: true as const,
      ledgerIndex: at,
      flags: Number(d.Flags),
      sequence: Number(d.Sequence),
      balanceDrops: String(d.Balance),
    };
  } catch (e) {
    if (notFound(e)) return { exists: false as const, ledgerIndex: at };
    throw e;
  }
}

export async function submitBlob(ledger: LedgerPort, txBlob: string) {
  const r: SubmitResult = await ledger.submitReliable(txBlob);
  if (r.status === 'validated') return { status: r.status, result: r.result, hash: r.hash, ledgerIndex: r.ledgerIndex };
  return r;
}
