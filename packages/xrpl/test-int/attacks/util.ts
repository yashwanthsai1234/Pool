// Small helpers shared by the 2.6 tests.
import type { SubmitResult } from '@legx/contracts/ports';
import xrpl from 'xrpl';
import { prepare } from '../../src/prepare.ts';
import type { Chain } from '../roles.ts';
import { newWallet } from '../roles.ts';

type Wallet = InstanceType<typeof xrpl.Wallet>;

/** `validated:tecNO_PERMISSION`, `rejected:tefPAST_SEQ`, `expired`: one comparable word for a final outcome. */
export function outcome(r: SubmitResult): string {
  return r.status === 'validated' || r.status === 'rejected' ? `${r.status}:${r.result}` : r.status;
}

/** A funded account that has no part in the deal. */
export async function stranger(c: Chain, xrp = 100): Promise<Wallet> {
  const w = newWallet('ed25519');
  await c.fund(w, xrp);
  return w;
}

/** The shell's incoming escrow objects that carry this condition (none once finished or cancelled). */
export async function escrowsWith(c: Chain, shell: string, conditionHex: string) {
  const r = await c.client.request({
    command: 'account_objects',
    account: shell,
    type: 'escrow',
    ledger_index: 'validated',
  });
  return (r.result.account_objects as unknown as { Account: string; Condition?: string }[]).filter(
    (o) => o.Condition?.toUpperCase() === conditionHex.toUpperCase(),
  );
}

/**
 * Signs and submits into the OPEN ledger without waiting (the closer is paused, so the test closes the ledger itself).
 * Every transaction placed before the next `accept` sees the same parent ledger.
 */
export async function place(c: Chain, wallet: Wallet, tx: xrpl.SubmittableTransaction) {
  const blob = wallet.sign(await prepare(tx, { client: c.client })).tx_blob;
  await c.rawSubmit(blob);
  return xrpl.hashes.hashSignedTx(blob);
}
