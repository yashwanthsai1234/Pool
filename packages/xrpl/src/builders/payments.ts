// Steps 2, 8, 9: the shell funding, the exit payment and the account close (DESIGN 7.3, 7.5).
// Source: https://xrpl.org/docs/references/protocol/transactions/types/payment
// Source: https://xrpl.org/docs/references/protocol/transactions/types/accountdelete
import { multisigFee } from '@legx/core/fees';
import type { AccountDelete, Payment } from 'xrpl';
import { addr, type BuildCtx, baseFee, distinct, drops, type Slot, slotFields } from './common.ts';

/** 2: Alice funds the shell with the reserve budget. */
export function build2(i: { alice: string; shell: string; amount: string }, ctx: BuildCtx): Payment {
  distinct('Payment', i.alice, i.shell);
  return {
    TransactionType: 'Payment',
    Account: addr(i.alice),
    Destination: addr(i.shell),
    Amount: drops(i.amount),
    Fee: String(baseFee(ctx)),
  };
}

/** A sealed payout, `rAddr` or `rAddr:tag` (DESIGN 6.6). */
export function splitPayout(p: string): { address: string; tag?: number } {
  const [a = '', t, ...rest] = p.split(':');
  if (rest.length > 0 || (t !== undefined && !/^(?:0|[1-9][0-9]{0,9})$/.test(t)) || Number(t) > 4_294_967_295) {
    throw new Error('bad payout tag');
  }
  return t === undefined ? { address: addr(a) } : { address: addr(a), tag: Number(t) };
}

/** 8: the deal wallet pays the sealed payout. 4-of-4, built on slot S. Fee = base x (1 + 4). */
export function build8(i: { shell: string; payout: string; amount: string; slot: Slot }, ctx: BuildCtx): Payment {
  const { address, tag } = splitPayout(i.payout);
  distinct('Payment', i.shell, address);
  return {
    TransactionType: 'Payment',
    Account: addr(i.shell),
    Destination: address,
    ...(tag === undefined ? {} : { DestinationTag: tag }),
    Amount: drops(i.amount),
    ...slotFields(i.slot),
    Fee: String(multisigFee(baseFee(ctx), 4)),
  };
}

/** 9: close the deal wallet, sending the rest to Alice. The fee is one owner reserve (rippled adds no signer fee). */
export function build9(
  i: { shell: string; destination: string; ownerReserveDrops: string; slot?: Slot },
  ctx: BuildCtx,
): AccountDelete {
  baseFee(ctx);
  distinct('AccountDelete', i.shell, i.destination);
  return {
    TransactionType: 'AccountDelete',
    Account: addr(i.shell),
    Destination: addr(i.destination),
    ...slotFields(i.slot),
    Fee: drops(i.ownerReserveDrops),
  };
}
