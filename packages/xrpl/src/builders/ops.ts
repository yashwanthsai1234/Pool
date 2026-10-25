// Anchor, TicketCreate and signer-list rotation (DESIGN 8.3, 7.5, 6.13).
// Source: https://xrpl.org/docs/references/protocol/transactions/types/accountset (a flagless AccountSet carries a memo)
// Source: https://xrpl.org/docs/references/protocol/transactions/types/ticketcreate
import { multisigFee } from '@legx/core/fees';
import type { AccountSet, SignerListSet, TicketCreate } from 'xrpl';
import { addr, type BuildCtx, baseFee, bytes32, hexUp, memo, seq } from './common.ts';
import { signerListFields } from './lock.ts';

const U64_MAX = 2n ** 64n - 1n;

/** anchor: C2SP-style checkpoint memo, MemoData = origin hash (32) || tree size (8, big-endian) || root (32). */
export function buildAnchor(
  i: { anchorAccount: string; originHash: Uint8Array; treeSize: bigint; root: Uint8Array },
  ctx: BuildCtx,
): AccountSet {
  if (i.treeSize < 0n || i.treeSize > U64_MAX) throw new Error('treeSize must fit in 8 bytes');
  const size = new Uint8Array(8);
  new DataView(size.buffer).setBigUint64(0, i.treeSize);
  const data = new Uint8Array(72);
  data.set(bytes32('originHash', i.originHash), 0);
  data.set(size, 32);
  data.set(bytes32('root', i.root), 40);
  return {
    TransactionType: 'AccountSet',
    Account: addr(i.anchorAccount),
    Memos: [memo('legx/ckpt/v1', hexUp(data))],
    Fee: String(baseFee(ctx)),
  };
}

/** A 4-of-4 TicketCreate on the deal wallet. Fee = base x (1 + signers). */
export function buildTicketCreate(
  i: { shell: string; count: number; signers?: number; sequence?: number },
  ctx: BuildCtx,
): TicketCreate {
  if (!Number.isInteger(i.count) || i.count < 1 || i.count > 250) throw new Error('count must be 1 to 250');
  return {
    TransactionType: 'TicketCreate',
    Account: addr(i.shell),
    TicketCount: i.count,
    ...(i.sequence === undefined ? {} : { Sequence: seq(i.sequence) }),
    Fee: String(multisigFee(baseFee(ctx), i.signers ?? 4)),
  };
}

/** Key rotation: all four slots sign a new signer list (4-of-4, so Fee = base x 5). */
export function buildSignerListRotation(
  i: { shell: string; signers: readonly string[] },
  ctx: BuildCtx,
): SignerListSet {
  const shell = addr(i.shell);
  return {
    TransactionType: 'SignerListSet',
    Account: shell,
    ...signerListFields(shell, i.signers),
    Fee: String(multisigFee(baseFee(ctx), 4)),
  };
}
