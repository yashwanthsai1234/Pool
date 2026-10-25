// Steps 3, 7 and exp: the quarantine escrow (DESIGN 7.3, 6.17).
// Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowcreate
// Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowfinish
// Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowcancel
import { escrowFinishFee } from '@legx/core/fees';
import type { EscrowCancel, EscrowCreate, EscrowFinish } from 'xrpl';
import { addr, type BuildCtx, baseFee, bytes32, DAY, drops, hexUp, memo, seq } from './common.ts';

const HEX = /^(?:[0-9A-F]{2})+$/;
const hexField = (name: string, h: string): string => {
  if (!HEX.test(h)) throw new Error(`${name} must be uppercase hex`);
  return h;
};

/** 3: Alice locks XRP to the shell. CancelAfter is validated close_time + the agreed days (never the local clock). */
export function build3(
  i: { alice: string; shell: string; amount: string; condition: string; closeTime: number; days: number },
  ctx: BuildCtx,
): EscrowCreate {
  if (!Number.isInteger(i.days) || i.days < 1) throw new Error('days must be a positive integer');
  return {
    TransactionType: 'EscrowCreate',
    Account: addr(i.alice),
    Destination: addr(i.shell),
    Amount: drops(i.amount),
    Condition: hexField('condition', i.condition),
    CancelAfter: seq(i.closeTime + i.days * DAY),
    Fee: String(baseFee(ctx)),
  };
}

/** 7: the sealed releaser finishes. One gate memo. No CredentialIDs: account preauth only (D23). Single-signed. */
export function build7(
  i: {
    releaser: string;
    owner: string;
    offerSequence: number;
    condition: string;
    fulfillment: string;
    gateLeafHash: Uint8Array;
  },
  ctx: BuildCtx,
): EscrowFinish {
  const fulfillment = hexField('fulfillment', i.fulfillment);
  return {
    TransactionType: 'EscrowFinish',
    Account: addr(i.releaser),
    Owner: addr(i.owner),
    OfferSequence: seq(i.offerSequence),
    Condition: hexField('condition', i.condition),
    Fulfillment: fulfillment,
    Memos: [memo('legx/release-gate/v1', hexUp(bytes32('gateLeafHash', i.gateLeafHash)))],
    Fee: String(escrowFinishFee(baseFee(ctx), fulfillment.length / 2, 0)),
  };
}

/** exp: anyone cancels after CancelAfter. */
export function buildEscrowCancel(
  i: { account: string; owner: string; offerSequence: number },
  ctx: BuildCtx,
): EscrowCancel {
  return {
    TransactionType: 'EscrowCancel',
    Account: addr(i.account),
    Owner: addr(i.owner),
    OfferSequence: seq(i.offerSequence),
    Fee: String(baseFee(ctx)),
  };
}
