// Exit slot S (DESIGN 7.5, decision D9). When the deal is funded the coordinator records the wallet's next Sequence
// as slot S (events.ts, `release.performed`). Both candidate exits (pay Bob, refund Alice) are built on S, so only the
// first validated one counts (the other fails with tefPAST_SEQ). A `tec` result uses S up without moving money: both
// candidates are voided, S+1 is recorded, and signatures are collected again.
import type { Repos } from '@legx/db';
import type { DealRow } from '@legx/db/repos/deals';
import { build8, build9 } from '@legx/xrpl';
import type { CoordinatorDeps } from './deps.ts';
import { unprocessable } from './errors.ts';

export const EXIT_PURPOSES = ['pay_bob', 'refund_alice'] as const;
export type ExitPurpose = (typeof EXIT_PURPOSES)[number];
export const isExit = (p: string): p is ExitPurpose => (EXIT_PURPOSES as readonly string[]).includes(p);
/** Purposes the coordinator builds. The others of the route table belong to later tasks (3.2.md, Known gaps). */
export const SUPPORTED_PURPOSES = [...EXIT_PURPOSES, 'close'] as const;

/** LastLedgerSequence = validated + 1800 for signatures that may take hours (DESIGN 7.5 step 2). */
export const COLLECTION_WINDOW = 1800;

const EXIT_STATES = ['FUNDED', 'DISPUTED'];
const CLOSE_STATES = ['PAID_OUT', 'REFUNDED', 'EXPIRED'];

/** The unsigned transaction of one purpose, before autofill. Source: DESIGN 7.3 steps 8 and 9; IMPLEMENTATION P3.2-04. */
export async function buildUnsigned(
  deps: CoordinatorDeps,
  deal: DealRow,
  purpose: string,
): Promise<Record<string, unknown>> {
  const network = deal.network as 'standalone' | 'testnet' | 'devnet';
  const fees = await deps.ledger.fees();
  const ctx = { network, baseFeeDrops: Number(fees.baseFee) };
  const shell = deal.shell_address as string;
  if (isExit(purpose)) {
    if (!EXIT_STATES.includes(deal.state)) throw unprocessable('wrong_state', `no exit in ${deal.state}`);
    if (deal.exit_slot === null) throw unprocessable('no_slot', 'slot S is not recorded');
    return build8(
      {
        shell,
        payout: purpose === 'pay_bob' ? deal.payout_b : deal.payout_a,
        amount: deal.amount_drops,
        slot: { sequence: deal.exit_slot },
      },
      ctx,
    ) as unknown as Record<string, unknown>;
  }
  if (purpose === 'close') {
    if (!CLOSE_STATES.includes(deal.state)) throw unprocessable('wrong_state', `cannot close in ${deal.state}`);
    return build9(
      { shell, destination: deal.payout_a.split(':')[0] as string, ownerReserveDrops: String(fees.reserveInc) },
      ctx,
    ) as unknown as Record<string, unknown>;
  }
  throw new ExitNotSupported(purpose);
}

export class ExitNotSupported extends Error {
  readonly purpose: string;
  constructor(purpose: string) {
    super(`purpose ${purpose} is not built by the coordinator yet`);
    this.purpose = purpose;
  }
}

/** A `tec` exit used S up: void every open exit candidate and record S+1. Call inside the transaction. */
export async function advanceSlot(repos: Repos, deal: DealRow): Promise<void> {
  for (const r of await repos.signatureRequests.listOpen(deal.deal_id))
    if (isExit(r.purpose)) await repos.signatureRequests.setStatus(r.request_id, 'void');
  await repos.deals.update(deal.deal_id, { exit_slot: (deal.exit_slot as number) + 1 });
}
