// Deal rows and their views. State never changes here: every state change is an event applied in events.ts or
// signatures.ts, stored in one transaction with its evidence event and outbox row (P3.2-03).
import type { DealView } from '@legx/contracts/api';
import type { Repos } from '@legx/db';
import type { DealRow } from '@legx/db/repos/deals';
import type { z } from 'zod';
import type { CoordinatorDeps } from './deps.ts';
import { conflict, notFound, unprocessable } from './errors.ts';
import { parseStored } from './log.ts';
import { appendCoordinatorEvent } from './statements.ts';

export type DealViewData = z.infer<typeof DealView>;

const ZERO_ROOT = '00'.repeat(32);
export const hasContractRoot = (d: DealRow) => d.contract_root !== ZERO_ROOT;

/** What `deals.create` fixed, kept in the log's first event because the deal table has no column for the policy. */
export interface DealConfig {
  readonly identity_policy: string;
}

export async function requireDeal(repos: Repos, dealId: string): Promise<DealRow> {
  const d = await repos.deals.get(dealId);
  if (!d) throw notFound(`no deal ${dealId}`);
  return d;
}

export async function loadConfig(repos: Repos, dealId: string): Promise<DealConfig> {
  const first = await repos.evidenceEvents.getBySeq(dealId, 0);
  const e = first && parseStored(0, first.leaf_hash, first.envelope);
  if (e?.kind !== 'deal.created') throw new Error(`deal ${dealId} has no genesis event`);
  return { identity_policy: e.data.identity_policy as string };
}

export interface NewDealInput {
  network: string;
  identityPolicy: string;
  amountDrops: string;
  payoutA: string;
  payoutB: string;
  lawyerOpsA: string;
  lawyerOpsB: string;
}

/** Creates the row and the genesis event in one transaction. The contract root is a zero placeholder until `setContract`. */
export async function createDeal(deps: CoordinatorDeps, input: NewDealInput): Promise<DealViewData> {
  if (input.network !== deps.ledger.network)
    throw unprocessable('wrong_network', `this coordinator serves ${deps.ledger.network}, not ${input.network}`);
  if (input.network === 'mainnet') throw unprocessable('wrong_network', 'mainnet is not available');
  if (input.lawyerOpsA === input.lawyerOpsB) throw unprocessable('bad_deal', 'the two operations accounts must differ');
  const header = await deps.ledger.validatedLedger();
  const dealId = await deps.db.transaction(async (repos) => {
    const row = await repos.deals.insert({
      state: 'DRAFT',
      network: input.network as DealRow['network'],
      contract_root: ZERO_ROOT,
      payout_a: input.payoutA,
      payout_b: input.payoutB,
      amount_drops: input.amountDrops,
    });
    await repos.deals.update(row.deal_id, {
      lawyer_ops_a: input.lawyerOpsA,
      lawyer_ops_b: input.lawyerOpsB,
      releaser_account: input.lawyerOpsB,
    });
    await appendCoordinatorEvent(repos, deps.signer, {
      dealId: row.deal_id,
      kind: 'deal.created',
      data: { identity_policy: input.identityPolicy, network: input.network, amount_drops: input.amountDrops },
      contractRoot: ZERO_ROOT,
      closeTime: header.closeTime,
      beforeAppend: async () => 'DRAFT',
    });
    await deps.crash?.('deal.afterStateWrite');
    return row.deal_id;
  });
  return await viewOf(deps.db.repos, dealId);
}

export async function viewOf(repos: Repos, dealId: string): Promise<DealViewData> {
  const d = await requireDeal(repos, dealId);
  const cfg = await loadConfig(repos, dealId);
  const escrow =
    d.escrow_owner !== null && d.escrow_sequence !== null && d.condition_hex !== null && d.cancel_after !== null
      ? {
          owner: d.escrow_owner,
          offer_sequence: d.escrow_sequence,
          amount_drops: d.amount_drops,
          condition: d.condition_hex,
          cancel_after: d.cancel_after,
        }
      : undefined;
  return {
    dealId: d.deal_id,
    state: d.state,
    network: d.network,
    identityPolicy: cfg.identity_policy,
    amountDrops: d.amount_drops,
    payoutA: d.payout_a,
    payoutB: d.payout_b,
    lawyerOpsA: d.lawyer_ops_a,
    lawyerOpsB: d.lawyer_ops_b,
    ...(hasContractRoot(d) ? { contractRoot: d.contract_root } : {}),
    ...(d.shell_address ? { walletAddress: d.shell_address } : {}),
    ...(d.signed_contract_seal ? { signedContractSeal: d.signed_contract_seal } : {}),
    ...(d.deal_seal ? { dealSeal: d.deal_seal } : {}),
    ...(d.nft_token_id ? { nftTokenId: d.nft_token_id } : {}),
    ...(d.mint_tx_hash ? { mintTxHash: d.mint_tx_hash } : {}),
    ...(escrow ? { escrow } : {}),
    ...(d.exit_slot !== null ? { exitSlot: d.exit_slot } : {}),
  } as DealViewData;
}

/** Alice fixes the wallet address once, while the deal is a draft (DESIGN 5.2 P1). A retry with the same value is a no-op. */
export async function setWallet(deps: CoordinatorDeps, dealId: string, walletAddress: string): Promise<DealViewData> {
  await deps.db.transaction(async (repos) => {
    const d = await requireDeal(repos, dealId);
    if (d.shell_address === walletAddress) return;
    if (d.state !== 'DRAFT' || d.shell_address !== null)
      throw conflict('wallet_fixed', 'the wallet address is already fixed');
    await repos.deals.update(dealId, { shell_address: walletAddress });
  });
  return await viewOf(deps.db.repos, dealId);
}

/**
 * Lawyer A fixes the contract root once, while the deal is a draft. The repository does not offer a setter for
 * `contract_root` (it is NOT NULL and the create call needs it), so this one place writes the column through `update`
 * (Request to 3.1 in 3.2.md: a `setContractRoot`).
 */
export async function setContract(deps: CoordinatorDeps, dealId: string, contractRoot: string): Promise<DealViewData> {
  await deps.db.transaction(async (repos) => {
    const d = await requireDeal(repos, dealId);
    if (d.contract_root === contractRoot) return;
    if (d.state !== 'DRAFT' || hasContractRoot(d))
      throw conflict('contract_fixed', 'the contract root is already fixed');
    await repos.deals.update(dealId, { contract_root: new Uint8Array(Buffer.from(contractRoot, 'hex')) } as never);
  });
  return await viewOf(deps.db.repos, dealId);
}
