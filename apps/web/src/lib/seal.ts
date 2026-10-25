// OD-36 (a): hand the vault frame a deal only through its seal. The seal is pinned the first time this key meets the deal (set once,
// so a later coordinator cannot change it); the frame recomputes `dealSeal` of the data and loads it only if it equals the pin.
// The frame's CSP is `connect-src 'none'`, so the page fetches the data; nothing in the seal can be forged by the page.
// Source: build/DECISIONS.md OD-36; DESIGN.md 6.3
import type { PublicDealData } from '@legx/contracts/deal';
import { bytesToHex, dealSeal } from '@legx/core/dealcore';
import type { connectVault } from '@legx/vault';
import type { ApiClient } from './api.ts';

export type SealVault = Pick<ReturnType<typeof connectVault>, 'pinSeal' | 'loadDeal'>;

/** Seal check: the seal recomputed from the public data must equal every seal the coordinator claims. */
export function checkSeal(publicData: PublicDealData, claimed: readonly (string | undefined)[]): string | undefined {
  try {
    const mine = bytesToHex(dealSeal(publicData)).toLowerCase();
    return claimed.every((c) => c?.toLowerCase() === mine) ? mine : undefined;
  } catch {
    return undefined;
  }
}

/** The deal as the phone verified it: the coordinator's view, and the public data only when its recomputed seal matches. */
export async function fetchSealedDeal(api: Pick<ApiClient, 'deals'>, dealId: string) {
  const [deal, data] = await Promise.all([api.deals.get({ dealId }), api.deals.publicData({ dealId })]);
  if (data.status !== 'complete') return { deal, state: 'incomplete' as const };
  const seal = checkSeal(data.publicData as never, [data.dealSeal, deal.dealSeal]);
  return seal
    ? { deal, state: 'ok' as const, publicData: data.publicData, domain: data.domain, seal }
    : { deal, state: 'seal-mismatch' as const };
}

export async function loadSealedDeal(
  vault: SealVault,
  dealId: string,
  data: PublicDealData,
  exitAmountDrops: string,
): Promise<void> {
  await vault.pinSeal(dealId, bytesToHex(dealSeal(data)));
  await vault.loadDeal(dealId, data, exitAmountDrops);
}

/** The party app's source of the data: the public data of a complete deal whose seal matches. */
export async function loadSealedDealFromApi(
  vault: SealVault,
  api: Pick<ApiClient, 'deals'>,
  dealId: string,
): Promise<void> {
  const r = await fetchSealedDeal(api, dealId);
  if (r.state !== 'ok') throw new Error(r.state === 'incomplete' ? 'DEAL_NOT_SEALED' : 'SEAL_MISMATCH');
  await loadSealedDeal(vault, dealId, r.publicData, r.deal.amountDrops);
}
