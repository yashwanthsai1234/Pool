// Where a vault frame gets the seal its allow-list compares every request with (OD-36 a, DQ-4.2-c). The frame never trusts a seal it is
// handed: the seal is pinned in the frame's own metadata when the key joins the deal (set once), and the public deal data the page
// hands over is used only if `dealSeal` recomputed over it equals that pin. The seal covers the wallet, contract root, payouts and slot keys;
// only the exit amount is outside it (the coordinator's `amountDrops`), and the firm HSM checks its own copy.
// Source: DESIGN.md 6.6 (deal seal), 6.4 "Code integrity"; build/DECISIONS.md OD-36
import { PublicDealData } from '@legx/contracts/deal';
import { DealId } from '@legx/contracts/values';
import { bytesToHex, dealSeal, hexToBytes } from '@legx/core/dealcore';
import type { Payout, SealedDeal } from '@legx/core/frostRules';
import { VaultError } from './errors.ts';
import type { PartyRole } from './rules.ts';
import { Store } from './store.ts';

type Row = { id: string; role: PartyRole; seal: string };
const MAX_FEE_DROPS = '1000000'; // as the firm cosigner's own limit (apps/server/src/agents.ts)

const payout = (p: string): Payout => {
  const [account, tag] = p.split(':');
  return { account: account as string, ...(tag === undefined ? {} : { tag: Number(tag) }) };
};

export function sealKeeper(opts: { role: PartyRole; dbName?: string }) {
  const store = new Store(opts.dbName ?? 'legx-vault');
  const idOf = (dealId: string) => {
    if (!DealId.safeParse(dealId).success) throw new VaultError('INPUT_INVALID');
    return `${dealId}:${opts.role}:sealpin`;
  };
  const verified = new Map<string, SealedDeal>();
  const pinned = async (dealId: string) => (await store.get<Row>('enrollment', idOf(dealId)))?.seal;
  return {
    /** Pins the seal at join time. Once set, only the same seal is accepted. */
    async pin(dealId: string, seal: string): Promise<void> {
      if (!/^[0-9a-f]{64}$/.test(seal)) throw new VaultError('INPUT_INVALID');
      const have = await pinned(dealId);
      if (have !== undefined && have !== seal) throw new VaultError('INPUT_INVALID');
      if (have === undefined) await store.put('enrollment', { id: idOf(dealId), role: opts.role, seal } satisfies Row);
    },
    /** Accepts the public data only if its recomputed seal is the pinned one. */
    async load(dealId: string, data: unknown, exitAmountDrops: string): Promise<void> {
      const pin = await pinned(dealId);
      if (pin === undefined) throw new VaultError('NOT_FOUND');
      const parsed = PublicDealData.safeParse(data);
      if (!parsed.success || !/^\d{1,16}$/.test(exitAmountDrops)) throw new VaultError('INPUT_INVALID');
      const d = parsed.data;
      let seal: Uint8Array;
      try {
        seal = dealSeal(d);
      } catch {
        throw new VaultError('MESSAGE_REFUSED');
      }
      if (bytesToHex(seal) !== pin) throw new VaultError('MESSAGE_REFUSED');
      const key = (k: string) => hexToBytes(k.toLowerCase());
      verified.set(dealId, {
        walletAddress: d.walletAddress,
        contractRoot: key(d.contractRoot),
        dealSeal: seal,
        payoutA: payout(d.payoutA),
        payoutB: payout(d.payoutB),
        exitAmountDrops,
        maxFeeDrops: MAX_FEE_DROPS,
        slotPubs: { A: key(d.xPubA), B: key(d.xPubB), LA: key(d.lawyerPubA), LB: key(d.lawyerPubB) },
      });
    },
    /** The vault's `deals` dependency: only a verified deal exists. */
    async get(dealId: string): Promise<SealedDeal> {
      const d = verified.get(dealId);
      if (!d) throw new VaultError('NOT_FOUND');
      return d;
    },
  };
}
