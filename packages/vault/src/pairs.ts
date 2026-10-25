// The registered key pair id of each deal's enrollment keys, and the list of deals a namespace holds keys for (OD-35). Enrollment
// keys stay per deal and role (4.9), so no long-lived key links one lawyer's deals; the vault's own metadata is the list.
import { DealId } from '@legx/contracts/values';
import { VaultError } from './errors.ts';
import type { PartyRole } from './rules.ts';
import { Store } from './store.ts';

type Row = { id: string; role: PartyRole; pairId: string };

export function pairIds(opts: { role: PartyRole; dbName?: string }) {
  const store = new Store(opts.dbName ?? 'legx-vault');
  const idOf = (dealId: string) => {
    if (!DealId.safeParse(dealId).success) throw new VaultError('INPUT_INVALID');
    return `${dealId}:${opts.role}:pair`;
  };
  return {
    async set(dealId: string, pairId: string): Promise<void> {
      await store.put('enrollment', { id: idOf(dealId), role: opts.role, pairId } satisfies Row);
    },
    async get(dealId: string): Promise<string | undefined> {
      return (await store.get<Row>('enrollment', idOf(dealId)))?.pairId;
    },
    /** Every deal with an enrollment key in this role's namespace, once each. */
    async deals(): Promise<string[]> {
      const rows = await store.byRole<{ id: string; role: string }>('enrollment', opts.role);
      return [...new Set(rows.filter((r) => r.id.endsWith(':enrollment')).map((r) => r.id.split(':')[0] as string))];
    },
  };
}
