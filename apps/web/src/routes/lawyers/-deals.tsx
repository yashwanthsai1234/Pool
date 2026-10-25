// The lawyer console's deal list (I-W-10, OD-35). Enrollment keys stay per deal and role (4.9), so there is no key that links one
// lawyer's deals together: the list comes from the vault's own metadata, and each deal is asked about with its own key.
import { EmptyState, StatusBadge } from '@legx/ui';
import type { VaultFrame } from '@legx/vault-host/app';
import type { ApiClient } from '../../lib/api.ts';

export type DealRow = { dealId: string; role: string | undefined; state: string } | { dealId: string; error: string };

/** One `deals.mine` per deal the vault holds a key for, each signed with that deal's key. A failure stays visible. */
export async function listLawyerDeals(
  vault: Pick<VaultFrame['vault'], 'deals'>,
  apiFor: (dealId: string) => ApiClient,
): Promise<DealRow[]> {
  const ids = await vault.deals();
  return Promise.all(
    ids.map(async (dealId): Promise<DealRow> => {
      try {
        const { deals } = await apiFor(dealId).deals.mine({});
        const mine = deals.find((d) => d.dealId === dealId);
        return mine ? { dealId, role: mine.role, state: mine.state } : { dealId, error: 'not listed by the server' };
      } catch {
        return { dealId, error: 'the server refused this key' };
      }
    }),
  );
}

export function LawyerDeals({ rows }: { rows: DealRow[] }) {
  if (rows.length === 0)
    return (
      <EmptyState title="No deals assigned">
        Deals your firm is a party to will be listed here, with the step that needs your signature.
      </EmptyState>
    );
  return (
    <section className="mx-auto flex max-w-2xl flex-col gap-3 p-4" aria-labelledby="deals-title">
      <h1 id="deals-title" className="text-2xl font-bold">
        Your deals
      </h1>
      <ul className="flex flex-col gap-2">
        {rows.map((r) => (
          <li
            key={r.dealId}
            data-testid={`deal-${r.dealId}`}
            className="flex flex-wrap items-center gap-2 border-b border-muted pb-2"
          >
            <span className="break-all">{r.dealId}</span>
            {'error' in r ? (
              <>
                <StatusBadge status="fail" /> <span>This deal could not be read: {r.error}</span>
              </>
            ) : (
              <>
                <StatusBadge status="pass" />{' '}
                <span>
                  {r.role ?? 'lawyer'}: {r.state}
                </span>
                <a className="underline" href={`/lawyers?deal=${r.dealId}&role=${r.role === 'lawyerB' ? 'LB' : 'LA'}`}>
                  Open console
                </a>
              </>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
