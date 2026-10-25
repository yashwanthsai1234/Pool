// My records (DESIGN 8.10): the phone re-runs the signature, chain and ledger checks itself with `verifyClientRecords`
// and shows its own result; a difference from the coordinator's checks is shown too (P4.3-06).

import { verifyClientRecords } from '@legx/core/clientRecords';
import { entryLink } from '@legx/core/evidence';
import { fromBase64Strict } from '@legx/core/pq';
import { EmptyState, StatusBadge } from '@legx/ui';
import { useQuery } from '@tanstack/react-query';
import { usePartyStrict } from './-context.tsx';
import { gate } from './-gate.tsx';

const EXPLORER: Record<string, string> = { testnet: 'https://testnet.xrpl.org', devnet: 'https://devnet.xrpl.org' };

export function RecordsScreen() {
  const s = usePartyStrict();
  const q = useQuery({
    queryKey: ['party', s.dealId, 'records'],
    queryFn: async () => {
      const side = s.role === 'alice' ? 'A' : 'B';
      const [{ records }, deal] = await Promise.all([
        s.api.records.list({ dealId: s.dealId, side }),
        s.api.deals.get({ dealId: s.dealId }),
      ]);
      const entries = records.map((r) => ({
        envelopeBytes: fromBase64Strict(r.envelope) ?? new Uint8Array(),
        leafHash: r.leafHash,
      }));
      await s.prepareEnvelopes?.(entries);
      const mine = verifyClientRecords(entries, s.checkEnvelope, { ledgerIndexOf: s.ledgerIndexOf });
      return records.map((r, i) => {
        const m = mine[i];
        const ledger = (entryLink(entries[i] as never)?.predicate.ledger ?? {}) as { tx_hash?: string };
        const differs =
          m !== undefined &&
          (m.signature !== r.checks.signature || m.chain !== r.checks.chain || m.ledger !== r.checks.ledger);
        return { seq: r.seq, mine: m, differs, txHash: ledger.tx_hash, explorer: EXPLORER[deal.network] };
      });
    },
  });
  const waiting = gate(q);
  if (waiting) return waiting;
  if (!q.data?.length) return <EmptyState title="No records yet">Records appear here as your deal moves.</EmptyState>;
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="records-title">
      <h1 id="records-title" className="text-2xl font-bold">
        My records
      </h1>
      <ol className="flex flex-col gap-3">
        {q.data.map((r) => (
          <li key={r.seq} data-testid={`record-${r.seq}`} className="flex flex-col gap-1 border-b border-muted pb-2">
            <strong>Record {r.seq}</strong>
            <span>
              Signature <StatusBadge status={r.mine?.signature ? 'pass' : 'fail'} />
            </span>
            <span>
              Chain <StatusBadge status={r.mine?.chain ? 'pass' : 'fail'} />
            </span>
            <span>
              Ledger{' '}
              <StatusBadge
                status={r.mine?.ledger === 'linked' ? 'pass' : r.mine?.ledger === 'none' ? 'pending' : 'fail'}
              />
              {r.txHash && r.explorer ? (
                <>
                  {' '}
                  <a className="underline" href={`${r.explorer}/transactions/${r.txHash}`}>
                    View on the ledger
                  </a>
                </>
              ) : null}
            </span>
            {r.differs ? (
              <span role="alert">Your phone's checks differ from the coordinator's. Trust your phone's.</span>
            ) : null}
          </li>
        ))}
      </ol>
    </section>
  );
}
