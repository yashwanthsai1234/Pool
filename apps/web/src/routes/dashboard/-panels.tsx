import { DealState } from '@legx/contracts/values';
import { cn, StatusBadge } from '@legx/ui';
import type { ReactNode } from 'react';
import { explorerUrl, type Network } from './-explorer.ts';
import type { EvidenceView, FrostEntry, Item, LedgerEntry } from './-model.ts';
import './-dashboard.css';

export function Panel({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  return (
    <section aria-label={title} className={cn('rounded-lg border-2 border-line p-4', className)}>
      <h2 className="mb-3 text-2xl font-bold">{title}</h2>
      {children}
    </section>
  );
}

const short = (s: string, n = 8) => (s.length > 2 * n + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s);

export function DealStatePanel({ state }: { state: string | undefined }) {
  const at = DealState.options.indexOf(state as never);
  return (
    <Panel title="Deal state">
      <ol className="grid gap-0.5 text-lg">
        {DealState.options.map((s, i) => (
          <li
            key={s}
            aria-current={i === at ? 'step' : undefined}
            className={cn(
              'rounded px-2 py-0.5',
              i === at ? 'legx-flash bg-primary font-bold text-primary-fg' : i < at ? 'text-fg' : 'text-muted',
            )}
          >
            {s}
          </li>
        ))}
      </ol>
    </Panel>
  );
}

export function ItemList({ title, items, columns }: { title: string; items: readonly Item[]; columns: 1 | 2 }) {
  const passed = items.filter((i) => i.status === 'pass').length;
  return (
    <Panel title={title}>
      <p className="mb-2 text-lg text-muted" data-testid={`${title}-count`}>
        {passed} of {items.length} pass
      </p>
      <ul className={cn('grid gap-x-4 gap-y-0.5 text-base', columns === 2 ? 'grid-cols-2' : 'grid-cols-1')}>
        {items.map((i) => (
          <li
            key={i.code}
            data-status={i.status}
            data-code={i.code}
            className="flex items-center justify-between gap-2"
          >
            <span className="truncate font-mono" title={i.detail ? `${i.code}: ${i.detail}` : i.code}>
              {i.code}
            </span>
            <StatusBadge
              status={i.status}
              className={cn('text-sm', i.status === 'pass' && 'legx-flash rounded px-1')}
            />
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export function LedgerLog({ entries, network }: { entries: readonly LedgerEntry[]; network: Network }) {
  return (
    <Panel title="Ledger log">
      {entries.length === 0 ? (
        <p className="text-lg text-muted">No validated transaction yet.</p>
      ) : (
        <ol className="grid gap-2 text-lg">
          {entries.slice(-9).map((e) => {
            const url = explorerUrl(network, 'tx', e.txHash);
            return (
              <li key={e.key} className="legx-flash rounded px-2 py-1">
                <div className="flex justify-between gap-2">
                  <span className="font-bold">{e.label}</span>
                  <span className="text-muted">ledger {e.ledgerIndex}</span>
                </div>
                {url ? (
                  <a href={url} target="_blank" rel="noreferrer" className="font-mono text-primary underline">
                    {short(e.txHash)}
                  </a>
                ) : (
                  <span className="font-mono">{short(e.txHash)}</span>
                )}
              </li>
            );
          })}
        </ol>
      )}
      <p className="mt-3 text-base text-muted">
        {network === 'standalone'
          ? 'Local ledger: no public explorer.'
          : `Network: ${network}. Links open the public explorer.`}
      </p>
    </Panel>
  );
}

export function EvidenceLog({ evidence, network }: { evidence: EvidenceView; network: Network }) {
  const cp = evidence.checkpoint;
  const anchor = cp ? explorerUrl(network, 'tx', cp.anchorTx) : undefined;
  return (
    <Panel title="Evidence log">
      <p className="text-lg">
        Chain:{' '}
        <strong data-testid="chain-status" className={evidence.chain === 'broken' ? 'text-fail' : undefined}>
          {evidence.chain === 'empty' ? 'no events yet' : evidence.chain === 'intact' ? 'intact, gap-free' : 'BROKEN'}
        </strong>{' '}
        <span className="text-muted">({evidence.events.length} events)</span>
      </p>
      <p className="text-lg">
        Merkle root:{' '}
        <span data-testid="merkle-root" className="font-mono">
          {cp ? short(cp.root) : 'not anchored yet'}
        </span>
      </p>
      {cp ? (
        <p className="text-base text-muted">
          tree size {cp.treeSize}, anchored in ledger {cp.anchorLedger}{' '}
          {anchor ? (
            <a href={anchor} target="_blank" rel="noreferrer" className="font-mono text-primary underline">
              {short(cp.anchorTx, 6)}
            </a>
          ) : null}
        </p>
      ) : null}
      <ol className="mt-2 grid gap-0.5 text-base">
        {evidence.events.slice(-6).map((e) => (
          <li key={e.seq} className="flex gap-3">
            <span className="w-8 text-right font-mono text-muted">{e.seq}</span>
            <span className="font-mono">{e.kind}</span>
          </li>
        ))}
      </ol>
    </Panel>
  );
}

export function FrostProgress({ frost }: { frost: readonly FrostEntry[] }) {
  return (
    <Panel title="FROST signing">
      <ul className="grid gap-1 text-lg">
        {frost.map((f) => (
          <li key={f.slot} data-slot={f.slot} className="flex items-center justify-between gap-2">
            <span className="font-bold">Slot {f.slot}</span>
            {f.pair ? (
              <span>
                signed by <span className="font-mono">{f.pair.map((k) => short(k, 5)).join(' + ')}</span>
              </span>
            ) : (
              <span className="text-muted">waiting</span>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  );
}
