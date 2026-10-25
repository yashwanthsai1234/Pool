import { DealProgress } from '@legx/ui';
import type { ReactNode } from 'react';
import type { Deal, Who } from '../../lib/demo-deals.tsx';
import { pdfHref, useDealStages } from '../present/-stages.tsx';
import { Card, Lock, money, RidChip, StatusChip, when } from './-kit.tsx';

const names = (by: Who[]) => (by.length ? ` (${by.map((b) => b.name).join(', ')})` : '');
const passed = (f: NonNullable<Deal['gate']>['findings'][number]) => (f.ok ?? f.passed) !== false;

const Row = ({ k, children }: { k: string; children: ReactNode }) => (
  <div className="flex flex-col gap-0.5 py-1 sm:flex-row sm:gap-4">
    <dt className="w-44 shrink-0 font-semibold">{k}</dt>
    <dd className="min-w-0 break-all text-muted">{children}</dd>
  </div>
);
const Section = ({ title, children }: { title: string; children: ReactNode }) => (
  <Card label={title} className="p-5">
    <h3 className="mb-2 text-xl font-bold">{title}</h3>
    <dl>{children}</dl>
  </Card>
);

export function EscrowCard({ deal, large }: { deal: Deal; large?: boolean }) {
  const e = deal.escrow;
  return (
    <Card label="Escrow" className={large ? 'p-8' : undefined}>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <p className={`font-bold tabular-nums ${large ? 'text-7xl' : 'text-[40px] leading-none'}`}>
          {money(e.amountXrp)}
        </p>
        <span
          className={`inline-flex items-center gap-2 rounded-full border-2 border-line px-4 py-1 font-bold ${large ? 'text-3xl' : 'text-base'}`}
        >
          <Lock open={e.status === 'released'} className={large ? 'size-8' : 'size-5'} />
          Escrow: {e.status}
        </span>
      </div>
      <p className={`mt-4 ${large ? 'text-3xl leading-snug' : 'text-base'}`}>
        Keys {e.keys.done}/{e.keys.of}
        {names(e.keys.by)} · Passports {e.passports.done}/{e.passports.of}
        {names(e.passports.by)} · Approvals {e.approvals.done}/{e.approvals.of}
        {names(e.approvals.by)}
      </p>
    </Card>
  );
}

function Released({ deal }: { deal: Deal }) {
  const { escrow: e, contract: c } = deal;
  const txs = [
    ['Contract NFT mint', c.mintTx],
    ['Escrow funded', e.fundTx],
    ['Released', e.releaseTx],
    ['Wallet closed', e.closeTx],
  ] as const;
  const explorer = deal.ledger.explorerBase;
  const findings = deal.gate?.findings ?? [];
  return (
    <>
      <Card label="Released" className="border-pass bg-pass/10 text-center">
        <p className="text-[40px] font-bold leading-tight text-pass">
          Released: {money(deal.amountXrp)} paid to {deal.recipient.name}
        </p>
        <p className="mt-1 text-base text-muted">
          {deal.sender.name} to {deal.recipient.name} · {when(deal.releasedAt)}
        </p>
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Parties">
          <Row k="Sender">
            <RidChip name={deal.sender.name} rid={deal.sender.rid} fingerprint={deal.sender.fingerprint} />
          </Row>
          <Row k="Recipient">
            <RidChip name={deal.recipient.name} rid={deal.recipient.rid} fingerprint={deal.recipient.fingerprint} />
          </Row>
        </Section>
        <Section title="Escrow">
          <Row k="Amount">{money(e.amountXrp)}</Row>
          <Row k="Status">{e.status}</Row>
          <Row k="Wallet">{e.walletAddress}</Row>
          <Row k="Terms">{deal.terms}</Row>
        </Section>
        <Section title="Contract">
          <Row k="Document">
            <a className="text-primary underline" href={pdfHref(c.pdfUrl)} target="_blank" rel="noreferrer">
              PDF preview
            </a>
          </Row>
          <Row k="SHA-256">{c.sha256}</Row>
          <Row k="NFT">
            <span className="break-all">
              {c.nftId} owned by {c.nftOwner}
            </span>
          </Row>
        </Section>
        <Section title="Release signatures">
          {deal.releasedBy?.map((r) => (
            <Row key={r.rid} k={`Released by ${r.name}`}>
              signature {r.signatureFingerprint}
            </Row>
          ))}
        </Section>
        {deal.gate ? (
          <Card label="Release gate" className="p-5 lg:col-span-2">
            <h3 className="mb-2 text-xl font-bold">
              Release gate: {findings.filter(passed).length}/{findings.length} checks
            </h3>
            <ul className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm sm:grid-cols-3 lg:grid-cols-4">
              {findings.map((f, i) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: the 17 findings are a fixed ordered list
                <li key={i} className={passed(f) ? 'text-muted' : 'font-bold text-fail'}>
                  <span aria-hidden="true">{passed(f) ? '✓' : '✗'}</span> {f.code ?? `check ${i + 1}`}:{' '}
                  {passed(f) ? 'pass' : 'fail'}
                </li>
              ))}
            </ul>
          </Card>
        ) : null}
        <Section title="Transactions">
          {txs.map(([k, h]) =>
            h ? (
              <Row key={k} k={k}>
                {explorer ? (
                  <a className="text-primary underline" href={`${explorer}/${h}`} target="_blank" rel="noreferrer">
                    {h}
                  </a>
                ) : (
                  h
                )}
              </Row>
            ) : null,
          )}
        </Section>
        <Section title="Timestamps">
          <Row k="Created">{deal.createdAt}</Row>
          {deal.releasedAt ? <Row k="Released at">{deal.releasedAt}</Row> : null}
        </Section>
      </div>
    </>
  );
}

export function DealDetail({ deal: initial }: { deal: Deal }) {
  const live = useDealStages(initial.id, initial);
  const deal = live.deal ?? initial;
  const released = deal.status === 'released';
  return (
    <article aria-label="Deal detail" className="flex flex-col gap-4">
      <header className="flex flex-wrap items-center gap-3">
        <h2 className="text-[28px] font-bold leading-tight">
          {deal.sender.name} to {deal.recipient.name}: {deal.amountXrp} XRP
        </h2>
        <StatusChip status={deal.status} />
      </header>
      {released ? (
        <Released deal={deal} />
      ) : (
        <>
          <EscrowCard deal={deal} />
          <Card label="Progress">
            <DealProgress stages={deal.stages} />
          </Card>
          <Card label="Timeline" className="p-5">
            <h3 className="mb-2 text-xl font-bold">Timeline</h3>
            <ol className="grid gap-x-8 gap-y-1 text-base sm:grid-cols-2">
              {deal.stages.map((s) => (
                <li key={s.n} data-timeline={s.status} className={s.status === 'done' ? '' : 'text-muted'}>
                  <span aria-hidden="true">{s.status === 'done' ? '✓' : s.status === 'failed' ? '✗' : '○'}</span>{' '}
                  {s.name}
                  {s.at ? ` · ${when(s.at)}` : ''}
                </li>
              ))}
            </ol>
          </Card>
        </>
      )}
      <details>
        <summary className="cursor-pointer font-semibold">All metadata</summary>
        <pre className="overflow-x-auto text-xs">{JSON.stringify(deal, null, 2)}</pre>
      </details>
    </article>
  );
}
