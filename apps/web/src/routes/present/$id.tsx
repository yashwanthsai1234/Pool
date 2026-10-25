import { DealProgress } from '@legx/ui';
import { createFileRoute } from '@tanstack/react-router';
import { DemoLabel } from '../../lib/demo-ui.tsx';
import { EscrowCard } from '../deals/-detail.tsx';
import { BigChip } from '../deals/-kit.tsx';
import { useDealStages } from './-stages.tsx';

function Present() {
  const { id } = Route.useParams();
  const { deal, stages, error } = useDealStages(id);
  if (error)
    return (
      <main className="min-h-dvh bg-bg p-8 text-fg">
        <h1 className="text-5xl font-bold">Deal not found</h1>
      </main>
    );
  if (!deal || !stages)
    return (
      <main className="min-h-dvh bg-bg p-8 text-fg">
        <h1 className="text-5xl font-bold">Loading</h1>
      </main>
    );
  const cur = stages.find((s) => s.status !== 'done');
  const turn =
    deal.status === 'released' ? 'Released: the escrow has paid out' : cur ? `Now: ${cur.name}` : 'All steps done';
  return (
    <main data-theme="projector" className="flex min-h-dvh flex-col justify-between gap-8 bg-bg p-12 text-fg">
      <header className="flex flex-wrap items-center justify-between gap-6">
        <h1 className="text-7xl font-bold leading-tight">
          {deal.sender.name} → {deal.recipient.name} · {deal.amountXrp} XRP
        </h1>
        <BigChip status={deal.status} />
      </header>
      <p role="status" className="rounded-2xl border-2 border-primary px-8 py-4 text-4xl font-bold text-primary">
        {turn}
      </p>
      <DealProgress stages={stages} large />
      <EscrowCard deal={deal} large />
      <DemoLabel />
    </main>
  );
}

export const Route = createFileRoute('/present/$id')({ component: Present });
