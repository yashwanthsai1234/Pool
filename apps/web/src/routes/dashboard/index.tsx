import { EmptyState, StatusBadge } from '@legx/ui';
import { createFileRoute } from '@tanstack/react-router';
import { lazy, Suspense } from 'react';
import { observerFeed } from '../../lib/observer.ts';
import { httpAttackClient } from './-attack-api.ts';
import { NETWORKS, type Network } from './-explorer.ts';

const attackClient = httpAttackClient();
const feed = observerFeed(import.meta.env);
// The dashboard pulls in the contract schemas and every panel: keep it out of the entry chunk (the phone budget).
const Dashboard = lazy(() => import('./-dashboard.tsx').then((m) => ({ default: m.Dashboard })));

// `/dashboard?deal=<deal id>&network=testnet`. No deal id: the room sees the waiting screen.
export const Route = createFileRoute('/dashboard/')({
  validateSearch: (s: Record<string, unknown>): { deal?: string; network: Network } => ({
    ...(typeof s.deal === 'string' && s.deal !== '' ? { deal: s.deal } : {}),
    network: NETWORKS.find((n) => n === s.network) ?? 'testnet',
  }),
  component: function DashboardRoute() {
    const { deal, network } = Route.useSearch();
    if (deal)
      return (
        <Suspense fallback={null}>
          <Dashboard dealId={deal} network={network} attackClient={attackClient} {...(feed ? { feed } : {})} />
        </Suspense>
      );
    return (
      <main data-theme="projector" className="flex min-h-dvh flex-col items-center justify-center bg-bg text-fg">
        <EmptyState title="Waiting for the first deal">The live deal state is shown here for the room.</EmptyState>
        <StatusBadge status="pending" className="text-xl" />
      </main>
    );
  },
});
