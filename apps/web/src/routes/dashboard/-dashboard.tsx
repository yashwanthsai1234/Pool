// The projector dashboard (IMPLEMENTATION 4.5): 1920 x 1080, dark. It reads the live feed and shows the deal; attack mode
// is the only thing that posts, and only when the server is in the demo profile.
import './-jitless.ts';
import { skipToken, useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { type LiveFeedOptions, type LiveRows, liveRowsKey, useLiveDeal } from '../../lib/live.ts';
import type { AttackClient, AttackResult } from './-attack-api.ts';
import { AttackPanel } from './-attack-panel.tsx';
import type { Network } from './-explorer.ts';
import { buildView } from './-model.ts';
import {
  DealStatePanel,
  EvidenceLog,
  FrostProgress,
  ItemList,
  LedgerLog,
  ShippingTimeline,
  WalkthroughTimeline,
} from './-panels.tsx';

export function Dashboard({
  dealId,
  network,
  attackClient,
  feed,
}: {
  dealId: string;
  network: Network;
  attackClient: AttackClient;
  /** The observer key's signed upgrade (OD-31). Keep it referentially stable. */
  feed?: Pick<LiveFeedOptions, 'auth' | 'onLedger'>;
}) {
  const live = useLiveDeal(dealId, feed);
  const rows = useQuery<LiveRows>({ queryKey: liveRowsKey(dealId), queryFn: skipToken });
  const [attack, setAttack] = useState<AttackResult | undefined>();
  const view = useMemo(() => buildView(rows.data?.rows ?? [], live.state, attack), [rows.data, live.state, attack]);
  return (
    <main data-theme="projector" data-testid="dashboard" className="min-h-dvh w-full bg-bg p-4 text-fg">
      <header className="mb-3 flex items-center justify-between">
        <h1 className="text-3xl font-bold">Deal dashboard</h1>
        <p className="flex items-center gap-4 text-xl">
          <span className="rounded border-2 border-fail px-3 py-0.5 font-bold text-fail">DEMO</span>
          <span>Network: {network}</span>
          <span role="status" aria-label="Live feed">
            Feed: {live.status}
          </span>
        </p>
      </header>
      <div className="grid grid-cols-[0.85fr_2fr_0.95fr_0.95fr] items-start gap-4">
        <div className="grid gap-4">
          <DealStatePanel state={view.state} />
          <FrostProgress frost={view.frost} />
          <ShippingTimeline steps={view.shipping} />
          <WalkthroughTimeline steps={view.walkthrough} />
        </div>
        <div className="grid gap-4">
          <ItemList title="Lock checker" items={view.lock} columns={2} />
          <ItemList title="Release gate" items={view.gate} columns={2} />
        </div>
        <div className="grid gap-4">
          <LedgerLog entries={view.ledger} network={network} />
          <EvidenceLog evidence={view.evidence} network={network} />
        </div>
        <AttackPanel client={attackClient} network={network} onResult={setAttack} />
      </div>
    </main>
  );
}
