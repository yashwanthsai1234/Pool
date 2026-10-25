// Home (the deal checklist), Lock money (Alice only) and Accept my badge (step 5f): each reads one query and has one action.
import { DealState } from '@legx/contracts/values';
import { Button, EmptyState, StatusBadge } from '@legx/ui';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { usePartyStrict } from './-context.tsx';
import { gate } from './-gate.tsx';

export type Screen = 'home' | 'lock' | 'badge' | 'presence' | 'approve' | 'records';
const ORDER = DealState.options;
const reached = (state: string, at: (typeof ORDER)[number]) => ORDER.indexOf(state as never) >= ORDER.indexOf(at);

const useDeal = () => {
  const s = usePartyStrict();
  return useQuery({ queryKey: ['party', s.dealId, 'view'], queryFn: () => s.api.deals.get({ dealId: s.dealId }) });
};

export function HomeScreen({ open, makeKey }: { open: (screen: Screen) => void; makeKey: () => void }) {
  const s = usePartyStrict();
  const deal = useDeal();
  const waiting = gate(deal);
  if (waiting) return waiting;
  if (!deal.data) return <EmptyState title="Deal not found">Open the link your lawyer sent you.</EmptyState>;
  const st = deal.data.state;
  const steps: { screen: Screen | 'key'; label: string; done: boolean; hidden?: boolean }[] = [
    { screen: 'key', label: 'Make my key', done: reached(st, 'KEYS_READY') },
    { screen: 'lock', label: 'Lock money', done: reached(st, 'WALLET_LOCKED'), hidden: s.role !== 'alice' },
    { screen: 'presence', label: 'Passport presence', done: reached(st, 'VERIFIED') },
    { screen: 'badge', label: 'Accept my badge', done: Boolean(deal.data.nftTokenId) && reached(st, 'FUNDED') },
    { screen: 'approve', label: 'Approve payment', done: reached(st, 'PAID_OUT') },
    { screen: 'records', label: 'My records', done: false },
  ];
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="home-title">
      <h1 id="home-title" className="text-2xl font-bold">
        {s.role === 'alice' ? 'Alice' : 'Bob'}: your deal
      </h1>
      <p>Deal state: {st}</p>
      <ul className="flex flex-col gap-3">
        {steps
          .filter((x) => !x.hidden)
          .map((x) => (
            <li key={x.screen} className="flex items-center justify-between gap-2">
              <button
                type="button"
                className="underline"
                onClick={() => (x.screen === 'key' ? makeKey() : open(x.screen))}
              >
                {x.label}
              </button>
              <StatusBadge status={x.done ? 'pass' : 'pending'} />
            </li>
          ))}
      </ul>
    </section>
  );
}

export function LockScreen() {
  const s = usePartyStrict();
  const deal = useDeal();
  const qc = useQueryClient();
  const lock = useMutation({
    mutationFn: async () => {
      if (!s.createShellKey) throw new Error('NOT_AVAILABLE');
      return s.api.deals.setWallet({ dealId: s.dealId, walletAddress: await s.createShellKey() });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['party', s.dealId] }),
  });
  const [steps, setSteps] = useState<{ id: string; status: string; detail?: string }[]>([]);
  const setup = useMutation({
    mutationFn: async () => {
      setSteps([]);
      await s.runLockSetup?.((st) => setSteps((xs) => [...xs.filter((x) => x.id !== st.id), st]));
    },
  });
  if (s.role !== 'alice') return <EmptyState title="Only Alice locks money">Bob does not fund the deal.</EmptyState>;
  const waiting = gate(deal);
  if (waiting || !deal.data) return waiting;
  const d = deal.data;
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="lock-title">
      <h1 id="lock-title" className="text-2xl font-bold">
        Lock money
      </h1>
      <p>Amount: {(Number(BigInt(d.amountDrops)) / 1e6).toLocaleString('en-US')} XRP</p>
      <p className="break-all">Deal wallet: {d.walletAddress ?? 'not made yet'}</p>
      {d.escrow ? <p>Escrow of {d.escrow.amount_drops} drops is held until the deal is released or expires.</p> : null}
      {d.walletAddress ? null : !s.createShellKey ? (
        <p role="note">This device cannot make the deal wallet yet. Your lawyer will tell you when it can.</p>
      ) : (
        <Button onClick={() => lock.mutate()} disabled={lock.isPending}>
          Make the deal wallet
        </Button>
      )}
      {d.walletAddress && s.runLockSetup ? (
        <>
          <Button onClick={() => setup.mutate()} disabled={setup.isPending || setup.isSuccess}>
            Set up the deal wallet
          </Button>
          <ul aria-label="Setup steps">
            {steps.map((x) => (
              <li key={x.id}>
                <StatusBadge status={x.status === 'done' ? 'pass' : x.status === 'failed' ? 'fail' : 'pending'} />{' '}
                {x.id}
                {x.detail ? `: ${x.detail}` : ''}
              </li>
            ))}
          </ul>
          {setup.isSuccess ? <p role="status">The deal wallet is set up. The setup key is retired.</p> : null}
          {setup.isError ? <p role="alert">Stopped: nothing further was signed.</p> : null}
        </>
      ) : null}
      {lock.isError ? <p role="alert">Nothing was sent: {(lock.error as Error).message}</p> : null}
    </section>
  );
}

export function BadgeScreen() {
  const s = usePartyStrict();
  const deal = useDeal();
  const accept = useMutation({
    mutationFn: async () => {
      if (!s.acceptBadge) throw new Error('NOT_AVAILABLE');
      await s.acceptBadge();
    },
  });
  const waiting = gate(deal);
  if (waiting || !deal.data) return waiting;
  if (!deal.data.nftTokenId) return <EmptyState title="No badge yet">Your lawyer has not made your badge.</EmptyState>;
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="badge-title">
      <h1 id="badge-title" className="text-2xl font-bold">
        Accept my badge
      </h1>
      <p className="break-all">Badge {deal.data.nftTokenId}</p>
      {s.acceptBadge ? (
        <Button onClick={() => accept.mutate()} disabled={accept.isPending || accept.isSuccess}>
          Accept badge
        </Button>
      ) : (
        <p role="note">This device cannot accept the badge yet. Your lawyer will tell you when it can.</p>
      )}
      {accept.isSuccess ? <p role="status">Badge accepted.</p> : null}
      {accept.isError ? <p role="alert">Nothing was sent: {(accept.error as Error).message}</p> : null}
    </section>
  );
}
