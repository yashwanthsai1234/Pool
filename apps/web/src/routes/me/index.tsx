// /me (phone): my deals, whose turn it is, and ONE primary action for my own next step (build/UX.md, PRODUCT_DEMO 5).
// Live dots come from useDealStages (polling; the unsigned demo pages never open the signed /ws).
import { DealProgress } from '@legx/ui';
import { skipToken, useMutation, useQueries, useQueryClient } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { useEffect } from 'react';
import { approveStage, type Deal, dealKey, savedRid, useDeals, useParticipants } from '../../lib/demo-deals.tsx';
import {
  Card,
  type ChipStatus,
  EmptyState,
  Page,
  PrimaryAction,
  RidChip,
  Skeleton,
  StatusChip,
  Toast,
  TurnBanner,
  useToast,
  WELCOME_KEY,
} from '../../lib/demo-ui.tsx';
import { useDealStages } from '../present/-stages.tsx';

const LABEL: Record<number, (d: Deal) => string> = {
  2: () => 'Verify my passport',
  3: () => 'Verify my passport',
  4: () => 'Set up my keys',
  5: () => 'Set up my keys',
  6: (d) => `Fund escrow: ${d.amountXrp} XRP`,
  8: () => 'Sign shipment',
  9: () => 'Sign receipt',
  10: () => 'Approve release',
  11: () => 'Approve release',
};
const DONE: Record<number, (d: Deal) => string> = {
  2: () => 'Passport verified',
  3: () => 'Passport verified',
  4: () => 'Keys set up',
  5: () => 'Keys set up',
  6: (d) => `Escrow funded: ${d.amountXrp} XRP locked`,
  8: () => 'Shipment signed',
  9: () => 'Receipt signed',
  10: () => 'Release approved',
  11: () => 'Release approved',
};
const WAIT: Record<number, string> = {
  2: 'verify their passport',
  3: 'verify their passport',
  4: 'set up their keys',
  5: 'set up their keys',
  6: 'fund the escrow',
  8: 'sign the shipment',
  9: 'sign the receipt',
  10: 'approve the release',
  11: 'approve the release',
};

/** Human words for a refused approval; the server's own text stays visible in small print. */
const humanError = (e: Error) => {
  const code = Number(e.message.slice(0, 3));
  const what =
    code === 403
      ? 'That step is not yours. Check whose turn it is.'
      : code === 409
        ? 'That step is out of order: an earlier step must finish first.'
        : 'The step did not go through. Try again in a moment.';
  return `${what} (server: ${e.message.slice(0, 120)})`;
};

type Role = 'sender' | 'recipient';
const view = (deal: Deal, rid: string) => {
  const mine: Role = deal.sender.rid === rid ? 'sender' : 'recipient';
  const other = mine === 'sender' ? deal.recipient : deal.sender;
  const next = deal.stages.find((s) => s.status !== 'done');
  const turn: 'you' | 'wait' | 'auto' | 'done' = !next
    ? 'done'
    : next.actor === mine
      ? 'you'
      : next.actor === 'auto'
        ? 'auto'
        : 'wait';
  return { mine, other, next, turn };
};
const chip = (d: Deal): ChipStatus =>
  d.status === 'released' || d.escrow.status === 'released'
    ? 'released'
    : d.stages.some((s) => s.status === 'failed')
      ? 'failed'
      : d.escrow.status === 'locked'
        ? 'locked'
        : 'pending';

function DealCard({ deal: listed, rid, focus }: { deal: Deal; rid: string; focus: boolean }) {
  const live = useDealStages(listed.id, listed).deal ?? listed;
  const { mine, other, next, turn } = view(live, rid);
  return (
    <Card
      label={`Deal ${live.sender.name} to ${live.recipient.name}`}
      className={focus ? 'border-2 border-primary' : undefined}
    >
      <div className="flex items-start justify-between gap-3">
        <h2 className="text-[20px] font-bold leading-tight">
          {live.amountXrp} XRP: {live.sender.name} to {live.recipient.name}
        </h2>
        <StatusChip status={chip(live)} />
      </div>
      <p className="text-sm text-muted">
        You {mine === 'sender' ? 'pay' : 'are paid'} · with <span className="font-semibold text-fg">{other.name}</span>
      </p>
      <DealProgress stages={live.stages} compact />
      <p
        className={
          turn === 'you' ? 'font-bold text-primary' : turn === 'done' ? 'font-bold text-pass' : 'text-base text-muted'
        }
      >
        {turn === 'done'
          ? 'Released'
          : turn === 'you'
            ? `Your turn: ${LABEL[next?.n ?? 0]?.(live) ?? next?.name}`
            : turn === 'auto'
              ? 'Running automatically'
              : `Waiting for ${other.name}`}
      </p>
    </Card>
  );
}

function Me() {
  const rid = savedRid();
  const qc = useQueryClient();
  const people = useParticipants();
  const deals = useDeals();
  const { toast, show, clear } = useToast();
  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(WELCOME_KEY);
      if (!raw) return;
      sessionStorage.removeItem(WELCOME_KEY);
      const w = JSON.parse(raw) as { name: string; rid: string };
      show({ tone: 'success', message: `You are registered as ${w.name}` });
    } catch {
      // no greeting
    }
  }, [show]);
  const listed = deals.data?.filter((d) => d.sender.rid === rid || d.recipient.rid === rid) ?? [];
  // The cards poll each deal (useDealStages); this reads the same cache so the banner and button follow the dots.
  const cached = useQueries({ queries: listed.map((d) => ({ queryKey: dealKey(d.id), queryFn: skipToken })) });
  const mine = listed.map((d, i) => (cached[i]?.data as Deal | undefined) ?? d);
  const me = people.data?.find((p) => p.rid === rid);
  const views = rid ? mine.map((d) => ({ d, ...view(d, rid) })) : [];
  const focus = views.find((v) => v.turn === 'you') ?? views.find((v) => v.turn !== 'done');

  const approve = useMutation({
    mutationFn: ({ deal, stage }: { deal: Deal; stage: number }) => approveStage(deal.id, rid ?? '', stage),
    onSuccess: (updated, { deal, stage }) => {
      qc.setQueryData(dealKey(deal.id), updated);
      void qc.invalidateQueries({ queryKey: ['demo'] });
      const d = updated?.stages ? updated : deal;
      const hash =
        (stage === 6 ? d.escrow?.fundTx : undefined) ?? d.stages?.find((s) => s.n === stage)?.txHashes?.at(-1);
      show({
        tone: 'success',
        message: DONE[stage]?.(d) ?? 'Done',
        ...(hash ? { tx: { hash, explorerBase: d.ledger?.explorerBase } } : {}),
      });
    },
    onError: (e) => show({ tone: 'error', message: humanError(e) }),
  });

  if (!rid)
    return (
      <Page title="My deals">
        <EmptyState
          title="Not registered"
          action={
            <a
              className="inline-flex min-h-12 items-center rounded-xl bg-primary px-6 font-semibold text-primary-fg"
              href="/register"
            >
              Register
            </a>
          }
        >
          Register on this device first: it takes one name.
        </EmptyState>
      </Page>
    );

  const myStep = focus?.turn === 'you' ? focus : undefined;
  const banner = !focus ? (
    mine.length ? (
      <TurnBanner turn="done">All done: funds released</TurnBanner>
    ) : null
  ) : focus.turn === 'you' ? (
    <TurnBanner turn="you">Your turn: {LABEL[focus.next?.n ?? 0]?.(focus.d) ?? focus.next?.name}</TurnBanner>
  ) : focus.turn === 'auto' ? (
    <TurnBanner turn="auto">Working: {focus.next?.name}</TurnBanner>
  ) : (
    <TurnBanner turn="wait">
      Waiting for {focus.other.name} to {WAIT[focus.next?.n ?? 0] ?? focus.next?.name}
    </TurnBanner>
  );

  return (
    <Page
      title={me ? `Hello ${me.name}` : 'My deals'}
      subtitle={me ? <RidChip rid={me.rid} fingerprint={me.fingerprint} /> : null}
      action={
        myStep?.next ? (
          <PrimaryAction
            pending={approve.isPending}
            onClick={() => myStep.next && approve.mutate({ deal: myStep.d, stage: myStep.next.n })}
          >
            {LABEL[myStep.next.n]?.(myStep.d) ?? myStep.next.name}
          </PrimaryAction>
        ) : undefined
      }
    >
      {toast ? <Toast toast={toast} onClose={clear} /> : null}
      {banner}
      {deals.isPending ? (
        <>
          <Skeleton />
          <Skeleton />
        </>
      ) : mine.length === 0 ? (
        <EmptyState title="No deals yet">The deal page creates one: ask the person at the laptop.</EmptyState>
      ) : (
        views.map((v) => <DealCard key={v.d.id} deal={v.d} rid={rid} focus={v === focus && v.turn === 'you'} />)
      )}
    </Page>
  );
}

export const Route = createFileRoute('/me/')({ component: Me });
