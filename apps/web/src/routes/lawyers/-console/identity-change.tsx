// P4.8-21: the console's view of a mid-deal identity change (DESIGN 6.10 "Changes in mid-deal"). A renewed passport, a changed
// identifier derivation or a switch to the chip path each need a new commitment in the seal, so a 4-of-4 seal update signed by
// every slot. A slot that refuses leaves the deal stalled at release (O9): that is shown and recorded once.
// Source: DESIGN.md 6.10; packages/core/src/zkIdentity.ts `identityChangePlan`, `identityChangeOutcome`
import type { PublicDealData } from '@legx/contracts/deal';
import type { Method } from '@legx/core/attest';
import { identityChangeOutcome, identityChangePlan } from '@legx/core/zkIdentity';
import { StatusBadge } from '@legx/ui';
import { useEffect, useMemo, useRef } from 'react';

type Slot = 'A' | 'LA' | 'B' | 'LB';
export type SlotResponses = Partial<Record<Slot, 'signed' | 'refused'>>;
export type ChangeOutcome = ReturnType<typeof identityChangeOutcome>;

const NAME: Record<Slot, string> = { A: 'Alice', LA: 'Lawyer A', B: 'Bob', LB: 'Lawyer B' };

export function IdentityChangePanel(p: {
  deal: PublicDealData;
  side: 'A' | 'B';
  next: { method: Method; commitment: string };
  responses: SlotResponses;
  /** Writes the refusal to the evidence log. Called once per refusal outcome. */
  record: (outcome: Extract<ChangeOutcome, { state: 'refused' }>) => Promise<void>;
}) {
  const plan = useMemo(() => {
    try {
      return identityChangePlan(p.deal, p.side, p.next);
    } catch (e) {
      return e instanceof Error ? e : new Error(String(e));
    }
  }, [p.deal, p.side, p.next]);
  const outcome = identityChangeOutcome(p.responses);
  const recorded = useRef(false);
  const { record } = p;
  useEffect(() => {
    if (outcome.state === 'refused' && !recorded.current) {
      recorded.current = true;
      void record(outcome);
    }
  }, [outcome, record]);

  if (plan instanceof Error)
    return (
      <section aria-labelledby="idc-title" className="flex flex-col gap-2">
        <h2 id="idc-title">Identity method change</h2>
        <p role="alert">This change is not allowed by the sealed policy: {plan.message}</p>
      </section>
    );
  return (
    <section aria-labelledby="idc-title" className="flex flex-col gap-2">
      <h2 id="idc-title">Identity method change</h2>
      <p>
        {NAME[p.side]}'s identity changes to {p.next.method}. This needs a 4-of-4 seal update: every slot must sign the
        new seal.
      </p>
      <dl className="break-all">
        <dt>Old seal</dt>
        <dd data-testid="old-seal">{plan.oldSeal}</dd>
        <dt>New seal</dt>
        <dd data-testid="new-seal">{plan.newSeal}</dd>
      </dl>
      <ul aria-label="Signers">
        {plan.signers.map((s) => (
          <li key={s} data-testid={`signer-${s}`}>
            <StatusBadge
              status={p.responses[s] === 'signed' ? 'pass' : p.responses[s] === 'refused' ? 'fail' : 'pending'}
            />{' '}
            {NAME[s]}: {p.responses[s] ?? 'waiting'}
          </li>
        ))}
      </ul>
      {outcome.state === 'refused' ? (
        <p role="alert">
          Stalled (O9): {outcome.refusedBy.map((s) => NAME[s]).join(', ')} refused to sign. The release cannot go ahead
          until the update is signed.
        </p>
      ) : (
        <p role="status">
          {outcome.state === 'applied'
            ? 'Applied: all four slots signed the new seal.'
            : `Waiting for ${outcome.waiting.map((s) => NAME[s]).join(', ')}.`}
        </p>
      )}
    </section>
  );
}
