import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { EventKind, LegxEvent } from '../src/events.ts';
import { GATE_CODES } from '../src/records.ts';

describe('P1.2-06 EventKind', () => {
  it('equals the list in DESIGN 8.1 plus the fix-fleet additions exactly', () => {
    const design = [
      'contract.lawyer_signed',
      'nft.minted',
      'shell.opened',
      'escrow.created',
      'key.bound',
      'ops.bound',
      'bar.verified',
      'bar.deal_linked',
      'attorney.credential.issued',
      'wallet.locked',
      'lock.verified',
      'lawyer.approved',
      'passport.verified',
      'release.gate.passed',
      'release.performed',
      'frost.dkg.completed',
      'frost.signed',
      'frost.refreshed',
      'identity.onboarded',
      'pq.bound',
      'exit.signed',
      'exit.validated',
      'dispute.opened',
      'award.recorded',
      'escrow.cancelled',
      'wallet.closed',
      // Added by the fix fleet (lane F1) from the agents' requests: tasks 3.2, 3.5, 3.9, 3.10 and OD-28.
      'deal.created',
      'enrollment.pinned',
      'ledger.disagreement',
      'frost.share.released',
      'frost.refused',
      'frost.recovery.requested',
      'frost.recovery.cancelled',
      'frost.recovery.authorized',
      'frost.recovery.signed',
      'release_code.handed_over',
      'checkpoint.anchored',
    ];
    expect(new Set(EventKind.options)).toEqual(new Set(design));
    expect(EventKind.options).toHaveLength(design.length);
  });

  const events = JSON.parse(readFileSync(new URL('../examples/LegxEvent.json', import.meta.url), 'utf8'));

  it('has one golden event per kind', () => {
    expect(events.map((e: { predicate: { kind: string } }) => e.predicate.kind)).toEqual(EventKind.options);
  });

  it('rejects an event whose data belongs to another kind', () => {
    const [a, b] = events;
    const mixed = { ...a, predicate: { ...a.predicate, data: b.predicate.data } };
    expect(LegxEvent.safeParse(mixed).success).toBe(false);
  });

  it('rejects an event with an unknown kind, or without sig_algs inside the signed predicate', () => {
    const [a] = events;
    expect(LegxEvent.safeParse({ ...a, predicate: { ...a.predicate, kind: 'wallet.drained' } }).success).toBe(false);
    const { sig_algs: _, ...noAlgs } = a.predicate;
    expect(LegxEvent.safeParse({ ...a, predicate: noAlgs }).success).toBe(false);
  });

  it('the release gate record lists all 15 gate codes of DESIGN 6.17', () => {
    expect(GATE_CODES).toHaveLength(15);
    const gate = events.find((e: { predicate: { kind: string } }) => e.predicate.kind === 'release.gate.passed');
    const codes = gate.predicate.data.gate.findings.map((f: { code: string }) => f.code);
    expect(new Set(codes)).toEqual(new Set(GATE_CODES));
  });
});
