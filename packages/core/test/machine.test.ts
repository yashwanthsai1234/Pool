import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { type Deal, type Event, moneyInWallet, QUORUM, type State, step, transition } from '../src/machine.ts';

const STATES: State[] = [
  'DRAFT',
  'CONTRACT_SIGNED',
  'SHELL_OPEN',
  'QUARANTINED',
  'KEYS_READY',
  'WALLET_LOCKED',
  'VERIFIED',
  'FUNDED',
  'PAID_OUT',
  'REFUNDED',
  'DISPUTED',
  'EXPIRED',
  'CLOSED',
];
const PLAIN = [
  'SIGN_CONTRACT',
  'OPEN_SHELL',
  'FUND_QUARANTINE',
  'KEYS_MADE',
  'LOCK_WALLET',
  'VERIFY_OK',
  'CANCEL_AFTER_PASSED',
  'OPEN_DISPUTE',
  'ABANDON',
] as const;
const sigs = fc.integer({ min: 0, max: 4 });
const ev: fc.Arbitrary<Event> = fc.oneof(
  ...PLAIN.map((t) => fc.constant({ t } as Event)),
  fc.record({
    t: fc.constant('RELEASE_ESCROW' as const),
    gatePassed: fc.boolean(),
    submitter: fc.constantFrom('rB', 'rX'),
    releaser: fc.constant('rB'),
  }),
  fc.record({ t: fc.constant('PAY_BOB' as const), sigs }),
  fc.record({ t: fc.constant('REFUND_ALICE' as const), sigs }),
  fc.record({
    t: fc.constant('AWARD' as const),
    to: fc.constantFrom('BOB', 'ALICE') as fc.Arbitrary<'BOB' | 'ALICE'>,
    sigs,
  }),
  fc.record({ t: fc.constant('CLOSE' as const), sigs }),
);
const fresh: Deal = { state: 'DRAFT', wasLocked: false };
const at = (state: State, wasLocked: boolean): Deal => ({ state, wasLocked });

it('T-P-04 invariants I1, I2, I6 and I8 hold for any event sequence', () => {
  fc.assert(
    fc.property(fc.array(ev, { maxLength: 40 }), (events) => {
      let d = fresh;
      for (const e of events) {
        const r = transition(d, e);
        if (!r.ok) continue;
        const n = r.deal;
        if (n.state === 'FUNDED') {
          expect(d.wasLocked).toBe(true); // I1: funded only after the lock
          expect(e.t === 'RELEASE_ESCROW' && e.gatePassed === true && e.submitter === e.releaser).toBe(true); // I8, P1.14-02
        }
        if (n.state === 'PAID_OUT' || n.state === 'REFUNDED') expect('sigs' in e && e.sigs >= QUORUM).toBe(true); // I2
        expect(d.state).not.toBe('CLOSED'); // I6: CLOSED is final
        if (d.state === 'EXPIRED') expect(n.state).toBe('CLOSED');
        d = n;
      }
    }),
    { numRuns: 2000 },
  );
});

describe('P1.14 release gate and awards', () => {
  const verified = at('VERIFIED', true);
  it('P1.14-01 RELEASE_ESCROW without gatePassed: true, or from another submitter, throws; the sealed releaser funds', () => {
    expect(() => step(verified, { t: 'RELEASE_ESCROW', gatePassed: false, submitter: 'rB', releaser: 'rB' })).toThrow(
      /gate/,
    );
    expect(() => step(verified, { t: 'RELEASE_ESCROW', submitter: 'rB', releaser: 'rB' } as unknown as Event)).toThrow(
      /gate/,
    );
    expect(() =>
      step(verified, { t: 'RELEASE_ESCROW', gatePassed: 'true', submitter: 'rB', releaser: 'rB' } as unknown as Event),
    ).toThrow(/gate/);
    expect(step(verified, { t: 'RELEASE_ESCROW', gatePassed: true, submitter: 'rB', releaser: 'rB' }).state).toBe(
      'FUNDED',
    );
  });
  it('P1.14-03 AWARD from DISPUTED pays Bob or refunds Alice, and needs all four', () => {
    const disputed = at('DISPUTED', true);
    expect(step(disputed, { t: 'AWARD', to: 'BOB', sigs: 4 }).state).toBe('PAID_OUT');
    expect(step(disputed, { t: 'AWARD', to: 'ALICE', sigs: 4 }).state).toBe('REFUNDED');
    expect(() => step(disputed, { t: 'AWARD', to: 'BOB', sigs: 3 })).toThrow(/quorum/);
  });
  it('an empty releaser never matches', () => {
    expect(transition(verified, { t: 'RELEASE_ESCROW', gatePassed: true, submitter: '', releaser: '' })).toMatchObject({
      refusal: 'submitter',
    });
  });
  it('the refusal kind is reported without throwing', () => {
    expect(
      transition(verified, { t: 'RELEASE_ESCROW', gatePassed: false, submitter: 'rB', releaser: 'rB' }),
    ).toMatchObject({
      ok: false,
      refusal: 'gate',
    });
    expect(
      transition(verified, { t: 'RELEASE_ESCROW', gatePassed: true, submitter: 'rX', releaser: 'rB' }),
    ).toMatchObject({
      ok: false,
      refusal: 'submitter',
    });
    // single-signed: no quorum applies, locked or not
    expect(transition(verified, { t: 'RELEASE_ESCROW', gatePassed: true, submitter: 'rB', releaser: 'rB' }).ok).toBe(
      true,
    );
    expect(transition(fresh, { t: 'CLOSE', sigs: 4 })).toMatchObject({ ok: false, refusal: 'illegal' });
  });
});

describe('exhaustive state times event table', () => {
  // The expected next state of DESIGN 5.1, written out independently of the table in machine.ts.
  const EDGES: Record<string, State> = {
    'DRAFT SIGN_CONTRACT': 'CONTRACT_SIGNED',
    'CONTRACT_SIGNED OPEN_SHELL': 'SHELL_OPEN',
    'CONTRACT_SIGNED ABANDON': 'CLOSED',
    'SHELL_OPEN FUND_QUARANTINE': 'QUARANTINED',
    'SHELL_OPEN ABANDON': 'CLOSED',
    'QUARANTINED KEYS_MADE': 'KEYS_READY',
    'QUARANTINED CANCEL_AFTER_PASSED': 'EXPIRED',
    'KEYS_READY LOCK_WALLET': 'WALLET_LOCKED',
    'KEYS_READY CANCEL_AFTER_PASSED': 'EXPIRED',
    'WALLET_LOCKED VERIFY_OK': 'VERIFIED',
    'WALLET_LOCKED CANCEL_AFTER_PASSED': 'EXPIRED',
    'VERIFIED RELEASE_ESCROW': 'FUNDED',
    'VERIFIED CANCEL_AFTER_PASSED': 'EXPIRED',
    'FUNDED PAY_BOB': 'PAID_OUT',
    'FUNDED REFUND_ALICE': 'REFUNDED',
    'FUNDED OPEN_DISPUTE': 'DISPUTED',
    'DISPUTED AWARD': 'PAID_OUT',
    'PAID_OUT CLOSE': 'CLOSED',
    'REFUNDED CLOSE': 'CLOSED',
    'EXPIRED CLOSE': 'CLOSED',
  };
  const full: Event[] = [
    ...PLAIN.map((t) => ({ t }) as Event),
    { t: 'RELEASE_ESCROW', gatePassed: true, submitter: 'rB', releaser: 'rB' },
    { t: 'PAY_BOB', sigs: QUORUM },
    { t: 'REFUND_ALICE', sigs: QUORUM },
    { t: 'AWARD', to: 'BOB', sigs: QUORUM },
    { t: 'CLOSE', sigs: QUORUM },
  ];
  it('every state and every event gives the expected state or an illegal refusal (13 x 14 x 2 lock flags)', () => {
    let checked = 0;
    for (const s of STATES)
      for (const e of full)
        for (const locked of [false, true]) {
          const r = transition(at(s, locked), e);
          const want = EDGES[`${s} ${e.t}`];
          if (want === undefined) expect(r, `${s} ${e.t}`).toMatchObject({ ok: false, refusal: 'illegal' });
          else expect(r, `${s} ${e.t}`).toMatchObject({ ok: true, deal: { state: want } });
          if (r.ok) expect(r.deal.wasLocked).toBe(locked || r.deal.state === 'WALLET_LOCKED');
          checked++;
        }
    expect(checked).toBe(13 * 14 * 2);
    expect(Object.keys(EDGES)).toHaveLength(20);
  });
  it('a locked deal refuses every sigs-carrying event below the quorum, an unlocked shell does not', () => {
    for (const s of STATES)
      for (const e of full) {
        if (!('sigs' in e)) continue;
        const low = { ...e, sigs: QUORUM - 1 };
        const legal = EDGES[`${s} ${e.t}`] !== undefined;
        expect(transition(at(s, true), low).ok, `${s} ${e.t}`).toBe(false);
        expect(transition(at(s, false), low).ok, `${s} ${e.t}`).toBe(legal);
      }
  });
  it('moneyInWallet is true exactly for FUNDED and DISPUTED', () => {
    expect(STATES.filter(moneyInWallet)).toEqual(['FUNDED', 'DISPUTED']);
  });
});
