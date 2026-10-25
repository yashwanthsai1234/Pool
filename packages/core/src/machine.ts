// Deal state machine (DESIGN 5.1, invariants I1 to I8). Pure and total: `transition` never throws, so the Quint
// model (task 5.1) can replay traces through it. `step` is the throwing form for callers that want an exception.
// Source: DESIGN 5.1 and Appendix C; build/SHIP_RECEIPT.md 5 (OD-37: SHIPPED and RECEIVED before the release).
export type State =
  | 'DRAFT'
  | 'CONTRACT_SIGNED'
  | 'SHELL_OPEN'
  | 'QUARANTINED'
  | 'KEYS_READY'
  | 'WALLET_LOCKED'
  | 'VERIFIED'
  | 'SHIPPED'
  | 'RECEIVED'
  | 'FUNDED'
  | 'PAID_OUT'
  | 'REFUNDED'
  | 'DISPUTED'
  | 'EXPIRED'
  | 'CLOSED';
export type Event =
  | { t: 'SIGN_CONTRACT' }
  | { t: 'OPEN_SHELL' }
  | { t: 'FUND_QUARANTINE' }
  | { t: 'KEYS_MADE' }
  | { t: 'LOCK_WALLET' }
  | { t: 'VERIFY_OK' }
  | { t: 'SHIP_SIGNED' }
  | { t: 'RECEIPT_SIGNED'; condition: 'ok' | 'damaged' | 'missing' }
  | { t: 'RELEASE_ESCROW'; gatePassed: boolean; submitter: string; releaser: string }
  | { t: 'CANCEL_AFTER_PASSED' }
  | { t: 'PAY_BOB'; sigs: number }
  | { t: 'REFUND_ALICE'; sigs: number }
  | { t: 'OPEN_DISPUTE' }
  | { t: 'AWARD'; to: 'BOB' | 'ALICE'; sigs: number }
  | { t: 'ABANDON' }
  | { t: 'CLOSE'; sigs: number };

export const QUORUM = 4; // client A, lawyer A, client B, lawyer B
export interface Deal {
  state: State;
  wasLocked: boolean;
}

const next: Record<State, Partial<Record<Event['t'], State>>> = {
  DRAFT: { SIGN_CONTRACT: 'CONTRACT_SIGNED' },
  CONTRACT_SIGNED: { OPEN_SHELL: 'SHELL_OPEN', ABANDON: 'CLOSED' },
  SHELL_OPEN: { FUND_QUARANTINE: 'QUARANTINED', ABANDON: 'CLOSED' }, // AccountDelete by master
  QUARANTINED: { KEYS_MADE: 'KEYS_READY', CANCEL_AFTER_PASSED: 'EXPIRED' },
  KEYS_READY: { LOCK_WALLET: 'WALLET_LOCKED', CANCEL_AFTER_PASSED: 'EXPIRED' },
  WALLET_LOCKED: { VERIFY_OK: 'VERIFIED', CANCEL_AFTER_PASSED: 'EXPIRED' },
  // OD-37: Bob's shipment, then Alice's receipt; the release is legal only after the receipt.
  VERIFIED: { SHIP_SIGNED: 'SHIPPED', CANCEL_AFTER_PASSED: 'EXPIRED' },
  SHIPPED: { RECEIPT_SIGNED: 'RECEIVED', CANCEL_AFTER_PASSED: 'EXPIRED' },
  RECEIVED: { RELEASE_ESCROW: 'FUNDED', CANCEL_AFTER_PASSED: 'EXPIRED' },
  FUNDED: { PAY_BOB: 'PAID_OUT', REFUND_ALICE: 'REFUNDED', OPEN_DISPUTE: 'DISPUTED' },
  DISPUTED: { AWARD: 'PAID_OUT' },
  PAID_OUT: { CLOSE: 'CLOSED' },
  REFUNDED: { CLOSE: 'CLOSED' },
  EXPIRED: { CLOSE: 'CLOSED' },
  CLOSED: {},
};

export type Refusal = 'illegal' | 'quorum' | 'gate' | 'submitter' | 'receipt';
export type Transition = { ok: true; deal: Deal } | { ok: false; refusal: Refusal; message: string };

// Total transition. Refuses an illegal event, a missing quorum, or a release without the gate (I8).
export function transition(d: Deal, e: Event): Transition {
  const to = next[d.state][e.t];
  if (!to) return { ok: false, refusal: 'illegal', message: `illegal ${e.t} in ${d.state}` };
  // OD-37: only an `ok` receipt moves the deal on; damaged or missing leaves it SHIPPED (dispute path, or the refund
  // after CancelAfter).
  if (e.t === 'RECEIPT_SIGNED' && e.condition !== 'ok')
    return { ok: false, refusal: 'receipt', message: `receipt condition ${e.condition}` };
  // I8: funds enter the deal wallet only after the release gate passed (DESIGN 6.17).
  if (e.t === 'RELEASE_ESCROW' && e.gatePassed !== true)
    return { ok: false, refusal: 'gate', message: 'release gate not passed' };
  // The release is single-signed by the sealed releaserAccount (DESIGN D4, D22, 6.17): no quorum, but the submitter must be it.
  if (e.t === 'RELEASE_ESCROW' && (e.submitter !== e.releaser || e.releaser === ''))
    return { ok: false, refusal: 'submitter', message: 'submitter is not the sealed releaser' };
  // After the lock, every ledger action from the deal wallet needs all four signatures.
  // Before the lock (abandon or close an unlocked shell) the master key alone signs.
  if ('sigs' in e && d.wasLocked && e.sigs < QUORUM)
    return { ok: false, refusal: 'quorum', message: `quorum not met: ${e.sigs}/${QUORUM}` };
  const state: State = e.t === 'AWARD' ? (e.to === 'BOB' ? 'PAID_OUT' : 'REFUNDED') : to;
  return { ok: true, deal: { state, wasLocked: d.wasLocked || state === 'WALLET_LOCKED' } };
}

// Pure transition. Throws on an illegal event, a missing quorum or a closed gate.
export function step(d: Deal, e: Event): Deal {
  const r = transition(d, e);
  if (!r.ok) throw new Error(r.message);
  return r.deal;
}
export const moneyInWallet = (s: State) => s === 'FUNDED' || s === 'DISPUTED';
