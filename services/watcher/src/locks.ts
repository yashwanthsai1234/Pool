// The lock checker on one validated ledger, for a funded deal wallet (DESIGN 10.2).
import type { Finding } from '@legx/contracts/records';
import type { XrplAddress } from '@legx/contracts/values';
import { checkLock, type Expected } from '@legx/core/lockcheck';
import { snapshot } from '@legx/xrpl/read';
import type { Link } from '@legx/xrpl/watcher/index';

export interface DealWatch {
  readonly dealId: string;
  readonly wallet: string;
  /** `funded`: the quarantine escrow has been finished, so its rules cannot hold any more (DQ-1). */
  readonly phase: 'pre-funding' | 'funded';
  readonly expected: Expected;
  /** The recorded exit ticket, if any: the only Ticket the wallet may own after funding. */
  readonly exitTicket?: number;
}

// TEMPORARY RULE, linked to DQ-1 (IMPLEMENTATION Appendix B, build/ISSUES.md I-3.5-a): `checkLock` has no `phase`
// option yet, and after the finish its escrow rules fail on every ledger. Until the design answers and lockcheck takes
// `phase: 'funded'`, the watcher drops exactly these four escrow findings once the deal is funded. Nothing else is dropped.
const ESCROW_RULES: ReadonlySet<string> = new Set([
  'QUARANTINE_PRESENT',
  'ESCROW_AMOUNT_AND_CONDITION',
  'NO_FINISH_DELAY_TRAP',
  'CANCEL_AFTER_MARGIN',
]);

export const failing = (f: readonly Finding[]) => f.filter((x) => x.level === 'block' && !x.ok);

/** Reads the wallet at validated ledger `index` from `link` and checks it. */
export async function lockCheckAt(link: Link, d: DealWatch, index: number) {
  const snap = await snapshot(link, [d.wallet as XrplAddress], index);
  const acct = snap.accounts[d.wallet];
  if (!acct) throw new Error(`lock check: no snapshot for ${d.wallet}`);
  const expected: Expected = {
    ...d.expected,
    allowedTicketSequences: d.exitTicket === undefined ? [] : [d.exitTicket],
  };
  const findings = checkLock(acct.accountData, [...acct.objects], expected).filter(
    (f) => d.phase !== 'funded' || !ESCROW_RULES.has(f.code),
  );
  return { ledger: snap.ledger, findings };
}
