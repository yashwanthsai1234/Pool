// What the recovery agent needs from the outside, as ports (IMPLEMENTATION 7 "Shape"). The demo and the production
// profile differ only in what is passed here.
import type { ZkVerification } from '@legx/contracts/records';
import type { SealedDeal } from '@legx/core/frostRules';

/** Notices to the people a recovery concerns: the old device and both lawyers (DESIGN 6.4 "Recovery rules"). */
export interface NoticePort {
  notify(notice: {
    dealId: string;
    recoveryId: string;
    to: 'old-device' | 'lawyerA' | 'lawyerB' | 'new-device';
    kind: 'recovery.requested' | 'recovery.cancelled' | 'recovery.ready';
    readyAt: number;
  }): Promise<void>;
}

/** A recovery proof, checked: who it proves, when it was made (by ledger time, ms), and whether a face match is in it. */
export interface CheckedRecoveryProof {
  readonly identifier: string;
  readonly provedAt: number;
  readonly faceMatch: boolean;
}
/**
 * Checks a recovery proof against what the verifier service (task 3.11) recorded: the supplied result must be the
 * recorded one, bound to the new key. A result a client made up is not in the records and is refused.
 */
export interface RecoveryProofPort {
  check(input: {
    dealId: string;
    slot: 'A' | 'B';
    newKeyId: string;
    proof: ZkVerification;
  }): Promise<CheckedRecoveryProof>;
}

/** Deal facts the agent reads from the coordinator. They are public data of the sealed deal (DESIGN 6.6). */
export interface DealInfoPort {
  /** The operations account of a lawyer slot (`lawyer_ops_a` or `lawyer_ops_b`). */
  opsAccount(dealId: string, slot: 'LA' | 'LB'): Promise<string>;
  /** The deal-scoped identifier of the client, as recorded at onboarding (DESIGN 6.10). */
  onboardingIdentifier(dealId: string, slot: 'A' | 'B'): Promise<string>;
  /** The sealed deal data a signature request is compared with (core `messageAllowed`). */
  sealed(dealId: string): Promise<SealedDeal>;
  /** True while the deal is in a state in which a client slot may sign (not closed or cancelled). */
  allowsSigning(dealId: string, slot: string): Promise<boolean>;
}
