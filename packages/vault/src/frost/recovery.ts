// Client recovery on a new phone (DESIGN 6.4 "Recovery rules"; P4.7-16, P4.7-17; OD-18):
//  1. a fresh zero-knowledge passport proof (at most 10 minutes old by ledger time) with the deal-scoped identifier
//     from onboarding, plus a face match. The phone checks it first with core's `recoveryStart`, so the screen can give
//     the reason; the recovery agent checks it again (task 3.9) and is the one that counts;
//  2. the 72-hour delay by ledger time. The old device and both lawyers are notified, and the old device can cancel;
//  3. after the delay: repair (repair.ts) and refresh (refresh.ts).
// The recovery agent signs nothing on its own: it needs this request, the proof and the delay (task 3.9).
// Source: DESIGN.md 6.4; packages/contracts/src/api.ts (`recovery.start`, `recovery.get`, `recovery.cancel`)
import type { ZkVerification } from '@legx/contracts/records';
import { PROOF_FRESH_MS, RecoveryError, recoveryStart } from '@legx/core/frostRules';
import type { RecoveryStatus } from './text.ts';

export interface RecoveryApi {
  recovery: {
    start(input: {
      kind: 'client';
      dealId: string;
      slot: 'A' | 'B';
      newKeyId: string;
      proof: ZkVerification;
    }): Promise<RecoveryStatus>;
    get(input: { dealId: string; recoveryId: string }): Promise<RecoveryStatus>;
    cancel(input: { dealId: string; recoveryId: string }): Promise<RecoveryStatus>;
  };
}

/** What the passport flow (task 4.8) hands over: the verified proof, when it was made, and the face match. */
export type FreshProof = { verification: ZkVerification; provedAt: number; faceMatch: boolean };

const REASONS: Record<string, string> = {
  IDENTIFIER_MISMATCH: 'This passport proof is for another person than the one who onboarded.',
  FACE_MATCH_MISSING: 'The proof has no face match. Scan again and complete the face check.',
  PROOF_STALE: `The proof is older than ${PROOF_FRESH_MS / 60_000} minutes. Make a fresh one.`,
};

/** Why a proof is refused, in words; undefined when it may start a recovery. `at` is ledger time in ms. */
export function proofRefusal(
  p: FreshProof,
  onboardingIdentifier: string,
  slot: 'A' | 'B',
  at: number,
): string | undefined {
  try {
    recoveryStart({
      kind: 'client',
      slot,
      at,
      proof: { identifier: p.verification.uniqueIdentifier ?? '', provedAt: p.provedAt },
      onboardingIdentifier,
      faceMatch: p.faceMatch && p.verification.verified,
    });
    return undefined;
  } catch (e) {
    return e instanceof RecoveryError ? (REASONS[e.code] ?? e.code) : 'The proof could not be checked.';
  }
}
