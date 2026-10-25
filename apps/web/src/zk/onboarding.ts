// OD-32: onboarding verification runs in the client's own lawyer's console. The server's ZK route verifies only the
// public proofs (it never receives the disclosure box in clear, OD-25); the console then opens the `zk-disclosure` box
// with its own X-Wing key, checks the result against the deal, and only then may sign `identity.onboarded` (OD-2).
// Source: build/DECISIONS.md OD-25, OD-32; DESIGN.md 6.10 ("Who verifies")
import type { ZkVerification, ZkVerifyRequest } from '@legx/contracts/records';
import type { Profile, Side } from '@legx/core/attest';
import type { SealedPackage } from '@legx/core/pq';
import { boxDigest, checkZkResult, type Disclosure } from '@legx/core/zkIdentity';

export interface ConsoleOnboardingDeps {
  /** The server's ZK route: public proofs only. A failure is "cannot check now", never a pass. */
  verifyPublic(request: ZkVerifyRequest): Promise<ZkVerification>;
  /** P4.8-08: the console's own local re-verification of the proof set; `false` blocks even when the adapter passed. */
  reverify?(): Promise<boolean>;
  /** Opens the disclosure box with the lawyer's own key (`openDisclosure` over the vault's X-Wing key). */
  openBox(
    box: SealedPackage,
    dealId: string,
    side: Side,
  ): Promise<{ ok: true; facts: Disclosure } | { ok: false; code: string }>;
}

export interface ConsoleOnboardingInput {
  dealId: string;
  side: Side;
  profile: Profile;
  request: ZkVerifyRequest;
  /** `onboardingBoundValue(contractRoot, slotPub)`, recomputed by the console from its own copy of the deal. */
  boundValue: string;
  cancelAfter: number;
  box: SealedPackage;
  /** The digest the stored box is expected to have (`disclosure_box_sha256`), when known. */
  boxSha256?: string;
}

export type ConsoleOnboarding =
  | { ok: true; verification: ZkVerification; identifier: string; facts: Disclosure; boxSha256: string }
  | { ok: false; code: string };

export async function verifyOnboardingInConsole(
  deps: ConsoleOnboardingDeps,
  i: ConsoleOnboardingInput,
): Promise<ConsoleOnboarding> {
  let verification: ZkVerification;
  try {
    verification = await deps.verifyPublic(i.request);
  } catch {
    return { ok: false, code: 'CANNOT_CHECK_NOW' };
  }
  const checked = checkZkResult(verification, i.request.originalQuery, {
    stage: 'onboarding',
    dealId: i.dealId,
    boundValue: i.boundValue,
    profile: i.profile,
    cancelAfter: i.cancelAfter,
  });
  if (!checked.ok) return { ok: false, code: checked.code };
  if (deps.reverify && !(await deps.reverify())) return { ok: false, code: 'LOCAL_REVERIFY_FAILED' };
  const digest = boxDigest(i.box);
  if (i.boxSha256 !== undefined && i.boxSha256 !== digest) return { ok: false, code: 'BOX_DIGEST_MISMATCH' };
  const opened = await deps.openBox(i.box, i.dealId, i.side);
  if (!opened.ok) return { ok: false, code: 'BOX_OPEN_FAILED' };
  return { ok: true, verification, identifier: checked.identifier, facts: opened.facts, boxSha256: digest };
}
