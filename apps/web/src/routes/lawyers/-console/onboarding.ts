// OD-32: the client's own lawyer verifies the client's onboarding proof in the console. The server's ZK route checks the public proofs
// only; the console opens the disclosure box with its vault key (in the frame), checks the result against the deal and the sealed
// commitment, and only then signs `identity.onboarded` (OD-2) and records it.
// Source: build/DECISIONS.md OD-2, OD-25, OD-32; DESIGN.md 6.10 (onboarding), 6.17 (ONBOARDING_OK), 8.1
import type { ZkVerifyRequest } from '@legx/contracts/records';
import { distinctTag, verifyOnboarding } from '@legx/core/attest';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@legx/core/dealcore';
import { type SealedPackage, toBase64 } from '@legx/core/pq';
import { onboardingBoundValue, trustRecordOf, zkIdentityCommitment } from '@legx/core/zkIdentity';
import { verifyOnboardingInConsole } from '../../../zk/onboarding.ts';
import { signSelfChecked } from './attestation.ts';
import type { createEventAppender } from './events.ts';
import { type ConsoleDeps, ConsoleError, SIDE_OF } from './ports.ts';

export interface OnboardingRun {
  /** The onboarding-stage request the client's phone proved (public proofs only), as the lawyer received it. */
  request: ZkVerifyRequest;
  /** The `zk-disclosure` box the client sealed to this lawyer's vault key. */
  box: SealedPackage;
  /** The escrow's planned `CancelAfter`, unix seconds: the proof must show the passport valid 30 days past it. */
  cancelAfter: number;
  /** P4.8-08: the console's own local re-verification of the proof set; `false` blocks. */
  reverify?: () => Promise<boolean>;
}

/** Onboarding is for the lawyer's own client only: lawyer A attests side A, lawyer B side B. */
export function createOnboarding(deps: ConsoleDeps, appendEvent: ReturnType<typeof createEventAppender>) {
  const { role, deal } = deps;
  const side = SIDE_OF[role];
  const data = deal.data;
  return {
    async verifyAndSign(run: OnboardingRun): Promise<Uint8Array> {
      if (!deps.onboarding) throw new ConsoleError('NO_DISCLOSURE_KEY', 'this console cannot open the disclosure box');
      const slotPub = side === 'A' ? data.xPubA : data.xPubB;
      const checked = await verifyOnboardingInConsole(
        {
          verifyPublic: deps.identity.zkVerify,
          openBox: deps.onboarding.openDisclosure,
          ...(run.reverify ? { reverify: run.reverify } : {}),
        },
        {
          dealId: deal.id,
          side,
          profile: deal.profile,
          request: run.request,
          boundValue: onboardingBoundValue(hexToBytes(data.contractRoot), hexToBytes(slotPub)),
          cancelAfter: run.cancelAfter,
          box: run.box,
        },
      );
      if (!checked.ok) throw new ConsoleError(checked.code);
      // The proof names a person; the seal names a commitment. They must be the same person (6.2: C = tupleHash(salt, N)).
      const commitment = bytesToHex(zkIdentityCommitment(await deps.identity.salt(), checked.identifier));
      if (commitment !== (side === 'A' ? data.commitmentA : data.commitmentB))
        throw new ConsoleError('COMMITMENT_MISMATCH');
      const payload = {
        deal_id: deal.id,
        contract_root: data.contractRoot,
        side,
        slot_pub: slotPub,
        commitment,
        disclosure_box_sha256: checked.boxSha256,
        checked_by_role: role === 'LA' ? 'lawyerA' : 'lawyerB',
        distinct_tag: bytesToHex(distinctTag(deal.id, utf8ToBytes(checked.identifier))),
        method: 'zkpassport',
        checks: {
          // `checkZkResult` (inside the verification above) has refused anything else: verified, bound, expiry margin.
          proof_verified: true,
          bound_value_matches: true,
          expiry_after_cancel_plus_30d: true,
          age_over_18: true,
          scope: checked.verification.scope,
          domain: checked.verification.domain,
          unique_identifier: checked.identifier,
          proof_sha256: checked.verification.proofSha256,
          trust: trustRecordOf(checked.verification),
        },
        sig_algs: ['ed25519', 'ml-dsa-65'],
      };
      const bytes = await signSelfChecked(deps.signer, payload, (envelope) =>
        verifyOnboarding({
          envelope,
          side,
          deal: { id: deal.id, data },
          sealedKeys: { lawyerKeyIds: deps.lawyerKeyIds, registry: deps.registry },
          now: deps.now(),
          profile: deal.profile,
        }),
      );
      await appendEvent('identity.onboarded', { side, attestation: toBase64(bytes) });
      return bytes;
    },
  };
}
