// The recovery proof check (DESIGN 6.4 "Recovery rules", 6.10): a client recovery starts with a fresh zero-knowledge
// passport proof that has the same deal-scoped identifier as onboarding, plus a face match. The agent does not verify
// proofs itself and does not take a client's word for one: it looks the supplied result up in the records the verifier
// service (task 3.11) wrote, requires it to be that exact record, and requires the proof to be bound to the NEW key,
// so a proof that was captured cannot enroll an attacker's device. Freshness is judged by the caller from `provedAt`
// (ledger time), at most 10 minutes (OD-18, core `PROOF_FRESH_MS`).
// Source: DESIGN 6.4 and 6.10; build/DECISIONS.md OD-18
import type { ZkVerification } from '@legx/contracts/records';
import { bytesToHex, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import type { CheckedRecoveryProof, RecoveryProofPort } from './ports.ts';
import { Refusal } from './recovery.ts';

/** A record the verifier service wrote after it checked a proof: the result, the ledger time (ms) and the face match. */
export interface VerifiedRecord {
  readonly result: ZkVerification;
  readonly verifiedAt: number;
  readonly faceMatch: boolean;
}
export interface VerifiedRecords {
  find(proofSha256: string): Promise<VerifiedRecord | undefined>;
}

/** The `custom_data` a recovery proof is made with: bound to the deal and the new enrollment key. New tag, see the status file. */
export const recoveryBoundValue = (dealId: string, newKeyId: string): string =>
  bytesToHex(tupleHash('legx/zk-recover/v1', [utf8ToBytes(dealId), utf8ToBytes(newKeyId)]));

export class RecordedProofs implements RecoveryProofPort {
  readonly #records: VerifiedRecords;
  constructor(records: VerifiedRecords) {
    this.#records = records;
  }
  async check(input: {
    dealId: string;
    slot: 'A' | 'B';
    newKeyId: string;
    proof: ZkVerification;
  }): Promise<CheckedRecoveryProof> {
    const rec = await this.#records.find(input.proof.proofSha256);
    const same = rec !== undefined && JSON.stringify(rec.result) === JSON.stringify(input.proof);
    if (!rec || !same || !rec.result.verified || rec.result.uniqueIdentifier === null)
      throw new Refusal('PROOF_NOT_VERIFIED');
    if (rec.result.committedInputs.custom_data !== recoveryBoundValue(input.dealId, input.newKeyId))
      throw new Refusal('PROOF_NOT_BOUND');
    return { identifier: rec.result.uniqueIdentifier, provedAt: rec.verifiedAt, faceMatch: rec.faceMatch };
  }
}
