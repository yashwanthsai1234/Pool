// Public deal data: every input of the deal seal, in seal order (DESIGN 6.6, 29 fields).
// Source: DESIGN.md section 6.6 "Deal seal"
import { z } from 'zod';
import { Hex32, IdentityPolicy, IdMethod, Payout, XrplAddress, XrplEd25519PublicKey } from './values.ts';

export const PublicDealData = z
  .strictObject({
    contractRoot: Hex32,
    signedContractSeal: Hex32,
    walletAddress: XrplAddress,
    xPubA: XrplEd25519PublicKey,
    xPubB: XrplEd25519PublicKey,
    commitmentA: Hex32, // C_A (DESIGN 6.2)
    commitmentB: Hex32, // C_B
    idMethodA: IdMethod,
    idMethodB: IdMethod,
    identityPolicy: IdentityPolicy,
    lawyerPubA: XrplEd25519PublicKey,
    lawyerPubB: XrplEd25519PublicKey,
    lawyerCommitmentA: Hex32, // LC_A
    lawyerCommitmentB: Hex32, // LC_B
    lawyerOpsA: XrplAddress,
    lawyerOpsB: XrplAddress,
    releaserAccount: XrplAddress,
    slotPolicyA: Hex32,
    slotPolicyLA: Hex32,
    slotPolicyB: Hex32,
    slotPolicyLB: Hex32,
    pqKeyHashA: Hex32,
    pqKeyHashLA: Hex32,
    pqKeyHashB: Hex32,
    pqKeyHashLB: Hex32,
    signerAccounts: z.array(XrplAddress).length(4), // hashed as join(",", sort(...)); order here does not matter
    quorum: z.literal(4),
    payoutA: Payout, // Alice's refund address
    payoutB: Payout, // Bob's payment address
  })
  // DESIGN 6.6: "dealSeal throws if releaserAccount !== lawyerOpsB".
  .refine((d) => d.releaserAccount === d.lawyerOpsB, {
    path: ['releaserAccount'],
    message: 'releaserAccount must equal lawyerOpsB',
  })
  .refine((d) => new Set(d.signerAccounts).size === 4, {
    path: ['signerAccounts'],
    message: 'signer accounts must be distinct',
  });
export type PublicDealData = z.infer<typeof PublicDealData>;

/** The seal fields in tupleHash order, so core and tests share one list (DESIGN 6.6). */
export const SEAL_FIELD_ORDER = Object.keys(PublicDealData.shape) as readonly (keyof PublicDealData)[];

/** `Domain` on the deal wallet: `01 || contractRoot || dealSeal`, 65 bytes, uppercase hex as on the ledger. */
export const DomainHex = z
  .string()
  .regex(/^01[0-9A-F]{128}$/)
  .brand<'DomainHex'>();
