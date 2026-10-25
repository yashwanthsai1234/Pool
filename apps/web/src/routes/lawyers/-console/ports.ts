// What the lawyer console needs from the outside. Task 4.3 wires the real ones (vault, API client, XRPL); the tests use
// fakes, or MSW through `httpLedgerRelay`. Every port is narrow, so a hostile coordinator can only hand over data that
// the console then checks itself.
import type { PublicDealData } from '@legx/contracts/deal';
import type { SignerPort } from '@legx/contracts/ports';
import type { ZkVerification, ZkVerifyRequest } from '@legx/contracts/records';
import type { Profile } from '@legx/core/attest';
import type { SlotPublic } from '@legx/core/frost';
import type { SignRequest } from '@legx/core/frostRules';
import type { KeyRegistry } from '@legx/core/hybridEnvelope';
import type { SealedPackage } from '@legx/core/pq';
import type { GateEventFields, ReleaseInput } from '@legx/core/releaseGate';
import type { Disclosure } from '@legx/core/zkIdentity';
import type { ApprovalWire, RequestApproval } from '@legx/vault/frost/approval';

export type Role = 'LA' | 'LB';
export type Side = 'A' | 'B';
export const SIDE_OF: Record<Role, Side> = { LA: 'A', LB: 'B' };

export type { ApprovalWire, SignRequest };

/** The lawyer slot: console share plus the firm HSM co-signer (task 4.7). `approval` goes with the request to the HSM. */
export interface SlotPort {
  readonly pub: SlotPublic;
  sign(request: SignRequest, approval: ApprovalWire): Promise<Uint8Array>;
}

/** The lawyer's operations account key (a non-extractable WebCrypto Ed25519 key in the browser). */
export interface OpsKey {
  readonly address: string;
  /** 33-byte XRPL public key, uppercase hex (`ED` + 64). */
  readonly pubHex: string;
  sign(msg: Uint8Array): Promise<Uint8Array>;
}

export interface LedgerHeader {
  index: number;
  hash: string;
  closeTime: number;
}

/** The coordinator's ledger relay: one validated snapshot, as the gate reads it, and the submit path. */
export interface LedgerRelay {
  snapshot(dealId: string): Promise<ReleaseInput>;
  accountSequence(address: string): Promise<number>;
  submit(txBlobHex: string): Promise<{ validated: boolean; hash: string; ledgerIndex: number; result: string }>;
}

/** The console's own read-only public XRPL connection (OD-10): it never trusts the relay for the ledger hash. */
export interface PublicLedger {
  latest(): Promise<LedgerHeader>;
  /** The validated ledger hash at `index`, or undefined when that node does not have it. */
  hashAt(index: number): Promise<string | undefined>;
}

export interface EvidencePort {
  /** Chain fields for the next event (seq, prev_hash, event id, payload commitment). */
  fields(payload: Uint8Array): Promise<GateEventFields>;
  append(envelope: Uint8Array): Promise<void>;
  /** The public proof set (zero-knowledge method) is stored as an attachment, never in the console. */
  attach(kind: 'zk-proof', side: Side, bytes: Uint8Array): Promise<void>;
  /** Lawyer B hands the coordinator only the release condition (never the code behind it). */
  condition(conditionHex: string): Promise<void>;
}

interface DealView {
  id: string;
  data: PublicDealData;
  profile: Profile;
  /** The contract clauses and salts the lawyer was given. The console recomputes the root from them. */
  contract: { clauses: Uint8Array[]; salts: Uint8Array[] };
}

export interface ConsoleDeps {
  role: Role;
  deal: DealView;
  slot: SlotPort;
  /** Lawyer's hybrid enrollment signer (Ed25519 plus ML-DSA-65) for attestations and events. */
  signer: SignerPort;
  /** The lawyer's approval prompt: shows the decoded message and asks for a user-verified WebAuthn approval. */
  confirm(view: ApprovalView): Promise<boolean>;
  requestApproval: RequestApproval;
  ops: OpsKey;
  ledger: LedgerRelay;
  publicLedger: PublicLedger;
  evidence: EvidencePort;
  registry: KeyRegistry;
  /** The enrollment key IDs of both lawyer slots, from the pinned directory. */
  lawyerKeyIds: Record<Side, readonly string[]>;
  /** Ledger history by index, for attestation freshness (validated history never changes). */
  ledgerLookup(index: number): { hash: string; closeTime: number } | undefined;
  /** Client's own passport inputs (client's lawyer only): the sealed salt, the CSCA list, the ZK adapter. */
  identity: {
    salt(): Promise<Uint8Array>;
    trustList: readonly Uint8Array[];
    zkVerify(request: ZkVerifyRequest): Promise<ZkVerification>;
    /** The release-stage request for this presence message, and the stored public proof set whose hash the result names. */
    zkRequest(presenceMsg: Uint8Array): { request: ZkVerifyRequest; proofSet: Uint8Array };
  };
  /** OD-32: opens the `zk-disclosure` box of this lawyer's client with the lawyer's vault key (the key stays in the frame). */
  onboarding?: {
    openDisclosure(
      box: SealedPackage,
      dealId: string,
      side: Side,
    ): Promise<{ ok: true; facts: Disclosure } | { ok: false; code: string }>;
  };
  /** Ripple-epoch seconds of the current validated ledger. */
  now(): number;
  nonce?: () => Uint8Array;
}

export interface ApprovalView {
  /** What the console decoded from the exact bytes, in words. */
  lines: string[];
  /** The decoded fields, for tests and the screen's detail view. */
  fields: Record<string, string>;
  /** SHA-256 of the message, hex: what the WebAuthn approval is over. */
  hash: string;
  /** Differences between what the coordinator said and what the bytes mean. Empty when they agree. */
  mismatch: string[];
}

export class ConsoleError extends Error {
  readonly code: string;
  constructor(code: string, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}
