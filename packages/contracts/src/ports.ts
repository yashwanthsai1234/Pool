// Ports: the interfaces services implement or call (IMPLEMENTATION 1.2 "Think", 7 port table).
// The demo profile and the production profile differ only in which implementation sits behind each port.
import type { z } from 'zod';
import type { FrostIdentifier, FrostSignedMessage } from './frost.ts';
import type { BarSourceKind, ZkVerification, ZkVerifyRequest } from './records.ts';
import type { Secret } from './secret.ts';
import type { DealId, Drops, Hex32, KeyId, Network, RippleTime, XrplAddress, XrplHash } from './values.ts';

/** A JSON object as rippled returns it (transaction, metadata, ledger entry). Typed by the ledger layer. */
export type XrplJson = Readonly<Record<string, unknown>>;

/** A validated ledger: index, hash and `close_time` (DESIGN 0 rule 4). */
export interface LedgerHeader {
  readonly ledgerIndex: number;
  readonly ledgerHash: XrplHash;
  readonly closeTime: RippleTime;
}

/** `account_info` plus every page of `account_objects` for one account. */
export interface AccountSnapshot {
  readonly accountData: XrplJson;
  readonly objects: readonly XrplJson[];
}

/** Reads for one decision, all from one validated ledger (DESIGN 6.9, 6.17; IMPLEMENTATION P2.2-05). */
export interface LedgerSnapshot {
  readonly ledger: LedgerHeader;
  readonly accounts: Readonly<Record<string, AccountSnapshot>>; // keyed by classic address
  /** Accounts that do not exist at this ledger (only when the caller allowed it); never in `accounts`. */
  readonly missing?: readonly string[];
}

export interface ValidatedTx {
  readonly hash: XrplHash;
  readonly ledgerIndex: number;
  readonly closeTime: RippleTime;
  readonly tx: XrplJson;
  readonly meta: XrplJson;
}

/**
 * Final outcome of a reliable submit (IMPLEMENTATION 2.2). `validated` covers tes and tec (a tec uses the
 * sequence). `rejected` is a tem or tef that can never apply. `expired`: past LastLedgerSequence, not found.
 * Source: https://xrpl.org/docs/concepts/transactions/reliable-transaction-submission
 */
export type SubmitResult =
  | {
      readonly status: 'validated';
      readonly result: string;
      readonly hash: XrplHash;
      readonly ledgerIndex: number;
      readonly meta: XrplJson;
    }
  | { readonly status: 'rejected'; readonly result: string }
  | { readonly status: 'expired'; readonly lastLedgerSequence: number };

export interface LedgerFees {
  readonly baseFee: Drops;
  readonly reserveBase: Drops;
  readonly reserveInc: Drops;
}

/** Hides xrpl.js. Every read is from a validated ledger; nothing here returns unvalidated data. */
export interface LedgerPort {
  readonly network: z.infer<typeof Network>;
  validatedLedger(): Promise<LedgerHeader>;
  ledgerHeader(ledgerIndex: number): Promise<LedgerHeader>;
  /** All accounts read at one ledger index (the latest validated one when `ledgerIndex` is omitted). */
  snapshot(
    accounts: readonly XrplAddress[],
    ledgerIndex?: number,
    options?: { readonly allowMissing?: boolean },
  ): Promise<LedgerSnapshot>;
  tx(hash: XrplHash): Promise<ValidatedTx | undefined>;
  autofill(tx: XrplJson, signersCount: number): Promise<XrplJson>;
  submitReliable(txBlob: string): Promise<SubmitResult>;
  fees(): Promise<LedgerFees>;
}

/** Time for decisions: the validated ledger `close_time`, never `Date.now()` (IMPLEMENTATION 1.3 rule 5). */
export interface ClockPort {
  now(): Promise<LedgerHeader>;
}

/** Every ML-DSA use has its own context, always passed explicitly (DESIGN 6.13; IMPLEMENTATION P1.16-15). */
export type MlDsaContext =
  | 'legx/dsse/v1'
  | 'legx/pq-binding/v1'
  | 'legx/checkpoint/v1'
  | 'legx/api-request/v1' // signed API requests (OD-5, DESIGN 8.10)
  | 'legx/release/v1' // release-hash statements (task 4.10)
  | 'legx/frost-msg/v1' // FROST relay messages (DESIGN 6.3, 6.4)
  | 'legx/enrollment-pop/v1'; // a new enrollment key's proof of possession (keys.register)

/** Both halves, always together: there is no way to return one signature alone (IMPLEMENTATION P1.2-07). */
export interface HybridSignature {
  readonly ed25519: Uint8Array; // 64 bytes
  readonly mlDsa65: Uint8Array; // 3,309 bytes
  readonly keyIds: { readonly ed25519: KeyId; readonly mlDsa65: KeyId };
}

export interface HybridPublicKeys {
  readonly ed25519: Uint8Array; // 32 bytes
  readonly mlDsa65: Uint8Array; // 1,952 bytes
  readonly keyIds: { readonly ed25519: KeyId; readonly mlDsa65: KeyId };
}

/** Service keys (verifier attestation, verifier issuer, evidence log): KMS in production, FileSigner in the demo. */
export interface SignerPort {
  /** Signs the same bytes with Ed25519 and with ML-DSA-65 under `ctx`. Fails as a whole if either half fails. */
  signHybrid(msg: Uint8Array, ctx: MlDsaContext): Promise<HybridSignature>;
  publicKeys(): Promise<HybridPublicKeys>;
}

export interface CheckpointSignature {
  readonly ed25519: Uint8Array; // 64 bytes, the C2SP 0x01 line
  readonly mlDsa44: Uint8Array; // 2,420 bytes, the C2SP 0x06 line
  readonly keyIds: { readonly ed25519: KeyId; readonly mlDsa44: KeyId };
}

/**
 * The log's own checkpoint signer (DESIGN 6.13, 8.2): an Ed25519 key and an ML-DSA-44 key, separate from
 * SignerPort. Ed25519 signs the note body (type 0x01). ML-DSA-44 signs the binary CosignedSubtree with the
 * empty context (type 0x06, timestamped). Both are returned together, never one alone.
 * Source: https://c2sp.org/tlog-checkpoint and https://c2sp.org/signed-note
 */
export interface CheckpointSignerPort {
  signCheckpoint(input: {
    readonly noteBody: Uint8Array;
    readonly cosignedSubtree: Uint8Array;
  }): Promise<CheckpointSignature>;
  publicKeys(): Promise<{
    readonly ed25519: Uint8Array; // 32 bytes
    readonly mlDsa44: Uint8Array; // 1,312 bytes
    readonly keyIds: { readonly ed25519: KeyId; readonly mlDsa44: KeyId };
  }>;
}

/** The next chain position for a deal: the signer puts both inside the payload (DESIGN 8.1). */
export interface ChainHead {
  readonly nextSeq: number;
  readonly prevHash: Hex32;
}

export type AppendResult =
  | { readonly status: 'stored'; readonly seq: number; readonly leafHash: Hex32 } // also on an idempotent retry
  | { readonly status: 'seq_taken'; readonly head: ChainHead }; // lost the race: sign again on the new head

export interface StoredEvent {
  readonly seq: number;
  readonly leafHash: Hex32;
  readonly envelope: Uint8Array; // exact stored bytes, never re-serialized
  readonly logIndex?: number;
}

/** The evidence store (DESIGN 8.1, 8.9; IMPLEMENTATION 3.4). */
export interface EvidenceStorePort {
  head(dealId: DealId): Promise<ChainHead>;
  append(dealId: DealId, envelope: Uint8Array): Promise<AppendResult>;
  list(dealId: DealId, afterSeq: number, limit: number): Promise<readonly StoredEvent[]>;
  /** Records that live outside a deal (bar records), stored by SHA-256 of their exact bytes. */
  putRecord(envelope: Uint8Array): Promise<Hex32>;
  getRecord(sha256: Hex32): Promise<Uint8Array | undefined>;
}

/** WORM object storage (DESIGN 8.9): S3 Object Lock in production, a local folder in the demo. */
export interface ObjectStorePort {
  /** The same key with the same bytes is a no-op (`exists`); with other bytes it is refused (`conflict`). */
  put(
    key: string,
    bytes: Uint8Array,
    retainDays: number,
  ): Promise<{ readonly status: 'created' | 'exists'; readonly sha256: Hex32 } | { readonly status: 'conflict' }>;
  get(key: string): Promise<Uint8Array | undefined>;
  delete(key: string): Promise<{ readonly status: 'deleted' | 'retained' }>;
}

/** A C2SP signed-note checkpoint with the Ed25519 (0x01) and ML-DSA-44 (0x06) lines (DESIGN 8.2, 6.13). */
export interface Checkpoint {
  readonly origin: string;
  readonly treeSize: number;
  readonly rootHash: Hex32;
  readonly note: string;
}

/** RFC 9162 log: Trillian Tessera in production, the in-process tree in the demo. Source: https://c2sp.org/tlog-checkpoint */
export interface TransparencyLogPort {
  add(leaf: Uint8Array): Promise<{ readonly index: number }>;
  checkpoint(): Promise<Checkpoint>;
  inclusionProof(index: number, treeSize: number): Promise<readonly Hex32[]>;
  consistencyProof(fromSize: number, toSize: number): Promise<readonly Hex32[]>;
}

/** RFC 3161 time stamps over a checkpoint hash (DESIGN 8.4). Source: https://www.rfc-editor.org/rfc/rfc3161.html */
export interface TsaPort {
  timestamp(sha256: Hex32): Promise<{ readonly authority: string; readonly token: Uint8Array }>;
}

/** One bar registry lookup (DESIGN 6.16). The bar number is Secret: only its SHA-256 is ever stored. */
export interface BarLookup {
  readonly jurisdiction: string;
  readonly barNumber: Secret<string>;
}

export interface BarLookupResult {
  readonly status: 'active' | 'not_active' | 'not_found';
  readonly source: {
    readonly kind: z.infer<typeof BarSourceKind>;
    readonly url: string;
    readonly evidenceSha256: Hex32;
  };
}

/** Per-jurisdiction adapters, the `manual` adapter and the demo adapter (IMPLEMENTATION 3.3). */
export interface BarRegistryAdapter {
  readonly name: string;
  lookup(query: BarLookup): Promise<BarLookupResult>;
}

/** Network proof verification behind a port; core sees only the recorded result (IMPLEMENTATION 1.17, 3.11). */
export interface ZkVerifierPort {
  verify(request: ZkVerifyRequest): Promise<ZkVerification>;
}

/** One relay message with its position in the session queue. */
export interface RelayedMessage {
  readonly seq: number;
  readonly message: z.infer<typeof FrostSignedMessage>;
}

/**
 * The coordinator's FROST relay (IMPLEMENTATION 3.9): a message box that stores and forwards signed bytes.
 * It carries commitments, signature shares and sealed DKG packages only, never a secret share in the clear.
 */
export interface FrostRelayPort {
  send(message: z.infer<typeof FrostSignedMessage>): Promise<{ readonly seq: number }>;
  receive(
    sessionId: Hex32,
    recipient: z.infer<typeof FrostIdentifier>,
    afterSeq: number,
  ): Promise<readonly RelayedMessage[]>;
}
