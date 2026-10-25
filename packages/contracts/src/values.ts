// Value types shared by every lane. Hex is lowercase for internal hashes and uppercase for
// ledger-facing values (build/TASKGRAPH.md conventions). Byte blobs larger than 64 bytes are base64.
import { sha256 } from '@noble/hashes/sha2.js';
import { z } from 'zod';

const U32_MAX = 4294967295;

/** Lowercase hex of exactly `n` bytes. */
export const HexBytes = (n: number) => z.string().regex(new RegExp(`^[0-9a-f]{${2 * n}}$`));
/** Lowercase hex of `min` to `max` bytes. */
export const HexBytesRange = (min: number, max: number) =>
  z.string().regex(new RegExp(`^(?:[0-9a-f]{2}){${min},${max}}$`));

/** 32-byte internal hash or commitment (SHA-256, tupleHash), lowercase. */
export const Hex32 = HexBytes(32).brand<'Hex32'>();
export type Hex32 = z.infer<typeof Hex32>;

/** Ledger-facing 32-byte hash (transaction hash, ledger hash), uppercase as rippled returns it. */
export const XrplHash = z
  .string()
  .regex(/^[0-9A-F]{64}$/)
  .brand<'XrplHash'>();
export type XrplHash = z.infer<typeof XrplHash>;

/** NFTokenID, uppercase hex. Source: https://xrpl.org/docs/references/protocol/data-types/nftoken */
export const NFTokenId = z
  .string()
  .regex(/^[0-9A-F]{64}$/)
  .brand<'NFTokenId'>();

/** Ed25519 signature, 64 bytes, lowercase hex. */
export const Ed25519SigHex = HexBytes(64).brand<'Ed25519Sig'>();
/** A signature by an XRPL account key: Ed25519 (64 bytes) or secp256k1 DER (up to 72 bytes). Source: DESIGN 6.8 */
export const XrplKeySigHex = HexBytesRange(64, 72).brand<'XrplKeySig'>();
/** A 32-byte compressed Edwards point or scalar (FROST commitments, shares, verifying shares). */
export const Hex32Point = HexBytes(32).brand<'Point32'>();

const BASE58_XRPL = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

/** Decodes an XRPL base58 string, or returns undefined on a character outside the alphabet. */
function base58Decode(s: string): Uint8Array | undefined {
  let n = 0n;
  for (const ch of s) {
    const d = BASE58_XRPL.indexOf(ch);
    if (d < 0) return undefined;
    n = n * 58n + BigInt(d);
  }
  const out: number[] = [];
  while (n > 0n) {
    out.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const ch of s) {
    if (ch !== BASE58_XRPL[0]) break;
    out.unshift(0);
  }
  return Uint8Array.from(out);
}

/**
 * Classic address check: version byte 0x00, 20-byte AccountID, 4-byte double-SHA-256 checksum.
 * Source: https://xrpl.org/docs/references/protocol/data-types/base58-encodings
 * Source: https://xrpl.org/docs/concepts/accounts/addresses#address-encoding
 */
function isClassicAddress(s: string): boolean {
  const b = base58Decode(s);
  if (b?.length !== 25 || b[0] !== 0) return false;
  const check = sha256(sha256(b.subarray(0, 21)));
  return b[21] === check[0] && b[22] === check[1] && b[23] === check[2] && b[24] === check[3];
}

/** Classic XRPL address with a valid checksum. */
export const XrplAddress = z
  .string()
  .regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/)
  .refine(isClassicAddress, 'bad address checksum')
  .brand<'XrplAddress'>();
export type XrplAddress = z.infer<typeof XrplAddress>;

/**
 * XRPL public key, uppercase: `ED` + 32-byte Ed25519 key, or `02`/`03` + 32-byte compressed secp256k1 key.
 * Source: https://xrpl.org/docs/concepts/accounts/cryptographic-keys
 */
export const XrplPublicKey = z
  .string()
  .regex(/^(?:ED|02|03)[0-9A-F]{64}$/)
  .brand<'XrplPublicKey'>();
export type XrplPublicKey = z.infer<typeof XrplPublicKey>;

/** Slot keys are Ed25519 FROST group keys (DESIGN 6.4): `ED` + 64 hex only. */
export const XrplEd25519PublicKey = z
  .string()
  .regex(/^ED[0-9A-F]{64}$/)
  .brand<'XrplPublicKey'>();

/** XRP amount in drops: decimal string, no leading zeros, at most 10^17 (100 billion XRP). Source: https://xrpl.org/docs/references/protocol/data-types/basic-data-types#specifying-currency-amounts */
export const Drops = z
  .string()
  .regex(/^(?:0|[1-9][0-9]{0,16}|100000000000000000)$/)
  .brand<'Drops'>();
export type Drops = z.infer<typeof Drops>;

/** Seconds since the Ripple epoch (2000-01-01T00:00:00Z), an unsigned 32-bit integer. Source: https://xrpl.org/docs/references/protocol/data-types/basic-data-types#specifying-time */
export const RippleTime = z.int().min(0).max(U32_MAX).brand<'RippleTime'>();
export type RippleTime = z.infer<typeof RippleTime>;

/** Validated ledger index (UInt32, at least 1). */
export const LedgerIndex = z.int().min(1).max(U32_MAX);

/** Account Sequence or TicketSequence (UInt32). */
export const SequenceNumber = z.int().min(1).max(U32_MAX);

/** Payout address in the seal: `rAddr` or `rAddr:tag`, tag 0..4294967295 in base 10 with no leading zeros (DESIGN 6.6). */
export const Payout = z
  .string()
  .regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}(?::(?:0|[1-9][0-9]{0,9}))?$/)
  .refine((s) => {
    const [addr = '', tag] = s.split(':');
    return isClassicAddress(addr) && (tag === undefined || Number(tag) <= U32_MAX);
  }, 'bad payout address or tag')
  .brand<'Payout'>();

/** Signer role in a deal (DESIGN 9 `deal_key.role`); binding sides A, LA, B, LB. */
export const Role = z.enum(['alice', 'lawyerA', 'bob', 'lawyerB']);
export type Role = z.infer<typeof Role>;
export const LawyerRole = z.enum(['lawyerA', 'lawyerB']);
/** Actor of an evidence event (DESIGN 8.1). */
export const ActorRole = z.enum([
  'alice',
  'bob',
  'lawyerA',
  'lawyerB',
  'coordinator',
  'watcher',
  'verifier',
  'recovery-agent', // its own FROST and recovery events only (DESIGN 6.4)
  'firm-hsm', // its own FROST audit events only (DESIGN 6.4)
]);

/** Client side. */
export const Side = z.enum(['A', 'B']);
export type Side = z.infer<typeof Side>;
/** Signer slot (DESIGN 6.4). */
export const Slot = z.enum(['A', 'LA', 'B', 'LB']);
export type Slot = z.infer<typeof Slot>;
export const LawyerSlot = z.enum(['LA', 'LB']);

/** Identity method per client (DESIGN 6.2, 6.10). */
export const IdMethod = z.enum(['zkpassport', 'nfc-chip']);
/** Identity policy in the seal (DESIGN 6.10). */
export const IdentityPolicy = z.enum(['zk', 'zk-or-chip', 'chip']);

/** Deal states (DESIGN 5.1, 9). */
export const DealState = z.enum([
  'DRAFT',
  'CONTRACT_SIGNED',
  'SHELL_OPEN',
  'QUARANTINED',
  'KEYS_READY',
  'WALLET_LOCKED',
  'VERIFIED',
  'FUNDED',
  'PAID_OUT',
  'REFUNDED',
  'DISPUTED',
  'EXPIRED',
  'CLOSED',
]);
export const Network = z.enum(['standalone', 'testnet', 'devnet', 'mainnet']);
/** Run profile (IMPLEMENTATION section 3). */
export const Profile = z.enum(['production', 'demo']);

/** UUIDv7 (RFC 9562). Source: https://www.rfc-editor.org/rfc/rfc9562.html */
export const DealId = z.uuid({ version: 'v7' }).brand<'DealId'>();
export type DealId = z.infer<typeof DealId>;
export const Uuid7 = z.uuid({ version: 'v7' });

/** Key identifier in the enrollment key registry (DESIGN 6.3, 9 `enrollment_key.key_id`). */
export const KeyId = z
  .string()
  .regex(/^[A-Za-z0-9._:/#-]{1,128}$/)
  .brand<'KeyId'>();
export type KeyId = z.infer<typeof KeyId>;

/** ISO 3166 alpha-2 code with an optional subdivision (`US-CA`); never contains `:` (DESIGN 6.2). */
export const Jurisdiction = z.string().regex(/^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/);

/** Standard padded base64 of exactly `n` bytes. Source: https://www.rfc-editor.org/rfc/rfc4648#section-4 */
export const Base64Bytes = (n: number) => {
  const full = Math.floor(n / 3);
  const tail = n % 3 === 0 ? '' : n % 3 === 1 ? '[A-Za-z0-9+/]{2}==' : '[A-Za-z0-9+/]{3}=';
  return z.string().regex(new RegExp(`^(?:[A-Za-z0-9+/]{4}){${full}}${tail}$`));
};
/** Standard padded base64 of any length up to `maxBytes`. */
export const Base64 = (maxBytes: number) =>
  z
    .base64()
    .max(4 * Math.ceil(maxBytes / 3))
    .brand<'Base64'>();

/** ML-DSA-65 sizes from FIPS 204, table 2. Source: https://csrc.nist.gov/pubs/fips/204/final */
export const MlDsa65PublicKey = Base64Bytes(1952).brand<'MlDsa65PublicKey'>();
export const MlDsa65Signature = Base64Bytes(3309).brand<'MlDsa65Signature'>();
/** Ed25519 signature in a DSSE envelope (base64, 64 bytes). */
export const Ed25519SigB64 = Base64Bytes(64).brand<'Ed25519SigB64'>();
/** Raw Ed25519 public key (32 bytes, lowercase hex) of an enrollment key. */
export const Ed25519PublicKeyHex = HexBytes(32).brand<'Ed25519PublicKey'>();

/** Ethereum-style 0x hex values recorded from ZKPassport (DESIGN 6.10 trust record), lowercase. */
export const EthHash = z
  .string()
  .regex(/^0x[0-9a-f]{64}$/)
  .brand<'EthHash'>();
export const EthAddress = z
  .string()
  .regex(/^0x[0-9a-f]{40}$/)
  .brand<'EthAddress'>();

/** A recent validated ledger, read at check time (DESIGN 6.15 `ledger_anchor`, 6.16 `checked_at_ledger`). */
export const LedgerAnchor = z.strictObject({ ledger_index: LedgerIndex, ledger_hash: XrplHash });
