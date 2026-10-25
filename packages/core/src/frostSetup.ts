// The key directory (DESIGN 6.3): enrollment keys are pinned out of band, never chosen by the coordinator.
//  - A client's own two devices pin each other with a QR code (both key hashes plus a short authentication string).
//  - A service holder's keys come from a signed list whose hash its own XRPL account anchored on the ledger;
//    a firm's list must be signed by the firm's operations account.
//  - The `enrollment_key` registry is append-only, and a key is usable only after its hash is in the evidence log.
// Source: DESIGN.md section 6.3; https://frost.zfnd.org/tutorial/dkg.html (participants must authenticate each other)
import { equalBytes } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { deriveAddress } from 'xrpl';
import { tupleHash } from './dealcore.ts';
import { type Directory, FrostError, type Role } from './frost.ts';
import { verifyXrplKeySig } from './verify.ts';

export type RegistryEntry = { holder: string; role: Role; edPub: Uint8Array };

/** The hash that enters the evidence log before a key is used. */
export const enrollmentKeyHash = (e: RegistryEntry): Uint8Array =>
  tupleHash('legx/enrollment-key/v1', [utf8ToBytes(e.holder), utf8ToBytes(e.role), e.edPub]);

/** In-memory form of the append-only `enrollment_key` table (Phase 3 runs the same rules on Postgres). */
export class EnrollmentRegistry {
  readonly #entries = new Map<string, RegistryEntry>();
  readonly #logged = new Set<string>();

  /** Pins a key. Pinning the same key again is a no-op; a different key for the same holder and role is refused. */
  pin(entry: RegistryEntry): void {
    const k = `${entry.holder}\u0000${entry.role}`;
    const old = this.#entries.get(k);
    if (old && !equalBytes(old.edPub, entry.edPub)) throw new FrostError('KEY_CHANGED', entry.holder);
    this.#entries.set(k, { ...entry, edPub: entry.edPub.slice() });
  }

  remove(_holder: string, _role: Role): never {
    throw new FrostError('REGISTRY_APPEND_ONLY');
  }

  /** Records that the key's hash entered the evidence log (and so a ledger checkpoint). */
  markLogged(keyHash: Uint8Array): void {
    this.#logged.add(bytesToHex(keyHash));
  }

  /** Throws unless this exact key is pinned for the holder and role, and logged. */
  require(entry: RegistryEntry): void {
    const pinned = this.#entries.get(`${entry.holder}\u0000${entry.role}`);
    if (!pinned || !equalBytes(pinned.edPub, entry.edPub)) throw new FrostError('KEY_NOT_PINNED', entry.holder);
    if (!this.#logged.has(bytesToHex(enrollmentKeyHash(entry)))) throw new FrostError('KEY_NOT_LOGGED', entry.holder);
  }

  /** The PinCheck the DKG runs before it uses any message: every holder in the directory must be pinned. */
  readonly check = (dir: Directory): void => {
    for (const h of dir.holders) this.require(h);
  };
}

// ---------- QR pinning between a client's two devices ----------

export type QrPin = { hashA: Uint8Array; hashB: Uint8Array; sas: string };

/** Six-digit short authentication string over both key hashes, shown on both screens. */
const sasOf = (hashA: Uint8Array, hashB: Uint8Array): string => {
  const h = tupleHash('legx/pin-sas/v1', [hashA, hashB]);
  return String(new DataView(h.buffer).getUint32(0) % 1_000_000).padStart(6, '0');
};

/** The QR code device A shows: its key hash, the key hash it received from B, and the SAS. */
export function qrPin(a: RegistryEntry, b: RegistryEntry): QrPin {
  const hashA = enrollmentKeyHash(a);
  const hashB = enrollmentKeyHash(b);
  return { hashA, hashB, sas: sasOf(hashA, hashB) };
}

/** Device B checks the scanned code against the key A sent and its own key; a wrong code fails PIN_MISMATCH. */
export function verifyQrPin(qr: QrPin, peer: RegistryEntry, mine: RegistryEntry, sasShown: string): void {
  if (
    !equalBytes(qr.hashA, enrollmentKeyHash(peer)) ||
    !equalBytes(qr.hashB, enrollmentKeyHash(mine)) ||
    qr.sas !== sasOf(qr.hashA, qr.hashB) ||
    sasShown !== qr.sas
  ) {
    throw new FrostError('PIN_MISMATCH', 'QR code');
  }
}

// ---------- signed key lists of service holders ----------

export type ServiceKeyList = { bytes: Uint8Array; signerPub: Uint8Array; sig: Uint8Array };

/** What the operations account signs: a domain-separated hash of the exact list bytes. */
export const serviceKeyListMessage = (bytes: Uint8Array): Uint8Array =>
  tupleHash('legx/service-key-list/v1', [sha256(bytes)]);

/**
 * Checks a service holder's key list: its hash must be the one the service's own XRPL account anchored on the
 * ledger (PIN_MISMATCH otherwise), and it must be signed by the firm's operations account (LIST_SIGNER_WRONG),
 * whose master key may be Ed25519 or secp256k1 (DESIGN 6.14). The list is JSON: {"keys": [{"holder", "role", "ed25519": "ED..."}]}.
 */
export function verifyServiceKeyList(
  list: ServiceKeyList,
  anchor: { account: string; hash: Uint8Array },
  expected: { serviceAccount: string; opsAccount: string },
): RegistryEntry[] {
  if (anchor.account !== expected.serviceAccount || !equalBytes(sha256(list.bytes), anchor.hash)) {
    throw new FrostError('PIN_MISMATCH', 'anchored list hash');
  }
  const pubHex = bytesToHex(list.signerPub).toUpperCase();
  const signer = list.signerPub.length === 33 ? deriveAddress(pubHex) : '';
  if (
    signer !== expected.opsAccount ||
    !verifyXrplKeySig(pubHex, serviceKeyListMessage(list.bytes), bytesToHex(list.sig))
  ) {
    throw new FrostError('LIST_SIGNER_WRONG', signer);
  }
  try {
    const parsed = JSON.parse(new TextDecoder().decode(list.bytes)) as {
      keys: { holder: string; role: Role; ed25519: string }[];
    };
    return parsed.keys.map((k) => ({ holder: k.holder, role: k.role, edPub: hexToBytes(k.ed25519.toLowerCase()) }));
  } catch {
    throw new FrostError('INPUT_INVALID', 'key list');
  }
}
