// Key pinning before a DKG (DESIGN 6.3, P4.7-13, T-U-29): the coordinator cannot choose whose keys a holder talks to.
//  - The client's phone and second authenticator pin each other with a QR code (both key hashes plus a six-digit
//    short authentication string shown on both screens), through core's `qrPin` / `verifyQrPin`.
//  - A service holder (the recovery agent, the firm HSM) is accepted only if its key is in its signed list whose hash
//    its own XRPL account anchored on the ledger (core's `verifyServiceKeyList`).
//  - This device's own key is pinned because it made it.
// Every refusal names the key it refuses, so the screen can show it.
// Source: DESIGN.md section 6.3; https://frost.zfnd.org/tutorial/dkg.html (participants must authenticate each other)

import { FrostError } from '@legx/core/frost';
import type { PinCheck } from '@legx/core/frostDkg';
import {
  EnrollmentRegistry,
  enrollmentKeyHash,
  type QrPin,
  qrPin,
  type RegistryEntry,
  type ServiceKeyList,
  verifyQrPin,
  verifyServiceKeyList,
} from '@legx/core/frostSetup';
import { equalBytes } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { type HolderInfo, hex, unhex } from './wire.ts';

/** A key this device will not use, by name and fingerprint (the screen shows both). */
export class KeyRefused extends Error {
  readonly code = 'KEY_REFUSED';
  readonly label: string;
  readonly fingerprint: string;
  readonly reason: string;
  constructor(h: Pick<HolderInfo, 'label' | 'edPub'>, reason: string) {
    super(`Refused the key of ${h.label} (${fingerprint(h.edPub)}): ${reason}`);
    this.name = 'KeyRefused';
    this.label = h.label;
    this.fingerprint = fingerprint(h.edPub);
    this.reason = reason;
  }
}

/** Short, readable fingerprint of a key: the first 8 bytes of its SHA-256, in groups of four hex digits. */
export const fingerprint = (key: Uint8Array): string => (hex(sha256(key).slice(0, 8)).match(/..../g) ?? []).join(' ');

const entry = (h: HolderInfo): RegistryEntry => ({ holder: h.keyId, role: h.role, edPub: h.edPub });

/** The QR code this device shows to its sibling: its own key hash, the sibling's, and the SAS. */
export function devicePinCode(mine: HolderInfo, peer: HolderInfo): { qr: string; sas: string } {
  const p = qrPin(entry(mine), entry(peer));
  return { qr: JSON.stringify({ v: 1, a: hex(p.hashA), b: hex(p.hashB), sas: p.sas }), sas: p.sas };
}

/** The sibling scanned `qr` and typed (or confirmed) the SAS it saw; refuses a code for any other key pair. */
export function checkDevicePin(qr: string, peer: HolderInfo, mine: HolderInfo, sasShown: string): void {
  try {
    const o = JSON.parse(qr) as { v: number; a: string; b: string; sas: string };
    const pin: QrPin = { hashA: unhex(o.a), hashB: unhex(o.b), sas: o.sas };
    if (o.v !== 1) throw new Error('version');
    verifyQrPin(pin, entry(peer), entry(mine), sasShown);
  } catch {
    throw new KeyRefused(peer, 'the scanned code is not for this key');
  }
}

/** A service holder's key must be in its anchored, signed list, with the same key bytes and role. */
export function checkServiceKey(
  h: HolderInfo,
  list: ServiceKeyList,
  anchor: { account: string; hash: Uint8Array },
  expected: { serviceAccount: string; opsAccount: string },
): void {
  let keys: RegistryEntry[];
  try {
    keys = verifyServiceKeyList(list, anchor, expected);
  } catch (e) {
    throw new KeyRefused(h, e instanceof FrostError ? `its key list fails (${e.code})` : 'its key list fails');
  }
  if (!keys.some((k) => k.holder === h.keyId && k.role === h.role && equalBytes(k.edPub, h.edPub)))
    throw new KeyRefused(h, 'not in the anchored key list');
}

/**
 * The `PinCheck` the DKG runs before round 1: every holder must have been pinned here (own key, QR, or anchored list)
 * and its key hash logged (DESIGN 6.3). A swapped key is refused under the name of the holder whose role it claims.
 */
export function keyDirectory(pinned: readonly HolderInfo[], logged: (keyHash: Uint8Array) => boolean = () => true) {
  const registry = new EnrollmentRegistry();
  for (const h of pinned) {
    registry.pin(entry(h));
    if (logged(enrollmentKeyHash(entry(h)))) registry.markLogged(enrollmentKeyHash(entry(h)));
  }
  const check: PinCheck = (dir) => {
    for (const h of dir.holders) {
      try {
        registry.require(h);
      } catch (e) {
        const reason =
          e instanceof FrostError && e.code === 'KEY_NOT_LOGGED' ? 'not in the evidence log' : 'not pinned';
        const shown = pinned.find((p) => p.keyId === h.holder) ?? pinned.find((p) => p.role === h.role);
        throw new KeyRefused({ label: shown?.label ?? h.holder, edPub: h.edPub }, reason);
      }
    }
  };
  return check;
}
