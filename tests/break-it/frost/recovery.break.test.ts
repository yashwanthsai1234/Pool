// Break-it (task 5.7): FROST recovery rules attacked through core's pure functions (DESIGN 6.4 "Recovery rules").
import { describe, expect, it } from 'vitest';
import { ed25519 } from '../../../packages/core/node_modules/@noble/curves/ed25519.js';
import { bytesToHex, utf8ToBytes } from '../../../packages/core/node_modules/@noble/hashes/utils.js';
import { deriveAddress } from '../../../packages/core/node_modules/xrpl/dist/npm/index.js';
import {
  RECOVERY_DELAY_MS,
  recoveryCancel,
  recoveryCancelMessage,
  recoveryStart,
} from '../../../packages/core/src/frostRules.ts';

const opsSecret = ed25519.utils.randomSecretKey();
const opsPub = new Uint8Array([0xed, ...ed25519.getPublicKey(opsSecret)]);
const opsAccount = deriveAddress(bytesToHex(opsPub).toUpperCase());

describe('I-S-F1 lawyer recovery request is not bound to the deal, slot, new key or time', () => {
  // Source: DESIGN 6.4 "Lawyer recovery starts only with a request signed by the firm's operations account";
  // https://www.rfc-editor.org/rfc/rfc9591#section-7.7 (a signer must know exactly what it authorizes)
  it('refuses an operations-account signature over bytes that are not a recovery request for this deal and slot', () => {
    // Any message the operations key ever signed (here: unrelated bytes; on the ledger: any single-signed transaction's
    // signing data and its public TxnSignature) must not start a recovery of slot LA.
    const request = utf8ToBytes('some unrelated message the firm signed last year');
    const sig = ed25519.sign(request, opsSecret);
    expect(() => recoveryStart({ kind: 'lawyer', slot: 'LA', at: 1_000, request, sig, opsPub, opsAccount })).toThrow();
  });
});

describe('I-S-F2 the recovery cancel statement is not bound to the deal or the recovery', () => {
  // Source: DESIGN 6.4 "The old device can cancel during the delay"; DESIGN 6 encoding rules (domain separation)
  it('two different recoveries that start at the same time on the same slot have different cancel messages', () => {
    const client = (identifier: string) =>
      recoveryStart({
        kind: 'client',
        slot: 'A',
        at: 5_000_000,
        proof: { identifier, provedAt: 5_000_000 },
        onboardingIdentifier: identifier,
        faceMatch: true,
      }).state;
    const dealX = client('scoped-id-deal-x');
    const dealY = client('scoped-id-deal-y');
    // A cancel signed for one recovery would also cancel the other.
    expect(bytesToHex(recoveryCancelMessage(dealX))).not.toBe(bytesToHex(recoveryCancelMessage(dealY)));
    const dev = ed25519.utils.randomSecretKey();
    const devPub = new Uint8Array([0xed, ...ed25519.getPublicKey(dev)]);
    const sig = ed25519.sign(recoveryCancelMessage(dealX), dev);
    expect(() => recoveryCancel(dealY, 5_000_000 + RECOVERY_DELAY_MS / 2, { sig, oldDevicePub: devPub })).toThrow();
  });
});
