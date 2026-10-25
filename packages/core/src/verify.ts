import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import * as xrpl from 'xrpl';

// Check one signature made by a 33-byte XRPL public key (DESIGN 6.8). Returns a boolean and never throws on bad
// input; only a wrong argument type (a programmer error) throws a TypeError.
// - Ed25519 (`ED` prefix): strict RFC 8032 over `msg` (`zip215: false`), so a ZIP-215-only signature fails.
// - secp256k1 (`02`/`03`): DER, low S, over SHA-512Half(`msg`), as rippled requires for fully canonical signatures.
// - any other key: false.
// Source: https://github.com/XRPLF/rippled/blob/develop/src/libxrpl/protocol/PublicKey.cpp (verify, publicKeyType)
// Source: https://github.com/paulmillr/noble-curves#ed25519 (the `zip215` option; default true is the lenient rule)
// Source: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7
export function verifyXrplKeySig(pubHex: string, msg: Uint8Array, sigHex: string): boolean {
  if (typeof pubHex !== 'string' || typeof sigHex !== 'string' || !(msg instanceof Uint8Array))
    throw new TypeError('verifyXrplKeySig(pubHex: string, msg: Uint8Array, sigHex: string)');
  let pub: Uint8Array;
  let sig: Uint8Array;
  try {
    pub = hexToBytes(pubHex);
    sig = hexToBytes(sigHex);
  } catch {
    return false;
  }
  if (pub.length !== 33) return false;
  if (pub[0] === 0xed) return sig.length === 64 && ed25519.verify(sig, msg, pub.subarray(1), { zip215: false });
  if (pub[0] === 0x02 || pub[0] === 0x03)
    return secp256k1.verify(sig, sha512(msg).subarray(0, 32), pub, { prehash: false, format: 'der', lowS: true });
  return false;
}

type Signer = { Account: string; SigningPubKey: string; TxnSignature: string };
const isSigner = (s: unknown): s is Signer => {
  const o = s as Partial<Signer> | undefined;
  return typeof o?.Account === 'string' && typeof o.SigningPubKey === 'string' && typeof o.TxnSignature === 'string';
};

// One Signer entry: its master key must derive to its account and sign the multi-signing message. Never throws.
// Only parsing is inside `try`; the verify result is never wrapped.
function signsForAccount(signer: Signer, tx: Record<string, unknown>): boolean {
  let msg: Uint8Array;
  try {
    if (xrpl.deriveAddress(signer.SigningPubKey) !== signer.Account) return false; // master-key signers only
    msg = hexToBytes(xrpl.encodeForMultiSigning(tx as never, signer.Account));
  } catch {
    return false;
  }
  return verifyXrplKeySig(signer.SigningPubKey, msg, signer.TxnSignature);
}

// Verify every signature in a multisigned blob (DESIGN 6.8). The signer set must equal `expected` exactly, with no
// duplicates and none missing. Hostile blobs give `ok: false`; nothing here throws.
// Source: https://github.com/XRPLF/rippled/blob/develop/src/libxrpl/protocol/STTx.cpp (multi-signing message)
// Source: https://xrpl.org/docs/concepts/accounts/multi-signing
export function verifyMultisigned(blob: string, expected: string[]): { ok: boolean; signers: string[] } {
  let tx: Record<string, unknown>;
  try {
    tx = xrpl.decode(blob);
  } catch {
    return { ok: false, signers: [] };
  }
  if (tx.SigningPubKey !== '' || !Array.isArray(tx.Signers)) return { ok: false, signers: [] };
  const { Signers, ...unsigned } = tx;
  const signers: string[] = [];
  for (const entry of Signers as { Signer?: unknown }[]) {
    const signer = entry?.Signer;
    if (!isSigner(signer) || !signsForAccount(signer, unsigned)) return { ok: false, signers };
    signers.push(signer.Account);
  }
  const uniq = new Set(signers);
  const want = new Set(expected);
  const exact = uniq.size === signers.length && uniq.size === want.size && [...want].every((a) => uniq.has(a));
  return { ok: exact, signers };
}
