// Signed-contract seal and the NFTokenMint memo (DESIGN 6.12, W1). Only the two lawyers sign the contract, each with
// the lawyer slot key that also sits on the deal wallet's signer list; the contract names the wallet (D16, D17).
import { equalBytes } from '@noble/curves/utils.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { tupleHash } from './dealcore.ts';
import { verifyXrplKeySig } from './verify.ts';

export type LawyerRole = 'LA' | 'LB';

/** What the deal seal fixes about the contract: the sealed lawyer slot keys are 33-byte XRPL keys (`ED` + 64 hex). */
export interface ContractTerms {
  contractRoot: Uint8Array;
  walletAddress: string;
  lawyerPubA: string;
  lawyerPubB: string;
}
export interface ContractSigs {
  sigLA: Uint8Array;
  sigLB: Uint8Array;
}
/** The decoded mint memo: both lawyer keys (uppercase XRPL hex) and their 64-byte Ed25519 signatures. */
export interface MintMemo extends ContractSigs {
  lawyerPubA: string;
  lawyerPubB: string;
}

export type SignedContractCode =
  | 'MEMO_MALFORMED'
  | 'URI_MALFORMED'
  | 'KEYS_NOT_SEALED'
  | 'SIG_LA_INVALID'
  | 'SIG_LB_INVALID'
  | 'SEAL_MISMATCH';
export type Check = { ok: true } | { ok: false; code: SignedContractCode };

const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();
const MEMO_VERSION = 0x01;
const MEMO_BYTES = 195; // 1 + 33 + 64 + 33 + 64
const URI_PREFIX = 'legx:sc:v1:';

/** `MemoType` of the mint memo: hex(utf8("legx/contract-sigs/v1")), uppercase. */
export const MINT_MEMO_TYPE = up(utf8ToBytes('legx/contract-sigs/v1'));

// Source: DESIGN 6.12 (contractSigMsg); encoding rules: DESIGN 6 "Encoding rules for every tuple hash".
export function contractSigMsg(contractRoot: Uint8Array, walletAddress: string, role: LawyerRole): Uint8Array {
  return tupleHash('legx/contract-sign/v1', [contractRoot, utf8ToBytes(walletAddress), utf8ToBytes(role)]);
}

/**
 * Signs the contract for `role` with `sign` (a FROST session of the lawyer slot, whose output is a plain Ed25519
 * signature, DESIGN 6.4) and refuses a signature that does not verify strictly under the sealed lawyer key.
 */
export async function signContract(
  sign: (msg: Uint8Array) => Promise<Uint8Array>,
  terms: ContractTerms,
  role: LawyerRole,
): Promise<Uint8Array> {
  const msg = contractSigMsg(terms.contractRoot, terms.walletAddress, role);
  const sig = await sign(msg);
  const pub = role === 'LA' ? terms.lawyerPubA : terms.lawyerPubB;
  if (!verifyXrplKeySig(pub, msg, up(sig))) throw new Error(`contract signature for ${role} does not verify`);
  return sig;
}

/** `hex(utf8("legx:sc:v1:" + upperHex(seal)))`, uppercase. Source: DESIGN 6.12 (NFT URI). */
export function nftUri(seal: Uint8Array): string {
  return up(utf8ToBytes(URI_PREFIX + up(seal)));
}

/** `MemoData` = hex(0x01 || lawyerPubA(33) || sigLA(64) || lawyerPubB(33) || sigLB(64)), 195 bytes, uppercase. */
export function encodeMintMemo(m: MintMemo): string {
  const data = concatBytes(
    new Uint8Array([MEMO_VERSION]),
    hexToBytes(m.lawyerPubA),
    m.sigLA,
    hexToBytes(m.lawyerPubB),
    m.sigLB,
  );
  if (data.length !== MEMO_BYTES) throw new Error(`mint memo must be ${MEMO_BYTES} bytes, got ${data.length}`);
  return up(data);
}

/** Parses `MemoData` (uppercase hex, as rippled returns it). Keys must be Ed25519 (`ED` prefix): slot keys are. */
export function decodeMintMemo(memoHex: string): { ok: true; value: MintMemo } | { ok: false; code: 'MEMO_MALFORMED' } {
  if (!new RegExp(`^(?:[0-9A-F]{2}){${MEMO_BYTES}}$`).test(memoHex)) return { ok: false, code: 'MEMO_MALFORMED' };
  const b = hexToBytes(memoHex);
  if (b[0] !== MEMO_VERSION || b[1] !== 0xed || b[98] !== 0xed) return { ok: false, code: 'MEMO_MALFORMED' };
  return {
    ok: true,
    value: {
      lawyerPubA: up(b.subarray(1, 34)),
      sigLA: b.slice(34, 98),
      lawyerPubB: up(b.subarray(98, 131)),
      sigLB: b.slice(131, 195),
    },
  };
}

// Source: DESIGN 6.12 (signedContractSeal).
function sealOf(t: ContractTerms, s: ContractSigs): Uint8Array {
  return tupleHash('legx/signed-contract/v1', [
    t.contractRoot,
    utf8ToBytes(t.walletAddress),
    hexToBytes(t.lawyerPubA),
    s.sigLA,
    hexToBytes(t.lawyerPubB),
    s.sigLB,
  ]);
}

/** The seal, the NFT URI and the mint `MemoData` for one signed contract. Pure: it does not verify the signatures. */
export function buildSignedContractSeal(terms: ContractTerms, sigs: ContractSigs) {
  const seal = sealOf(terms, sigs);
  const memoHex = encodeMintMemo({ lawyerPubA: terms.lawyerPubA, lawyerPubB: terms.lawyerPubB, ...sigs });
  return { seal, uriHex: nftUri(seal), memoHex };
}

// The URI must be exactly hex(utf8("legx:sc:v1:" + 64 uppercase hex)), all uppercase.
function sealFromUri(uriHex: string): Uint8Array | undefined {
  if (!/^(?:[0-9A-F]{2})+$/.test(uriHex)) return undefined;
  const text = new TextDecoder().decode(hexToBytes(uriHex));
  const m = /^legx:sc:v1:([0-9A-F]{64})$/.exec(text);
  return m?.[1] === undefined ? undefined : hexToBytes(m[1]);
}

const sameKey = (a: string, b: string) => {
  try {
    return equalBytes(hexToBytes(a), hexToBytes(b));
  } catch {
    return false;
  }
};

/**
 * Checks a signed contract against the sealed lawyer keys (DESIGN 6.12): the memo carries exactly the sealed keys,
 * both signatures verify strictly, and the URI holds the recomputed seal. The caller must take `memoHex` and `uriHex`
 * from the validated mint transaction on the ledger, never from its own database (IMPLEMENTATION 1.5).
 */
export function verifySignedContract(terms: ContractTerms, memoHex: string, uriHex: string): Check {
  const memo = decodeMintMemo(memoHex);
  if (!memo.ok) return memo;
  const m = memo.value;
  if (!sameKey(m.lawyerPubA, terms.lawyerPubA) || !sameKey(m.lawyerPubB, terms.lawyerPubB))
    return { ok: false, code: 'KEYS_NOT_SEALED' };
  const { contractRoot: root, walletAddress: wallet } = terms;
  if (!verifyXrplKeySig(m.lawyerPubA, contractSigMsg(root, wallet, 'LA'), up(m.sigLA)))
    return { ok: false, code: 'SIG_LA_INVALID' };
  if (!verifyXrplKeySig(m.lawyerPubB, contractSigMsg(root, wallet, 'LB'), up(m.sigLB)))
    return { ok: false, code: 'SIG_LB_INVALID' };
  const uriSeal = sealFromUri(uriHex);
  if (!uriSeal) return { ok: false, code: 'URI_MALFORMED' };
  if (!equalBytes(uriSeal, sealOf(terms, m))) return { ok: false, code: 'SEAL_MISMATCH' };
  return { ok: true };
}
