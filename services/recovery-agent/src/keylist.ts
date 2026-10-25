// The agent's key directory entry (DESIGN 6.3): a service holder publishes its enrollment keys in a signed list at a
// well-known HTTPS address and anchors the list's hash on the ledger from its OWN XRPL account, as a memo. A client's
// app accepts a key only if it is in the list, the list hash equals that anchor, and the anchor came from the agent's
// account: so the coordinator cannot swap in a key of its own. The checks are task 1.15's `verifyServiceKeyList`.
// Source: DESIGN 6.3; https://xrpl.org/docs/references/protocol/transactions/common-fields (Memos: MemoType, MemoData)
import type { LedgerPort } from '@legx/contracts/ports';
import { bytesToHex, hexToBytes, sha256, utf8ToBytes } from '@legx/core/dealcore';
import { FrostError } from '@legx/core/frost';
import {
  type RegistryEntry,
  type ServiceKeyList,
  serviceKeyListMessage,
  verifyServiceKeyList,
} from '@legx/core/frostSetup';
import { ed25519 } from '@noble/curves/ed25519.js';
import { equalBytes } from '@noble/curves/utils.js';

export const KEY_LIST_MEMO_TYPE = bytesToHex(utf8ToBytes('legx/service-key-list/v1')).toUpperCase();

export interface ListedKey {
  readonly holder: string;
  readonly role: 'recovery-agent';
  /** XRPL form: `ED` and 64 uppercase hex characters. */
  readonly ed25519: string;
  /** Base64 of the ML-DSA-65 public key. */
  readonly mldsa65: string;
}

/** The list bytes, exactly as they are signed, hashed and served. */
export const buildKeyList = (keys: readonly ListedKey[]): Uint8Array => utf8ToBytes(JSON.stringify({ keys }));

/** Signs the list with the agent's XRPL account key (an Ed25519 seed). */
export function signKeyList(bytes: Uint8Array, accountSecret: Uint8Array): ServiceKeyList {
  return {
    bytes,
    signerPub: new Uint8Array([0xed, ...ed25519.getPublicKey(accountSecret)]),
    sig: ed25519.sign(serviceKeyListMessage(bytes), accountSecret),
  };
}

/** The memo the agent's account puts on a transaction to anchor a list. */
export const anchorMemo = (bytes: Uint8Array) => ({
  Memo: { MemoType: KEY_LIST_MEMO_TYPE, MemoData: bytesToHex(sha256(bytes)).toUpperCase() },
});

/** Reads the anchor from a validated transaction: which account made it, and the hash in its memo. */
export async function readAnchor(
  ledger: Pick<LedgerPort, 'tx'>,
  txHash: string,
): Promise<{ account: string; hash: Uint8Array } | undefined> {
  const t = await ledger.tx(txHash as never);
  if (t?.meta.TransactionResult !== 'tesSUCCESS') return undefined;
  const memos = (t.tx.Memos ?? []) as { Memo?: { MemoType?: string; MemoData?: string } }[];
  const hit = memos.find(
    (m) => m.Memo?.MemoType?.toUpperCase() === KEY_LIST_MEMO_TYPE && /^[0-9A-Fa-f]{64}$/.test(m.Memo?.MemoData ?? ''),
  );
  return hit
    ? { account: t.tx.Account as string, hash: hexToBytes((hit.Memo as { MemoData: string }).MemoData.toLowerCase()) }
    : undefined;
}

/**
 * The client app's side: accepts `key` only if the list is signed by the agent's account, its hash is the one the
 * agent's own account anchored, and the key is in the list. A missing anchor is a refusal, not a pass.
 */
export function acceptServiceKey(input: {
  list: ServiceKeyList;
  anchor: { account: string; hash: Uint8Array } | undefined;
  agentAccount: string;
  key: RegistryEntry;
}): RegistryEntry {
  if (!input.anchor) throw new FrostError('PIN_MISMATCH', 'the list has no ledger anchor');
  const entries = verifyServiceKeyList(input.list, input.anchor, {
    serviceAccount: input.agentAccount,
    opsAccount: input.agentAccount,
  });
  const found = entries.find(
    (e) => e.holder === input.key.holder && e.role === input.key.role && equalBytes(e.edPub, input.key.edPub),
  );
  if (!found) throw new FrostError('KEY_NOT_PINNED', input.key.holder);
  return found;
}
