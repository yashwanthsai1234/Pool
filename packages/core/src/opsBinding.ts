// Operations-account binding (DESIGN 6.14, W3). The firm's operations account and the lawyer slot key both sign one
// message that ties the account to this contract, this lawyer key and this bar-record commitment.
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { deriveAddress } from 'xrpl';
import { tupleHash } from './dealcore.ts';
import type { LawyerRole } from './signedContract.ts';
import { verifyXrplKeySig } from './verify.ts';

/** AccountRoot flag: the master key may not sign. Source: https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot */
export const LSF_DISABLE_MASTER = 0x00100000;

/** The part of a validated `account_info` result this check reads (xrpl.js `AccountInfoResponse['result']` fits). */
export interface AccountInfo {
  validated?: boolean;
  account_data: { Account: string; Flags: number; RegularKey?: string };
}

/** The message inputs. Every one of them must come from the sealed deal (DESIGN 6.6), not from the binder. */
export interface OpsBindTerms {
  contractRoot: Uint8Array;
  opsAccount: string;
  lawyerPub: string; // the lawyer slot key, 33-byte XRPL hex
  lawyerCommitment: Uint8Array; // LC_role (DESIGN 6.2)
  role: LawyerRole;
}
/** An `ops.bound` evidence record: the terms plus the operations key and both signatures (hex). */
export interface OpsBinding extends OpsBindTerms {
  opsPub: string;
  opsSig: string;
  lawyerSig: string;
}

export type OpsBindingCode =
  | 'NOT_VALIDATED'
  | 'ACCOUNT_MISMATCH'
  | 'OPS_KEY_NOT_AUTHORIZED'
  | 'OPS_SIG_INVALID'
  | 'LAWYER_SIG_INVALID';

// Source: DESIGN 6.14 (opsBindMsg); encoding rules: DESIGN 6 "Encoding rules for every tuple hash".
export function opsBindMsg(t: OpsBindTerms): Uint8Array {
  return tupleHash('legx/ops-binding/v1', [
    t.contractRoot,
    utf8ToBytes(t.opsAccount),
    hexToBytes(t.lawyerPub),
    t.lawyerCommitment,
    utf8ToBytes(t.role),
  ]);
}

// The key may sign for the account: it is the master key and lsfDisableMaster is clear, or it is the RegularKey.
// Source: https://xrpl.org/docs/concepts/accounts/cryptographic-keys (master key pair, regular key pair)
function keyMaySign(pubHex: string, acct: AccountInfo['account_data']): boolean {
  let address: string;
  try {
    address = deriveAddress(pubHex);
  } catch {
    return false;
  }
  const masterOn = (acct.Flags & LSF_DISABLE_MASTER) === 0;
  return (address === acct.Account && masterOn) || address === acct.RegularKey;
}

/**
 * Checks an operations-account binding against the account as read from one validated ledger (DESIGN 6.14). It does
 * no network read. A firm that rotates its RegularKey after binding fails here and must bind again.
 */
export function verifyOpsBinding(
  accountInfo: AccountInfo,
  binding: OpsBinding,
): { ok: true } | { ok: false; code: OpsBindingCode } {
  if (accountInfo.validated !== true) return { ok: false, code: 'NOT_VALIDATED' };
  const acct = accountInfo.account_data;
  if (acct.Account !== binding.opsAccount) return { ok: false, code: 'ACCOUNT_MISMATCH' };
  if (!keyMaySign(binding.opsPub, acct)) return { ok: false, code: 'OPS_KEY_NOT_AUTHORIZED' };
  // Lawyer slot keys are Ed25519 FROST group keys (DESIGN 6.4); checked before hashing so hostile hex cannot throw.
  if (!/^ED[0-9A-F]{64}$/i.test(binding.lawyerPub)) return { ok: false, code: 'LAWYER_SIG_INVALID' };
  const msg = opsBindMsg(binding);
  if (!verifyXrplKeySig(binding.opsPub, msg, binding.opsSig)) return { ok: false, code: 'OPS_SIG_INVALID' };
  if (!verifyXrplKeySig(binding.lawyerPub, msg, binding.lawyerSig)) return { ok: false, code: 'LAWYER_SIG_INVALID' };
  return { ok: true };
}
