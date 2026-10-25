// The firm's key directory entry (DESIGN 6.3): the firm publishes the enrollment keys of its console, HSM service and
// partner in a list signed by its operations account (which holds the LEGX_ATTORNEY credential, 6.16) and anchors the
// list's hash on the ledger from that same account. Signing, anchoring and the lawyer console's acceptance check are
// the recovery agent's (task 3.9) and core's `verifyServiceKeyList`; only the list's contents differ: lawyer roles.
// Source: DESIGN 6.3; https://xrpl.org/docs/references/protocol/transactions/common-fields (Memos)
import { utf8ToBytes } from '@legx/core/dealcore';
import type { Role } from '@legx/core/frost';

export { acceptServiceKey, anchorMemo, readAnchor, signKeyList } from '@legx/recovery-agent/keylist';

export interface FirmListedKey {
  readonly holder: string;
  readonly role: Extract<Role, 'console' | 'firm-hsm' | 'partner'>;
  /** XRPL form: `ED` and 64 uppercase hex characters. */
  readonly ed25519: string;
  /** Base64 of the ML-DSA-65 public key. */
  readonly mldsa65: string;
}

/** The list bytes, exactly as they are signed, hashed and served. */
export const buildFirmKeyList = (keys: readonly FirmListedKey[]): Uint8Array => utf8ToBytes(JSON.stringify({ keys }));
