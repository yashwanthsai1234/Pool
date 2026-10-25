// Typed vault errors. A code and nothing else crosses the frame boundary (protocol.ts), so an error can
// never carry share bytes, a salt or a key.

export type VaultCode =
  | 'PASSKEY_REQUIRED' // the PRF tap was cancelled, failed, or returned no PRF output (P4.2-07)
  | 'RECOVERY_CODE_WRONG' // the recovery code is malformed or does not open the file (P4.2-06)
  | 'APPROVAL_REFUSED' // the second device (or the firm HSM) did not approve (P4.2-14)
  | 'DECRYPT_FAILED' // a stored ciphertext is corrupted or was moved to another entry
  | 'SHARE_INVALID' // a share does not match its verifying share
  | 'MESSAGE_REFUSED' // the request is not on the task 1.15 allow-list for this deal and slot
  | 'SIGNATURE_INVALID' // the aggregate failed strict verification, or a holder sent a bad share
  | 'NOT_FOUND'
  | 'NO_SHARE_1' // the entry was restored from a file and waits for a repaired share 1 (task 4.7)
  | 'ROLE_REFUSED' // a share would go to the client's own lawyer, or a mode does not fit the role
  | 'SINGLE_DEVICE_NOT_ACCEPTED' // single-device mode without the accepted warning (P4.2-15)
  | 'STORAGE_FAILED' // IndexedDB refused the write (for example the quota); nothing was stored
  | 'FILE_INVALID'
  | 'INPUT_INVALID'
  | 'CODE_HASH_MISMATCH'; // the frame's own code is not the signed release: every request is refused (task 4.10)

export class VaultError extends Error {
  readonly code: VaultCode;
  constructor(code: VaultCode) {
    super(code);
    this.name = 'VaultError';
    this.code = code;
  }
}
