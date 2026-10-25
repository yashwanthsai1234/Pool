// Every failure the verifier reports is a VerifierError with a stable code, never a raw TypeError or a hang.
export type VerifierCode =
  | 'ADAPTER_BAD_REQUEST'
  | 'ADAPTER_TIMEOUT'
  | 'ADAPTER_UNREACHABLE'
  | 'ADAPTER_BAD_RESPONSE'
  | 'NO_ADAPTER'
  | 'AWAITING_OPS_ACCEPT'
  | 'OPS_ACCOUNT_MISSING'
  | 'NOT_ACTIVE'
  | 'NOT_FOUND'
  | 'NOT_ONBOARDED'
  | 'BAR_NUMBER_MISMATCH'
  | 'COMMITMENT_MISMATCH'
  | 'VERIFICATION_STALE'
  | 'LEDGER_REJECTED'
  | 'LEDGER_EXPIRED'
  | 'SELF_CHECK_FAILED';

export class VerifierError extends Error {
  override readonly name = 'VerifierError';
  readonly code: VerifierCode;
  constructor(code: VerifierCode, message: string) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
