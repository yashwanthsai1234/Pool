// The console receiver: opens the sealed transfer, decodes it and feeds passive authentication and the chip checks (1.9).
// Source: DESIGN.md 6.15; OD-22, OD-23
import { type ChipCheckCode, type ChipCheckResult, chipChecks } from '@legx/core/passport/passiveAuth';
import { type OpenCode, openSealed, type Sealed, type Session } from './channel.ts';
import { decodeChipData, type WireCode } from './wire.ts';

export interface ReceiveContext {
  readonly trustList: readonly Uint8Array[];
  /** Validated ledger close_time, Ripple epoch seconds. */
  readonly atTime: number;
  readonly salt: Uint8Array;
  readonly commitment: Uint8Array;
  /** The presenceMsg whose first 8 bytes the session sent as the AA challenge. */
  readonly presenceMsg: Uint8Array;
}

export type ReceiveResult =
  | ChipCheckResult
  | { readonly ok: false; readonly code: OpenCode | WireCode | ChipCheckCode };

export async function receiveChip(session: Session, sealed: Sealed, ctx: ReceiveContext): Promise<ReceiveResult> {
  const opened = await openSealed(session, sealed);
  if (!opened.ok) return opened;
  const d = decodeChipData(opened.plaintext);
  if (!d.ok) return d;
  return chipChecks({ ...d.data, ...ctx });
}
