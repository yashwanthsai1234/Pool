// Everything the coordinator needs from the outside, as ports (IMPLEMENTATION 7 "Shape"). The demo and production
// profiles differ only in what is passed here.
import type { PublicDealData } from '@legx/contracts/deal';
import type { LedgerPort, SignerPort } from '@legx/contracts/ports';
import type { ReleaseGateRecord as ReleaseGateRecordSchema } from '@legx/contracts/records';
import type { Database } from '@legx/db';
import type { z } from 'zod';

export type ReleaseGateRecord = z.infer<typeof ReleaseGateRecordSchema>;

/** What the release gate (task 1.12) is asked: the claim a lawyer signed, and the deal as the coordinator sees it. */
export interface GateInput {
  readonly dealId: string;
  readonly publicData: PublicDealData;
  readonly claim: ReleaseGateRecord;
  readonly ledger: LedgerPort;
}
export type GateResult = { readonly ok: true } | { readonly ok: false; readonly failed: readonly string[] };
/** The coordinator re-runs the gate itself before it relays release records (DESIGN 10.2). */
export interface GatePort {
  run(input: GateInput): Promise<GateResult>;
}

/** A hybrid key pair pinned out of band for callers that are not yet inside any deal (a lawyer creating a deal). */
export interface PinnedKey {
  readonly ed25519: Uint8Array;
  readonly mlDsa65: Uint8Array;
  /** A lawyer's operations account: lets the key pin itself as the console of that lawyer's slot (keys.register). */
  readonly opsAccount?: string;
}

export interface CoordinatorDeps {
  readonly db: Database;
  readonly ledger: LedgerPort;
  /** The coordinator's own evidence key: it signs the events it creates itself (exit and close results). */
  readonly signer: SignerPort;
  readonly gate: GatePort;
  /** Pinned keys of lawyers allowed to create deals, by pair id. */
  readonly lawyerKeys: (pairId: string) => PinnedKey | undefined;
  /** Pinned observer keys of the projector dashboard (OD-31), by pair id: read routes and the live feed only. */
  readonly observerKeys?: (pairId: string) => PinnedKey | undefined;
  /**
   * Called between every two awaited steps that matter (`deal.afterStateWrite`, `submit.before`, `submit.after`, ...).
   * Production leaves it out; tests throw from it to model a process kill (P3.2-03, P3.2-10).
   */
  readonly crash?: (point: string) => void | Promise<void>;
}
