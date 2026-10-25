// Reading the deal's own evidence log. The log is the history (IMPLEMENTATION 3.2 "Think"): facts that no column holds
// (the identity policy, which events arrived) are read from it. Stored envelopes were verified when they were stored.
import { fromBase64Strict } from '@legx/core/pq';
import type { Repos } from '@legx/db';

export interface LoggedEvent {
  readonly seq: number;
  readonly leafHash: string;
  readonly kind: string;
  readonly actor: { readonly role: string; readonly key_id: string };
  readonly data: Record<string, unknown>;
  readonly ledger?: { readonly tx_hash: string; readonly ledger_index: number };
}

const dec = new TextDecoder('utf-8', { fatal: true });

/** Parses one stored envelope into its predicate fields; undefined for bytes that are not an event (never stored by us). */
export function parseStored(seq: number, leafHash: string, envelope: Uint8Array): LoggedEvent | undefined {
  try {
    const env = JSON.parse(dec.decode(envelope)) as { payload: string };
    const body = fromBase64Strict(env.payload);
    if (!body) return undefined;
    const p = (JSON.parse(dec.decode(body)) as { predicate: Record<string, unknown> }).predicate;
    return {
      seq,
      leafHash,
      kind: p.kind as string,
      actor: p.actor as LoggedEvent['actor'],
      data: p.data as Record<string, unknown>,
      ...(p.ledger ? { ledger: p.ledger as NonNullable<LoggedEvent['ledger']> } : {}),
    };
  } catch {
    return undefined;
  }
}

export async function loadLog(repos: Repos, dealId: string): Promise<LoggedEvent[]> {
  const out: LoggedEvent[] = [];
  for (let after = -1; ; ) {
    const page = await repos.evidenceEvents.listAfter(dealId, after, 500);
    for (const r of page) {
      const e = parseStored(r.seq, r.leaf_hash, r.envelope);
      if (e) out.push(e);
    }
    if (page.length < 500) return out;
    after = (page.at(-1) as { seq: number }).seq;
  }
}

/** The newest event of a kind, optionally narrowed by a predicate on its data. */
export function lastOf(
  log: readonly LoggedEvent[],
  kind: string,
  where: (d: Record<string, unknown>) => boolean = () => true,
): LoggedEvent | undefined {
  for (let i = log.length - 1; i >= 0; i--) {
    const e = log[i] as LoggedEvent;
    if (e.kind === kind && where(e.data)) return e;
  }
  return undefined;
}
