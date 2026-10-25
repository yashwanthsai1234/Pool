// Share refresh on one device (DESIGN 6.4 "Refresh and repair"; P4.7-12, P4.7-22). The shares never leave the vault:
// `vault.refreshShares` lends them to the protocol and stores the new ones next to the old. Then each local holder signs
// its deletion statement, and the refresh is complete only when every remaining holder's statement is in; only then
// does the vault drop the old shares. If any holder aborts (for example on a bad sub-share it got), the old ones return,
// so no holder is left with a new share the others do not have.
// A REFRESH IS HYGIENE, NOT REVOCATION: old shares still combine with each other until every holder has deleted them,
// and nobody can prove a deletion. A share known to be stolen needs rotation (rotation.ts). Our code, unaudited.
// Source: https://frost.zfnd.org/tutorial/refreshing-shares.html (delete old shares only after all refreshed)
// Source: https://github.com/ZcashFoundation/frost/blob/frost-ed25519/v3.0.0/frost-core/src/keys/refresh.rs
import { FrostError, type KeyShare, type SlotPublic } from '@legx/core/frost';
import type { PinCheck, ShareCipher } from '@legx/core/frostDkg';
import type { FrostRefreshed, RefreshContext } from '@legx/core/frostRefresh';
import type { Vault } from '../vault.ts';
import { xwingShareCipher } from './cipher.ts';
import type { SessionSource } from './dkg.ts';
import { FrostHolder } from './holder.ts';
import type { RelayPort } from './transport.ts';
import { indexOf, type PartyKeys, type WireContext } from './wire.ts';

export type RefreshEvent =
  | { kind: 'refreshed' } // new shares are stored on this device
  | { kind: 'aborted'; reason: string; culprit?: string }
  | { kind: 'deletions'; have: string[]; missing: string[] };

export interface RefreshInput extends WireContext {
  readonly relay: RelayPort;
  readonly sessions: SessionSource;
  readonly pinned: PinCheck;
  /** Enrollment keys of the holders this device runs, by index. */
  readonly local: readonly { index: number; keys: PartyKeys }[];
  readonly participants?: readonly number[];
  readonly epoch: number;
  readonly cipher?: ShareCipher;
  readonly timeoutMs?: number;
  readonly onEvent?: (e: RefreshEvent) => void;
}

/** Runs the refresh with this device's shares in `vault`; resolves with the `frost.refreshed` record. */
export async function refreshSlot(
  o: RefreshInput & { vault: Pick<Vault, 'refreshShares' | 'endRefresh'> },
): Promise<FrostRefreshed> {
  const emit = o.onEvent ?? (() => undefined);
  const participants = o.participants ?? [1, 2, 3];
  const label = (i: number) => o.holders[i - 1]?.label ?? `holder ${i}`;
  const holderFor = (index: number) => {
    const keys = o.local.find((l) => l.index === index)?.keys;
    if (!keys) throw new FrostError('INPUT_INVALID', `no keys for holder ${index}`);
    return new FrostHolder({
      index,
      keys,
      dealId: o.dealId,
      slot: o.slot,
      holders: o.holders,
      relay: o.relay,
      cipher: o.cipher ?? xwingShareCipher,
      pinned: o.pinned,
      ...(o.timeoutMs ? { timeoutMs: o.timeoutMs } : {}),
    });
  };
  let done: { sessionId: string; ctx: RefreshContext; pub: SlotPublic; holders: FrostHolder[] } | undefined;
  try {
    await o.vault.refreshShares(o.dealId, async (shares: KeyShare[], pub: SlotPublic) => {
      const sessionId = await o.sessions('refresh');
      const holders = shares.map((s) => holderFor(indexOf(s.identifier)));
      const out = await Promise.all(
        holders.map((h, i) =>
          h.refresh(sessionId, { share: shares[i] as KeyShare, pub, participants, epoch: o.epoch }),
        ),
      );
      const first = out[0] as (typeof out)[number];
      done = { sessionId, ctx: first.ctx, pub: first.pub, holders };
      return { pub: first.pub, shares: out.map((r) => r.share) };
    });
  } catch (e) {
    const culprit = (e as { culprit?: number }).culprit;
    emit({
      kind: 'aborted',
      reason: e instanceof Error ? e.message : String(e),
      ...(culprit ? { culprit: label(culprit) } : {}),
    });
    throw e;
  }
  const d = done as { sessionId: string; ctx: RefreshContext; pub: SlotPublic; holders: FrostHolder[] } | undefined;
  if (!d) throw new FrostError('REFRESH_INVALID', 'not run');
  emit({ kind: 'refreshed' });
  // a deletion statement is a statement about the old share, so only now, after the new one is stored
  for (const h of d.holders) await h.signDeletion(d.sessionId, d.ctx, d.pub, o.epoch);
  // The old shares stay in the vault until every holder's statement is in; a late abort by anyone brings them back.
  const deadline = Date.now() + (o.timeoutMs ?? 60_000);
  for (;;) {
    let record: FrostRefreshed;
    try {
      record = await (d.holders[0] as FrostHolder).refreshStatus(d.sessionId, d.ctx, d.pub);
    } catch (e) {
      await o.vault.endRefresh(o.dealId, 'old');
      const culprit = (e as { culprit?: number }).culprit;
      emit({
        kind: 'aborted',
        reason: e instanceof Error ? e.message : String(e),
        ...(culprit ? { culprit: label(culprit) } : {}),
      });
      throw e;
    }
    emit({
      kind: 'deletions',
      have: participants.filter((p) => !record.missing.includes(p)).map(label),
      missing: record.missing.map(label),
    });
    if (record.status === 'COMPLETE') await o.vault.endRefresh(o.dealId, 'new');
    if (record.status === 'COMPLETE' || Date.now() > deadline) return record;
    await new Promise((r) => setTimeout(r, 50));
  }
}
