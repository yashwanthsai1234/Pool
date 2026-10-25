// Share repair on one device (DESIGN 6.4 "Refresh and repair"; P4.7-04, P4.7-18): a new device gets a fresh share
// through two helpers, without the old share and without anyone rebuilding the key. The group key is unchanged, and a
// refresh should follow (the screen offers it). Our code over ZF's `repairable` math (task 1.15), unaudited.
// Three device situations:
//  - a helper only (the second device, or the agent): `vault.repairShare` lends its share, nothing is installed;
//  - a new phone that restored share 2 from its file: it helps with share 2 and receives share 1 at once;
//  - a new phone with nothing (second-device mode): it only receives, and stores share 1 with `storeShares`.
// Source: https://github.com/ZcashFoundation/frost/blob/frost-ed25519/v3.0.0/frost-core/src/keys/repairable.rs
import { FrostError, type KeyShare, type SlotPublic } from '@legx/core/frost';
import type { PinCheck, ShareCipher } from '@legx/core/frostDkg';
import type { Vault } from '../vault.ts';
import { xwingShareCipher } from './cipher.ts';
import type { SessionSource } from './dkg.ts';
import { FrostHolder } from './holder.ts';
import type { RelayPort } from './transport.ts';
import type { PartyKeys, WireContext } from './wire.ts';

export interface RepairInput extends WireContext {
  readonly relay: RelayPort;
  readonly sessions: SessionSource;
  readonly pinned: PinCheck;
  /** The slot's public data from its last `frost.dkg.completed` or `frost.refreshed` record. */
  readonly pub: SlotPublic;
  readonly newIndex: number;
  readonly helpers: readonly number[];
  /** This device's holders, by index (a helper, the new holder, or both). */
  readonly local: readonly { index: number; keys: PartyKeys }[];
  readonly cipher?: ShareCipher;
  readonly timeoutMs?: number;
}

function holders(o: RepairInput) {
  return (index: number) => {
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
}

/** A helper with a share in `vault` (and, on a new phone, also the new holder): the repaired share is installed. */
export async function repairWithVault(o: RepairInput & { vault: Pick<Vault, 'repairShare'> }): Promise<void> {
  const make = holders(o);
  const receiving = o.local.some((l) => l.index === o.newIndex);
  await o.vault.repairShare(o.dealId, async (share, pub) => {
    const helper = make(Number(o.helpers.find((h) => o.local.some((l) => l.index === h))));
    const sid = await o.sessions('repair');
    const help = helper.repairHelp(sid, { share, pub, helpers: o.helpers, newIndex: o.newIndex });
    if (!receiving) return void (await help);
    const [, repaired] = await Promise.all([help, make(o.newIndex).repairReceive(sid, { pub, helpers: o.helpers })]);
    return repaired;
  });
}

/** A new device with no share at all receives its share from the two helpers. The caller stores it. */
export async function repairReceive(o: RepairInput): Promise<KeyShare> {
  const sid = await o.sessions('repair');
  return holders(o)(o.newIndex).repairReceive(sid, { pub: o.pub, helpers: o.helpers });
}
