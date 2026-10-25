// One slot's key-generation ceremony on one device (DESIGN 6.4 "Key generation rules"; P4.7-01, 02, 13 to 15, 19):
//  1. every holder's key is pinned (pinning.ts) before anything is sent;
//  2. the DKG with the transcript echo and complaints (holder.ts over core's round functions);
//  3. all three pairs test-sign the fixed message; the slot is ready only when all three verify;
//  4. the `frost.dkg.completed` record (core's `dkgCompletedRecord`).
// A device runs one holder (the phone with a second device, the console) or two (the phone that also holds the
// security-key or same-phone passkey share). The shares come back only when the slot is ready, so a failed
// ceremony stores nothing; the caller hands them to the vault's `storeShares`, which zeroes them.
// Source: DESIGN.md 6.4; https://frost.zfnd.org/tutorial/dkg.html
import { FrostError, type KeyShare, type SlotPublic, slotPubkey } from '@legx/core/frost';
import {
  type DkgCompleted,
  dkgCompletedRecord,
  type PinCheck,
  type ShareCipher,
  testSignCheck,
  testSignMessage,
} from '@legx/core/frostDkg';
import { xwingShareCipher } from './cipher.ts';
import { CeremonyError, type DkgStep, FrostHolder } from './holder.ts';
import { fingerprint, KeyRefused } from './pinning.ts';
import type { Purpose, RelayPort } from './transport.ts';
import type { HolderInfo, PartyKeys, WireContext } from './wire.ts';

export const PAIRS: readonly (readonly [number, number])[] = [
  [1, 2],
  [1, 3],
  [2, 3],
];

export type PairResult = { pair: readonly [number, number]; names: [string, string]; ok: boolean; reason?: string };
export type DkgEvent =
  | { kind: 'step'; step: DkgStep }
  | { kind: 'refused'; label: string; fingerprint: string; reason: string }
  | { kind: 'aborted'; reason: string; culprit?: string; complaint: boolean }
  | { kind: 'pair'; result: PairResult }
  | { kind: 'ready'; fingerprint: string; slotPub: Uint8Array };

/** Where a device gets a session id: the opener opens it, the other devices learn it from the coordinator's feed. */
export type SessionSource = (purpose: Purpose, pair?: readonly [string, string]) => Promise<string>;
export const openerSessions =
  (relay: RelayPort, holders: readonly HolderInfo[]): SessionSource =>
  (purpose, pair) =>
    relay.openSession({ purpose, holders, ...(pair ? { pair } : {}) });

export interface DkgInput extends WireContext {
  readonly relay: RelayPort;
  readonly sessions: SessionSource;
  readonly pinned: PinCheck;
  /** The holders this device runs, by index, with their enrollment keys. */
  readonly local: readonly { index: number; keys: PartyKeys }[];
  readonly cipher?: ShareCipher;
  readonly timeoutMs?: number;
  readonly pollMs?: number;
  readonly onEvent?: (e: DkgEvent) => void;
}

export type DkgResult =
  | { ready: true; pub: SlotPublic; shares: Map<number, KeyShare>; record: DkgCompleted; pairs: PairResult[] }
  | { ready: false; pairs: PairResult[] };

const labelOf = (holders: readonly HolderInfo[], index: number | undefined) =>
  index === undefined ? undefined : (holders[index - 1]?.label ?? `holder ${index}`);

/** Runs the ceremony; throws on a refused key or an aborted DKG (no share exists then). */
export async function runSlotDkg(o: DkgInput): Promise<DkgResult> {
  const emit = o.onEvent ?? (() => undefined);
  const holderOf = (index: number, keys: PartyKeys) =>
    new FrostHolder({
      index,
      keys,
      dealId: o.dealId,
      slot: o.slot,
      holders: o.holders,
      relay: o.relay,
      cipher: o.cipher ?? xwingShareCipher,
      pinned: o.pinned,
      ...(o.timeoutMs ? { timeoutMs: o.timeoutMs } : {}),
      ...(o.pollMs ? { pollMs: o.pollMs } : {}),
    });
  const mine = o.local.map((l) => holderOf(l.index, l.keys));
  const first = mine[0];
  if (!first) throw new FrostError('INPUT_INVALID', 'no local holder');

  // 1. pinning, before anything goes out
  try {
    o.pinned(first.directory('00'.repeat(32)));
  } catch (e) {
    if (!(e instanceof KeyRefused)) throw e;
    // name the key as the ceremony shows it, even when it was never pinned here
    const shown = o.holders.find((h) => fingerprint(h.edPub) === e.fingerprint);
    const named = shown && shown.label !== e.label ? new KeyRefused(shown, e.reason) : e;
    emit({ kind: 'refused', label: named.label, fingerprint: named.fingerprint, reason: named.message });
    throw named;
  }

  // 2. the DKG
  const sessionId = await o.sessions('dkg');
  let runs: Awaited<ReturnType<FrostHolder['dkg']>>[];
  try {
    runs = await Promise.all(
      mine.map((h, i) => h.dkg(sessionId, i === 0 ? { onStep: (step) => emit({ kind: 'step', step }) } : {})),
    );
  } catch (e) {
    const culprit = e instanceof CeremonyError || e instanceof FrostError ? e.culprit : undefined;
    emit({
      kind: 'aborted',
      reason: e instanceof Error ? e.message : String(e),
      complaint: e instanceof CeremonyError && e.code === 'DKG_COMPLAINT',
      ...(labelOf(o.holders, culprit) ? { culprit: labelOf(o.holders, culprit) } : {}),
    });
    throw e;
  }
  const run = runs[0] as (typeof runs)[number];
  const pub = run.key.public;
  const shares = new Map(runs.map((r, i) => [(mine[i] as FrostHolder).me, r.key.secret]));
  const wipe = () => {
    for (const s of shares.values()) s.signingShare.fill(0);
  };

  // 3. test-signing with every pair
  const pairs: PairResult[] = [];
  const testSignatures: { pair: [number, number]; sig: Uint8Array }[] = [];
  for (const pair of PAIRS) {
    const names = [labelOf(o.holders, pair[0]), labelOf(o.holders, pair[1])] as [string, string];
    const msg = testSignMessage(run.ctx, pub, pair);
    try {
      const sid = await o.sessions('sign', [
        o.holders[pair[0] - 1]?.identifier ?? '',
        o.holders[pair[1] - 1]?.identifier ?? '',
      ]);
      const inPair = mine.filter((h) => pair.includes(h.me));
      const sigs = inPair.length
        ? await Promise.all(
            inPair.map((h) =>
              h.sign(sid, {
                msg,
                kind: 'tagged',
                share: shares.get(h.me) as KeyShare,
                pub,
                check: testSignCheck(run.ctx, pub, h.me),
                pair,
              }),
            ),
          )
        : [await first.observeSign(sid, pub, msg)];
      testSignatures.push({ pair: [pair[0], pair[1]], sig: sigs[0] as Uint8Array });
      pairs.push({ pair, names, ok: true });
    } catch (e) {
      pairs.push({ pair, names, ok: false, reason: e instanceof Error ? e.message : String(e) });
    }
    emit({ kind: 'pair', result: pairs[pairs.length - 1] as PairResult });
  }
  if (!pairs.every((p) => p.ok)) {
    wipe();
    return { ready: false, pairs };
  }

  // 4. the record
  let record: DkgCompleted;
  try {
    record = dkgCompletedRecord({ ctx: run.ctx, pub, round1: run.round1, echoes: run.echoes, testSignatures });
  } catch (e) {
    wipe();
    throw e;
  }
  emit({ kind: 'ready', fingerprint: fingerprint(slotPubkey(pub)), slotPub: slotPubkey(pub) });
  return { ready: true, pub, shares, record, pairs };
}
