// FROST ceremonies inside the vault frame (DESIGN 6.4 "Code integrity", IMPLEMENTATION 4.10). The DKG runs in the frame:
// its shares are made there and go straight into the frame's own vault, so the app page never holds one. The frame has
// `connect-src 'none'`, so the relay and the session source are reached back through the same MessagePort: the app
// answers `call` messages (relay.openSession/send/receive, sessions) and receives `event` messages. Everything that
// crosses is signed, HPKE-sealed or public (P4.7-09); the result carries the public key set and the completed record.
// Source: https://html.spec.whatwg.org/multipage/web-messaging.html#message-channels (MessagePort, structured clone)

import type { SlotPublic } from '@legx/core/frost';
import type { FrostRefreshed } from '@legx/core/frostRefresh';
import type { SignRequest } from '@legx/core/frostRules';
import { z } from 'zod';
import { VaultError } from './errors.ts';
import type { ApprovalWire } from './frost/approval.ts';
import { xwingShareCipher } from './frost/cipher.ts';
import { relayCoSigner, type StartRemote } from './frost/cosign.ts';
import { type DkgEvent, type DkgResult, type PairResult, runSlotDkg, type SessionSource } from './frost/dkg.ts';
import { FrostHolder } from './frost/holder.ts';
import { keyDirectory } from './frost/pinning.ts';
import { refreshSlot } from './frost/refresh.ts';
import { repairReceive, repairWithVault } from './frost/repair.ts';
import type { Purpose, RelayPort } from './frost/transport.ts';
import { type HolderInfo, hex, type PartyKeys } from './frost/wire.ts';
import type { Vault } from './vault.ts';

/** What only the frame can provide: this device's enrollment keys for a deal (never returned, only used to sign). */
export interface CeremonyHost {
  partyKeys(a: { dealId: string; keyId: string }): Promise<PartyKeys>;
}

const bytes = z.custom<Uint8Array>((v) => v instanceof Uint8Array);
const Holder = z.strictObject({
  identifier: z.string().max(80),
  keyId: z.string().max(200),
  role: z.string().max(40),
  edPub: bytes,
  pqPub: bytes,
  deviceId: z.string().max(200),
  label: z.string().max(200),
});
/** The `dkg` request. Share 2 is held elsewhere (second device or firm HSM), so no share is ever an input. */
export const DkgArgs = z.strictObject({
  dealId: z.uuid({ version: 'v7' }),
  slot: z.enum(['A', 'B', 'LA', 'LB']),
  holders: z.array(Holder).length(3),
  localIndex: z.int().min(1).max(3),
  keyId: z.string().max(200),
  share2: z.enum(['second-device', 'firm-hsm']),
  timeoutMs: z.int().positive().optional(),
  pollMs: z.int().positive().optional(),
});
export type DkgRequest = z.infer<typeof DkgArgs>;

const Base = {
  dealId: DkgArgs.shape.dealId,
  slot: DkgArgs.shape.slot,
  holders: DkgArgs.shape.holders,
  localIndex: DkgArgs.shape.localIndex,
  keyId: DkgArgs.shape.keyId,
  timeoutMs: DkgArgs.shape.timeoutMs,
} as const;
/** The `refresh` request: this device's shares are already in the frame's vault. */
export const RefreshArgs = z.strictObject({
  ...Base,
  epoch: z.int().positive(),
  participants: z.array(z.int().min(1).max(3)).min(2).max(3).optional(),
});
export type RefreshRequest = z.infer<typeof RefreshArgs>;
/** The `repair` request. `helper`: this device lends the share it holds (and receives, if it is also the new holder). `receive`: a new device with no share. */
export const RepairArgs = z.strictObject({
  ...Base,
  mode: z.enum(['helper', 'receive']),
  newIndex: z.int().min(1).max(3),
  helpers: z.array(z.int().min(1).max(3)).length(2),
  pub: z.custom<SlotPublic>((v) => typeof v === 'object' && v !== null && Array.isArray((v as SlotPublic).commitments)),
});
export type RepairRequest = z.infer<typeof RepairArgs>;
/**
 * The `signSlot` request (a lawyer slot: share 1 in this frame, share 2 at the firm HSM): the holders as pinned, which one
 * is remote, and the lawyer's approval. The approval must be over the hash of the bytes this frame derives itself.
 */
export const SlotSignBase = z.strictObject({
  dealId: DkgArgs.shape.dealId,
  slot: z.enum(['LA', 'LB']),
  holders: DkgArgs.shape.holders,
  localIndex: DkgArgs.shape.localIndex,
  remote: DkgArgs.shape.localIndex,
  keyId: DkgArgs.shape.keyId,
  timeoutMs: DkgArgs.shape.timeoutMs,
});
export type SlotSignRequest = z.infer<typeof SlotSignBase> & { request: SignRequest; approval: ApprovalWire };
/** The public part of `DkgResult`: no shares. */
export type FrameDkgResult =
  | { ready: true; pub: never; record: never; pairs: PairResult[] }
  | { ready: false; pairs: PairResult[] };

/** Frame to app: a call the app answers, and an event. App to frame: the call's result. */
const CeremonyMsg = z.union([
  z.strictObject({
    legxCeremony: z.literal(1),
    kind: z.literal('call'),
    n: z.int(),
    op: z.string().max(20),
    args: z.unknown(),
  }),
  z.strictObject({ legxCeremony: z.literal(1), kind: z.literal('event'), event: z.unknown() }),
  z.strictObject({
    legxCeremony: z.literal(1),
    kind: z.literal('result'),
    n: z.int(),
    ok: z.boolean(),
    result: z.unknown(),
  }),
]);
export const isCeremonyMessage = (data: unknown): boolean => CeremonyMsg.safeParse(data).success;

/** The app's side of a ceremony: where the frame's relay calls and session lookups go. */
export interface CeremonyIo {
  relay: RelayPort;
  sessions: SessionSource;
  onEvent?: (e: DkgEvent) => void;
  /** Slot signing only: asks the firm HSM to join the session (`firm-hsm/sign`, signed by the operations key). */
  start?: StartRemote;
}

type Pending = Map<number, { resolve: (v: unknown) => void; reject: (e: unknown) => void }>;

/** Frame side: owns the pending calls of one port. */
export function ceremonyServer(port: MessagePort, vault: Vault, host: CeremonyHost | undefined) {
  const pending: Pending = new Map();
  let n = 0;
  const call = (op: string, args: unknown) =>
    new Promise<unknown>((resolve, reject) => {
      const id = n++;
      pending.set(id, { resolve, reject });
      port.postMessage({ legxCeremony: 1, kind: 'call', n: id, op, args });
    });
  const emit = (event: unknown) => port.postMessage({ legxCeremony: 1, kind: 'event', event });
  /** What every ceremony needs: the holders as pinned, the relay and sessions reached through the app, this device's keys. */
  const common = async (a: Pick<DkgRequest, 'dealId' | 'slot' | 'holders' | 'localIndex' | 'keyId' | 'timeoutMs'>) => {
    if (!host) throw new VaultError('NOT_FOUND');
    const holders = a.holders as unknown as HolderInfo[];
    const relay: RelayPort = {
      openSession: (i) => call('openSession', i) as Promise<string>,
      send: (m) => call('send', m) as ReturnType<RelayPort['send']>,
      receive: (s, r, after) => call('receive', [s, r, after]) as ReturnType<RelayPort['receive']>,
    };
    return {
      dealId: a.dealId,
      slot: a.slot,
      holders,
      relay,
      sessions: ((purpose: Purpose, pair) => call('session', { purpose, pair }) as Promise<string>) as SessionSource,
      pinned: keyDirectory(holders),
      local: [{ index: a.localIndex, keys: await host.partyKeys({ dealId: a.dealId, keyId: a.keyId }) }],
      ...(a.timeoutMs ? { timeoutMs: a.timeoutMs } : {}),
    };
  };
  return {
    /** True when `data` was a ceremony result and has been consumed. */
    consume(data: unknown): boolean {
      const m = CeremonyMsg.safeParse(data);
      if (!m.success || m.data.kind !== 'result') return false;
      const p = pending.get(m.data.n);
      pending.delete(m.data.n);
      if (m.data.ok) p?.resolve(m.data.result);
      else p?.reject(new Error('RELAY_FAILED'));
      return true;
    },
    async refresh(a: RefreshRequest): Promise<FrostRefreshed> {
      const c = await common(a);
      return refreshSlot({
        ...c,
        vault,
        epoch: a.epoch,
        ...(a.participants ? { participants: a.participants } : {}),
        onEvent: emit,
      });
    },
    async repair(a: RepairRequest): Promise<{ repaired: true }> {
      const c = await common(a);
      const input = { ...c, pub: a.pub, newIndex: a.newIndex, helpers: a.helpers };
      if (a.mode === 'helper') await repairWithVault({ ...input, vault });
      else await vault.installShare1(a.dealId, await repairReceive(input));
      return { repaired: true };
    },
    /** Signs one request with share 1 here and share 2 at the firm HSM, over the relay reached through the app. */
    async signSlot(a: SlotSignRequest): Promise<Uint8Array> {
      const c = await common(a);
      const holder = new FrostHolder({
        index: a.localIndex,
        keys: (c.local[0] as (typeof c.local)[number]).keys,
        dealId: a.dealId,
        slot: a.slot,
        holders: c.holders,
        relay: c.relay,
        cipher: xwingShareCipher,
        pinned: c.pinned,
        ...(a.timeoutMs ? { timeoutMs: a.timeoutMs } : {}),
      });
      return vault.signFrost(a.dealId, a.request, (messageOf) =>
        relayCoSigner({
          holder,
          relay: c.relay,
          holders: c.holders,
          dealId: a.dealId,
          slot: a.slot,
          remote: a.remote,
          messageOf,
          start: (i) => call('start', i).then(() => undefined),
          approve: async (msgHash) => {
            if (hex(msgHash) !== a.approval.message_hash) throw new VaultError('APPROVAL_REFUSED');
            return a.approval;
          },
        }),
      );
    },
    async dkg(a: DkgRequest): Promise<FrameDkgResult> {
      const c = await common(a);
      const r: DkgResult = await runSlotDkg({
        ...c,
        ...(a.pollMs ? { pollMs: a.pollMs } : {}),
        onEvent: emit,
      });
      if (!r.ready) return { ready: false, pairs: r.pairs };
      const share1 = r.shares.get(a.localIndex);
      if (!share1) throw new VaultError('SHARE_INVALID');
      await vault.storeShares({ dealId: a.dealId, pub: r.pub, share1, share2: { mode: a.share2 } });
      return { ready: true, pub: r.pub as never, record: r.record as never, pairs: r.pairs };
    },
  };
}

/** App side: answers the frame's calls with `io` and forwards its events. Returns true when `data` was ours. */
export function ceremonyClient(port: MessagePort) {
  let io: CeremonyIo | undefined;
  return {
    use<T>(next: CeremonyIo, run: () => Promise<T>): Promise<T> {
      io = next;
      return run().finally(() => {
        io = undefined;
      });
    },
    consume(data: unknown): boolean {
      const m = CeremonyMsg.safeParse(data);
      if (!m.success || m.data.kind === 'result') return false;
      const msg = m.data;
      if (msg.kind === 'event') {
        io?.onEvent?.(msg.event as DkgEvent);
        return true;
      }
      const reply = (ok: boolean, result?: unknown) =>
        port.postMessage({ legxCeremony: 1, kind: 'result', n: msg.n, ok, result });
      const a = msg.args as never;
      const sessionArgs = msg.args as { purpose: Purpose; pair?: readonly [string, string] };
      const work: Promise<unknown> | undefined = !io
        ? undefined
        : msg.op === 'openSession'
          ? io.relay.openSession(a)
          : msg.op === 'send'
            ? io.relay.send(a)
            : msg.op === 'receive'
              ? io.relay.receive(...(msg.args as Parameters<RelayPort['receive']>))
              : msg.op === 'session'
                ? io.sessions(sessionArgs.purpose, sessionArgs.pair)
                : msg.op === 'start'
                  ? io.start?.(a)
                  : undefined;
      if (!work) reply(false);
      else
        work.then(
          (r) => reply(true, r),
          () => reply(false),
        );
      return true;
    },
  };
}
