// A FROST share holder in the browser that talks to the relay (task 3.9). It is protocol-compatible with
// `services/recovery-agent/src/holder.ts` (same kinds, same order, same AADs), so the phone, the second device, the
// console, the recovery agent and the firm HSM can sit in one ceremony; `test/frost/interop.test.ts` runs it with
// 3.9's holder. It moves messages and calls task 1.15's pure round functions; it adds no cryptography of its own.
//  - The relay is untrusted: every incoming message is checked (both signatures, session, sender's pinned key).
//  - Enrollment signatures are async here (WebCrypto Ed25519, task 4.9's ML-DSA), but core's `EnrollmentSigner` is
//    synchronous. So core gets a placeholder signer, and each outgoing message is signed for real by `#sendCore`;
//    the copy that went out (with the real signature) is the one kept for transcripts and records.
//  - Nonces live only inside core's `SigningSession` objects, in memory, used once (DESIGN 6.4, 10.1).
//  - A failed round sends a signed `abort` that names no share.
// Source: https://frost.zfnd.org/tutorial/dkg.html (broadcast channel; round 2 authenticated and confidential)
// Source: https://www.rfc-editor.org/rfc/rfc9591#section-5 (two-round signing)
// Source: https://github.com/ZcashFoundation/frost/blob/frost-ed25519/v3.0.0/frost-core/src/keys/repairable.rs
import type { FrostRelayPort } from '@legx/contracts/ports';
import { tupleHash } from '@legx/core/dealcore';
import {
  aggregateChecked,
  type CheckResult,
  type Commitment,
  FrostError,
  type FrostMsg,
  holderId,
  type KeyShare,
  SigningSession,
  type SlotPublic,
  u32,
} from '@legx/core/frost';
import {
  type DkgContext,
  type DkgKey,
  dkgReceiveEcho,
  dkgReceiveRound1,
  dkgReceiveRound2,
  dkgStart,
  judgeComplaint,
  type PinCheck,
  type ShareCipher,
} from '@legx/core/frostDkg';
import {
  deletionStatement,
  type FrostRefreshed,
  type RefreshContext,
  refreshedEvent,
  refreshReceiveCommits,
  refreshReceiveShares,
  refreshStart,
} from '@legx/core/frostRefresh';
import { checkDelta, repairDelta, repairFinish, repairSigma } from '@legx/core/frostRepair';
import { fromBase64Strict, toBase64 } from '@legx/core/pq';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  boxBytes,
  commitmentsDigest,
  type HolderInfo,
  hex,
  indexOf,
  type OfKind,
  openRelayed,
  type PartyKeys,
  type RelayKind,
  type RelayMessage,
  type Signed,
  sealedBox,
  signRelayMessage,
  toWire,
  unhex,
  type WireContext,
} from './wire.ts';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** Core signs through this; the real signature is made by `#sendCore` (see the header). */
const PLACEHOLDER = { sign: (): Uint8Array => new Uint8Array(64) };

export interface HolderConfig {
  /** 1, 2 or 3: the position in the slot's canonical role order. */
  readonly index: number;
  readonly keys: PartyKeys;
  readonly dealId: string;
  readonly slot: WireContext['slot'];
  readonly holders: readonly HolderInfo[];
  readonly relay: FrostRelayPort;
  readonly cipher: ShareCipher;
  readonly pinned: PinCheck;
  readonly pollMs?: number;
  /** Per round. Measured with `Date.now`, so a backgrounded tab whose timers are paused still times out correctly. */
  readonly timeoutMs?: number;
  /** After round 3 a holder waits this long for a complaint before it returns its key (DESIGN 6.4 rule 3). */
  readonly complaintWindowMs?: number;
}

export type Inbound = { seq: number; signed: Signed; message: RelayMessage; core: FrostMsg };
export type SignCheck = (msg: Uint8Array, list: readonly Commitment[]) => CheckResult;
export interface SignOptions {
  /** The bytes this holder decoded and checked itself. A follower refuses a begin for any other bytes (P4.7-08). */
  readonly msg: Uint8Array;
  readonly kind: 'xrpl-multisign' | 'tagged';
  readonly share: KeyShare;
  readonly pub: SlotPublic;
  readonly check: SignCheck;
  /** The two holder indexes asked to sign; the lower one aggregates. */
  readonly pair: readonly [number, number];
  readonly approval?: OfKind<'sign.begin'>['approval'];
  readonly tagged?: { tag: string; parts: readonly Uint8Array[] };
}

/** A ceremony failure that is not a cryptographic check: an abort, a timeout, or a judged complaint. */
export class CeremonyError extends Error {
  readonly code: 'SESSION_ABORTED' | 'TIMEOUT' | 'DKG_COMPLAINT';
  /** The holder index to blame, when one can be named. */
  readonly culprit: number | undefined;
  constructor(code: CeremonyError['code'], detail: string, culprit?: number) {
    super(`${code}: ${detail}`);
    this.name = 'CeremonyError';
    this.code = code;
    this.culprit = culprit;
  }
}

const repairAad = (session: Uint8Array, kind: string, from: number, to: number): Uint8Array =>
  tupleHash('legx/frost-repair/v1', [session, new TextEncoder().encode(kind), u32(from), u32(to)]);
const commitmentOf = (c: { identifier: string; hiding: string; binding: string }): Commitment => ({
  identifier: c.identifier,
  hiding: unhex(c.hiding),
  binding: unhex(c.binding),
});
const wireCommitment = (c: Commitment) => ({
  identifier: c.identifier,
  hiding: hex(c.hiding),
  binding: hex(c.binding),
});

export class FrostHolder {
  readonly me: number;
  readonly identifier: string;
  readonly #cfg: HolderConfig;
  readonly #wire: WireContext;
  readonly #inbox = new Map<string, { cursor: number; items: Inbound[] }>();
  readonly #own = new Map<string, FrostMsg[]>();
  readonly #kem = new Map<string, { publicKey: Uint8Array; secretKey: Uint8Array }>();

  constructor(cfg: HolderConfig) {
    this.#cfg = cfg;
    this.me = cfg.index;
    this.identifier = holderId(cfg.index);
    this.#wire = { dealId: cfg.dealId, slot: cfg.slot, holders: cfg.holders };
  }

  /** Core's view of the holders. */
  directory(sessionId: string): DkgContext {
    return {
      sessionId: unhex(sessionId),
      slot: this.#cfg.slot,
      holders: this.#cfg.holders.map((h) => ({ holder: h.keyId, role: h.role, edPub: h.edPub, deviceId: h.deviceId })),
    };
  }

  async send(message: RelayMessage): Promise<Signed> {
    const signed = await signRelayMessage(message, this.#cfg.keys);
    await this.#cfg.relay.send(signed);
    return signed;
  }

  /** Signs and sends a core message; returns the core copy with the real signature, and keeps it. */
  async #sendCore(sessionId: string, core: FrostMsg, extra?: Parameters<typeof toWire>[2]): Promise<FrostMsg> {
    const signed = await this.send(toWire(this.#wire, core, extra));
    const sent = openRelayed(this.#wire, signed).core;
    this.#own.set(sessionId, [...(this.#own.get(sessionId) ?? []), sent]);
    return sent;
  }

  #header(sessionId: string) {
    return { session_id: sessionId, deal_id: this.#cfg.dealId, slot: this.#cfg.slot, from: this.identifier };
  }

  /** Pulls new messages into the inbox, checking every one; a replayed message of another session is refused. */
  async #pull(sessionId: string): Promise<Inbound[]> {
    const box = this.#inbox.get(sessionId) ?? { cursor: -1, items: [] };
    this.#inbox.set(sessionId, box);
    const got = await this.#cfg.relay.receive(sessionId as never, this.identifier as never, box.cursor);
    for (const r of got) {
      if (box.items.some((i) => i.seq === r.seq)) continue; // a relay that repeats itself
      const { message, core } = openRelayed(this.#wire, r.message);
      if (message.session_id !== sessionId)
        throw new FrostError('SESSION_MISMATCH', 'session id', indexOf(message.from));
      box.items.push({ seq: r.seq, signed: r.message, message, core });
      box.cursor = Math.max(box.cursor, r.seq);
    }
    return box.items;
  }

  /** Waits until `count` messages of `kind` (to me or broadcast) are in; an abort or a complaint ends the wait. */
  async collect(sessionId: string, kind: RelayKind, count: number): Promise<Inbound[]> {
    const deadline = Date.now() + (this.#cfg.timeoutMs ?? 60_000);
    for (;;) {
      const items = await this.#pull(sessionId);
      await this.#stopOnFailure(sessionId, items, kind);
      // one per sender: a duplicate from a sender never counts twice
      const hits = [...new Map(items.filter((i) => i.message.kind === kind).map((i) => [i.message.from, i])).values()];
      if (hits.length >= count) return hits.slice(0, count);
      if (Date.now() > deadline) throw new CeremonyError('TIMEOUT', `${kind} ${hits.length}/${count}`);
      await sleep(this.#cfg.pollMs ?? 10);
    }
  }

  async #stopOnFailure(sessionId: string, items: Inbound[], waitingFor?: RelayKind): Promise<void> {
    const complaint = items.find((i) => i.message.kind === 'dkg.complaint');
    if (complaint && waitingFor !== 'dkg.complaint') throw await this.#judge(sessionId, items, complaint);
    const abort = items.find((i) => i.message.kind === 'abort');
    if (abort && waitingFor !== 'abort')
      throw new CeremonyError(
        'SESSION_ABORTED',
        (abort.message as OfKind<'abort'>).reason,
        indexOf(abort.message.from),
      );
  }

  async #abort(sessionId: string, e: unknown): Promise<void> {
    const code = e instanceof Error && 'code' in e && /^[A-Z_]{1,64}$/.test(String(e.code)) ? String(e.code) : 'FAILED';
    try {
      await this.send({ ...this.#header(sessionId), kind: 'abort', reason: code } as RelayMessage);
    } catch {
      // the session may already be closed by someone else's abort
    }
  }

  /** Runs `fn`; on failure publishes a signed abort that names no share, then rethrows. */
  async #guarded<T>(sessionId: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      if (!(e instanceof CeremonyError && e.code !== 'TIMEOUT')) await this.#abort(sessionId, e);
      throw e;
    }
  }

  // ---------- key generation ----------

  /** All DKG steps for this holder (DESIGN 6.4 rules 2 and 3). A complaint from anyone is judged and names the guilty. */
  async dkg(
    sessionId: string,
    hooks: {
      /** Test hook: a dishonest holder rewrites its own outgoing messages before signing them. */
      tamper?: (m: FrostMsg) => FrostMsg | Promise<FrostMsg>;
      onStep?: (step: DkgStep) => void;
    } = {},
  ): Promise<{ key: DkgKey; ctx: DkgContext; round1: FrostMsg[]; echoes: FrostMsg[] }> {
    return await this.#guarded(sessionId, async () => {
      const ctx = this.directory(sessionId);
      const start = dkgStart(ctx, this.me, { signer: PLACEHOLDER, cipher: this.#cfg.cipher, pinned: this.#cfg.pinned });
      const out = async (m: FrostMsg) => this.#sendCore(sessionId, hooks.tamper ? await hooks.tamper(m) : m);
      const own = await out(start.out[0] as FrostMsg);
      hooks.onStep?.('round1');
      const r1 = (await this.collect(sessionId, 'dkg.round1', 2)).map((i) => i.core);
      const afterR1 = dkgReceiveRound1(start.state, r1);
      const echo = await out(afterR1.out[0] as FrostMsg);
      hooks.onStep?.('echo');
      const echoes = (await this.collect(sessionId, 'dkg.echo', 2)).map((i) => i.core);
      const afterEcho = await dkgReceiveEcho(start.state, echoes);
      for (const m of afterEcho.out) await out(m);
      hooks.onStep?.('round2');
      const r2 = await this.collect(sessionId, 'dkg.round2', 2);
      const done = await dkgReceiveRound2(
        start.state,
        r2.map((i) => i.core),
      );
      if (!done.key) {
        const complaint = done.out[0] as FrostMsg;
        const accused = new DataView((complaint.fields[0] as Uint8Array).buffer).getUint32(0);
        const accusedMessage = (r2.find((i) => i.core.from === accused) as Inbound).signed;
        await this.#sendCore(sessionId, complaint, { accusedMessage });
        throw new CeremonyError('DKG_COMPLAINT', `share from holder ${accused} fails its check`, accused);
      }
      start.state.kemSecret.fill(0);
      await this.#complaintWindow(sessionId);
      return { key: done.key, ctx, round1: [own, ...r1], echoes: [echo, ...echoes] };
    });
  }

  async #complaintWindow(sessionId: string): Promise<void> {
    const end = Date.now() + (this.#cfg.complaintWindowMs ?? 100);
    do {
      await this.#stopOnFailure(sessionId, await this.#pull(sessionId));
      await sleep(this.#cfg.pollMs ?? 10);
    } while (Date.now() < end);
  }

  async #judge(sessionId: string, items: Inbound[], complaint: Inbound): Promise<CeremonyError> {
    const ctx = this.directory(sessionId);
    const own = (this.#own.get(sessionId) ?? []).filter((m) => m.kind === 'dkg-r1');
    const round1 = [...own, ...items.filter((i) => i.message.kind === 'dkg.round1').map((i) => i.core)];
    const verdict = await judgeComplaint(ctx, round1, complaint.core, this.#cfg.cipher);
    return new CeremonyError('DKG_COMPLAINT', verdict.reason, verdict.guilty);
  }

  // ---------- signing ----------

  /** One signing attempt: the lower index of the pair aggregates. Returns the verified aggregate signature. */
  async sign(sessionId: string, o: SignOptions): Promise<Uint8Array> {
    return await this.#guarded(sessionId, () =>
      o.pair[0] === this.me ? this.#aggregator(sessionId, o) : this.#follower(sessionId, o),
    );
  }

  async #aggregator(sessionId: string, o: SignOptions): Promise<Uint8Array> {
    const s = SigningSession.open(o.share, o.pub, o.msg);
    const mine = s.commitment;
    const extra = o.approval ? { approval: o.approval } : {};
    await this.send({
      ...this.#header(sessionId),
      kind: 'sign.begin',
      message: hex(o.msg),
      message_kind: o.kind,
      commitment: wireCommitment(mine),
      ...extra,
      ...(o.tagged ? { tagged: { tag: o.tagged.tag, parts: o.tagged.parts.map(hex) } } : {}),
    });
    const other = (await this.collect(sessionId, 'sign.commit', 1))[0] as Inbound;
    const list = [mine, commitmentOf((other.message as OfKind<'sign.commit'>).commitment)];
    await this.send({
      ...this.#header(sessionId),
      kind: 'sign.request',
      message: hex(o.msg),
      message_kind: o.kind,
      commitments: list.map(wireCommitment),
      ...extra,
    } as unknown as RelayMessage);
    return await this.#shares(sessionId, o, s, list);
  }

  async #follower(sessionId: string, o: SignOptions): Promise<Uint8Array> {
    const begin = (await this.collect(sessionId, 'sign.begin', 1))[0] as Inbound;
    const b = begin.message as OfKind<'sign.begin'>;
    // Only the bytes this holder decoded itself: the relay or the aggregator cannot swap the message (P4.7-08).
    if (b.message !== hex(o.msg)) throw new FrostError('MESSAGE_REFUSED', 'the message differs from the one I checked');
    const s = SigningSession.open(o.share, o.pub, o.msg);
    await this.send({
      ...this.#header(sessionId),
      kind: 'sign.commit',
      message_hash: hex(sha256(o.msg)),
      commitment: wireCommitment(s.commitment),
    } as RelayMessage);
    const req = (await this.collect(sessionId, 'sign.request', 1))[0] as Inbound;
    const r = req.message as OfKind<'sign.request'>;
    if (r.message !== b.message || r.from !== b.from)
      throw new FrostError('SESSION_MISMATCH', 'request differs from the begin');
    return await this.#shares(sessionId, o, s, r.commitments.map(commitmentOf));
  }

  async #shares(
    sessionId: string,
    o: SignOptions,
    s: SigningSession,
    list: readonly Commitment[],
  ): Promise<Uint8Array> {
    const share = s.signShare(o.msg, list, o.check);
    await this.send({
      ...this.#header(sessionId),
      kind: 'sign.share',
      message_hash: hex(sha256(o.msg)),
      commitments_hash: commitmentsDigest(list),
      share: hex(share),
    } as RelayMessage);
    const other = (await this.collect(sessionId, 'sign.share', 1))[0] as Inbound;
    const theirs = other.message as OfKind<'sign.share'>;
    return aggregateChecked(o.pub, list, o.msg, { [this.identifier]: share, [theirs.from]: unhex(theirs.share) });
  }

  /**
   * A holder outside the pair watches a signing session and aggregates the two broadcast shares itself (the phone
   * checking the 2+3 test signature). It signs nothing, so it needs no share.
   */
  async observeSign(sessionId: string, pub: SlotPublic, msg: Uint8Array): Promise<Uint8Array> {
    const req = (await this.collect(sessionId, 'sign.request', 1))[0] as Inbound;
    const r = req.message as OfKind<'sign.request'>;
    if (r.message !== hex(msg)) throw new FrostError('MESSAGE_REFUSED', 'another message');
    const shares = await this.collect(sessionId, 'sign.share', 2);
    const list = r.commitments.map(commitmentOf);
    return aggregateChecked(
      pub,
      list,
      msg,
      Object.fromEntries(shares.map((i) => [i.message.from, unhex((i.message as OfKind<'sign.share'>).share)])),
    );
  }

  // ---------- refresh ----------

  /**
   * A zero-sum re-sharing among `participants` (DESIGN 6.4). Every sub-share is checked against its dealer's Feldman
   * commitments; one that fails names the dealer and aborts, and no share is replaced. The caller installs the new
   * share and only then calls `signDeletion`.
   */
  async refresh(
    sessionId: string,
    o: {
      share: KeyShare;
      pub: SlotPublic;
      participants: readonly number[];
      epoch: number;
      tamper?: (m: FrostMsg) => FrostMsg | Promise<FrostMsg>;
    },
  ): Promise<{ share: KeyShare; pub: SlotPublic; ctx: RefreshContext }> {
    return await this.#guarded(sessionId, async () => {
      const ctx: RefreshContext = { ...this.directory(sessionId), pub: o.pub, participants: o.participants };
      const extra = { epoch: o.epoch };
      const start = refreshStart(ctx, this.me, o.share, { signer: PLACEHOLDER, cipher: this.#cfg.cipher });
      await this.#sendCore(sessionId, start.out[0] as FrostMsg, extra);
      const others = o.participants.length - 1;
      const commits = (await this.collect(sessionId, 'refresh.commit', others)).map((i) => i.core);
      const shares = await refreshReceiveCommits(start.state, commits);
      for (const m of shares.out) await this.#sendCore(sessionId, o.tamper ? await o.tamper(m) : m, extra);
      const subs = (await this.collect(sessionId, 'refresh.subshare', others)).map((i) => i.core);
      const done = await refreshReceiveShares(start.state, subs);
      start.state.kemSecret.fill(0);
      await this.#complaintWindow(sessionId);
      return { ...done, ctx };
    });
  }

  /** The signed statement that this holder deleted its old share; sent to everyone. */
  async signDeletion(sessionId: string, ctx: RefreshContext, newPub: SlotPublic, epoch: number): Promise<void> {
    await this.#sendCore(sessionId, deletionStatement(PLACEHOLDER, ctx, this.me, newPub), { epoch });
  }

  /**
   * The `frost.refreshed` record from the statements in so far (COMPLETE only with every holder's). Does not wait.
   * Throws `SESSION_ABORTED` when a holder aborted after all: then nobody may keep the new shares.
   */
  async refreshStatus(sessionId: string, ctx: RefreshContext, newPub: SlotPublic): Promise<FrostRefreshed> {
    const items = await this.#pull(sessionId);
    await this.#stopOnFailure(sessionId, items);
    const own = (this.#own.get(sessionId) ?? []).filter((m) => m.kind === 'refresh-deleted');
    return refreshedEvent(ctx, newPub, [
      ...own,
      ...items.filter((i) => i.message.kind === 'refresh.deleted').map((i) => i.core),
    ]);
  }

  // ---------- repair ----------

  /** A helper's side of a repair for holder `newIndex` (ZF `repairable` part 1 and 2, with delta commitments). */
  async repairHelp(
    sessionId: string,
    o: { share: KeyShare; pub: SlotPublic; helpers: readonly number[]; newIndex: number },
  ): Promise<void> {
    await this.#guarded(sessionId, async () => {
      await this.#hello(sessionId);
      const hellos = await this.collect(sessionId, 'repair.hello', 2);
      const kemOf = (idx: number) => {
        const m = hellos.find((h) => indexOf(h.message.from) === idx)?.message as OfKind<'repair.hello'> | undefined;
        const k = m && fromBase64Strict(m.kem_pub);
        if (!k) throw new FrostError('REPAIR_CONTRIBUTION_INVALID', `hello from ${idx}`, idx);
        return k;
      };
      const { deltas, commitments } = repairDelta(o.pub, o.helpers, o.share, o.newIndex);
      const dc = [...commitments].map(([to, c]) => ({ to: holderId(to), commitment: hex(c) }));
      const sid = unhex(sessionId);
      const sealTo = async (to: number, kind: string, pt: Uint8Array) =>
        sealedBox(
          this.#cfg.holders[to - 1] as HolderInfo,
          await this.#cfg.cipher.seal(kemOf(to), repairAad(sid, kind, this.me, to), pt),
        );
      const other = o.helpers.find((h) => h !== this.me) as number;
      const delta = (to: number, pt: Uint8Array) =>
        sealTo(to, 'delta', pt).then((box) =>
          this.send({
            ...this.#header(sessionId),
            kind: 'repair.delta',
            to: holderId(to),
            box,
            delta_commitments: dc,
          } as RelayMessage),
        );
      await delta(other, deltas.get(other) as Uint8Array);
      await delta(o.newIndex, new Uint8Array(32)); // the new holder needs only the public commitments
      const incoming = (await this.collect(sessionId, 'repair.delta', 1))[0] as Inbound;
      const msg = incoming.message as OfKind<'repair.delta'>;
      const from = indexOf(msg.from);
      const theirs = new Map(msg.delta_commitments.map((c) => [indexOf(c.to), unhex(c.commitment)]));
      const d = await this.#cfg.cipher.open(
        this.#kemSecret(sessionId),
        repairAad(sid, 'delta', from, this.me),
        boxBytes(msg.box),
      );
      checkDelta(this.me, from, d, theirs);
      const sigma = repairSigma([deltas.get(this.me) as Uint8Array, d]);
      for (const v of [...deltas.values(), d]) v.fill(0);
      await this.send({
        ...this.#header(sessionId),
        kind: 'repair.sigma',
        to: holderId(o.newIndex),
        box: await sealTo(o.newIndex, 'sigma', sigma),
      } as RelayMessage);
      sigma.fill(0);
    });
  }

  /** The new holder's side: checks both helpers' commitments and sigmas; the share must match its verifying share. */
  async repairReceive(sessionId: string, o: { pub: SlotPublic; helpers: readonly number[] }): Promise<KeyShare> {
    return await this.#guarded(sessionId, async () => {
      await this.#hello(sessionId);
      await this.collect(sessionId, 'repair.hello', 2);
      const deltas = await this.collect(sessionId, 'repair.delta', 2);
      const sigmas = await this.collect(sessionId, 'repair.sigma', 2);
      const sid = unhex(sessionId);
      const contributions = [];
      for (const dIn of deltas) {
        const dm = dIn.message as OfKind<'repair.delta'>;
        const from = indexOf(dm.from);
        const sm = sigmas.find((x) => x.message.from === dm.from)?.message as OfKind<'repair.sigma'> | undefined;
        if (!sm) throw new FrostError('REPAIR_CONTRIBUTION_INVALID', `helper ${from}`, from);
        const sigma = await this.#cfg.cipher.open(
          this.#kemSecret(sessionId),
          repairAad(sid, 'sigma', from, this.me),
          boxBytes(sm.box),
        );
        contributions.push({
          from,
          sigma,
          commitments: new Map(dm.delta_commitments.map((c) => [indexOf(c.to), unhex(c.commitment)])),
        });
      }
      try {
        return repairFinish(o.pub, this.me, contributions);
      } finally {
        for (const c of contributions) c.sigma.fill(0);
      }
    });
  }

  #kemSecret(sessionId: string): Uint8Array {
    return (this.#kem.get(sessionId) as { secretKey: Uint8Array }).secretKey;
  }

  async #hello(sessionId: string): Promise<void> {
    const kem = this.#cfg.cipher.keygen();
    this.#kem.set(sessionId, kem);
    await this.send({
      ...this.#header(sessionId),
      kind: 'repair.hello',
      kem_pub: toBase64(kem.publicKey),
    } as RelayMessage);
  }
}

/** DKG progress for the screens. */
export type DkgStep = 'round1' | 'echo' | 'round2';
