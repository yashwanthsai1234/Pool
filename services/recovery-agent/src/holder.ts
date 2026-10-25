// A FROST share holder that talks to the relay: the same code is the scripted participant in the tests and the
// participant inside the recovery agent. It moves messages and calls task 1.15's pure round functions; it adds no
// cryptography of its own. A relay is untrusted, so every incoming message is checked (both signatures, the session,
// the sender's pinned key) before it is used, and a failed round sends a signed `abort` that names no share.
// Source: https://frost.zfnd.org/tutorial/dkg.html (broadcast channel; round 2 authenticated and confidential)
// Source: https://www.rfc-editor.org/rfc/rfc9591#section-5 (two-round signing)
import type { FrostRelayPort, RelayedMessage } from '@legx/contracts/ports';
import type { RelayMessage } from '@legx/coordinator/frost/schema';
import { bytesToHex, hexToBytes, sha256, tupleHash } from '@legx/core/dealcore';
import {
  aggregateChecked,
  type Commitment,
  FrostError,
  type FrostMsg,
  type HolderKey,
  holderId,
  idScalar,
  type KeyShare,
  type Role,
  SigningSession,
  type SlotName,
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
import { ed25519 } from '@noble/curves/ed25519.js';
import { XWING_ENC_LENGTH } from './cipher.ts';
import { type SignBegin, type SignCheck, type SignContext, type SignMessage, taggedMessage } from './policy.ts';

import {
  type HolderInfo,
  type HolderKeys,
  openRelayed,
  type Signed,
  signRelayMessage,
  toWire,
  type WireContext,
} from './wire.ts';

const hex = bytesToHex;
/** Strict base64 (relay input is untrusted): a malformed field fails the message instead of decoding to garbage. */
const b64d = (s: string): Uint8Array => {
  const b = fromBase64Strict(s);
  if (!b) throw new Error('malformed base64 field');
  return b;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export interface HolderConfig {
  /** 1, 2 or 3: the position in the slot's canonical role order. */
  readonly index: number;
  readonly keys: HolderKeys;
  readonly dealId: string;
  readonly slot: SlotName;
  readonly holders: readonly HolderInfo[];
  readonly relay: FrostRelayPort;
  readonly cipher: ShareCipher;
  readonly pinned: PinCheck;
  readonly pollMs?: number;
  readonly timeoutMs?: number;
  /** After round 3 a holder waits this long for a complaint before it returns its key (DESIGN 6.4 rule 3). */
  readonly complaintWindowMs?: number;
}

type Inbound = { seq: number; signed: Signed; message: RelayMessage; core: FrostMsg };

export type { SignBegin, SignCheck, SignContext };
export interface SignOptions {
  /** The message to sign. Required for the aggregator; a follower that leaves it out signs what the begin carries. */
  readonly msg?: Uint8Array;
  readonly kind: 'xrpl-multisign' | 'tagged';
  readonly share: KeyShare;
  readonly pub: SlotPublic;
  readonly check: SignCheck;
  /** The two holder indexes asked to sign; the lower one aggregates. */
  readonly pair: readonly [number, number];
  /** A server holder marks the commitment used atomically before it signs (task 1.15 `releaseShare`). */
  readonly release?: (commitment: Commitment, sign: () => Uint8Array, msg: Uint8Array) => Promise<Uint8Array>;
  /** A signer that has seen a message it does not want to sign calls this before the check (agent policy). */
  readonly onBegin?: (begin: SignBegin, from: HolderInfo) => void | Promise<void>;
  readonly approval?: SignBegin['approval'];
  /** A tagged message travels with its preimage: `msg` must be `tupleHash(tag, parts)`. */
  readonly tagged?: { tag: string; parts: readonly Uint8Array[] };
  /** Called after the aggregate verified. */
  readonly onSigned?: (info: {
    signature: Uint8Array;
    shares: string[];
    list: readonly Commitment[];
    msg: Uint8Array;
  }) => void | Promise<void>;
}

/** Commitment-list digest that goes in `sign.share` (informational; the share is bound to the list by RFC 9591 itself). */
const commitmentsDigest = (list: readonly Commitment[]): string =>
  hex(
    tupleHash(
      'legx/frost-commitments/v1',
      [...list]
        .sort((a, b) => (idScalar(a.identifier) < idScalar(b.identifier) ? -1 : 1))
        .flatMap((c) => [hexToBytes(c.identifier), c.hiding, c.binding]),
    ),
  );

/** A ceremony failure that is not a cryptographic check: an abort, a timeout, or a judged complaint (`culprit` = holder index). */
export class CeremonyError extends Error {
  readonly code: 'SESSION_ABORTED' | 'TIMEOUT' | 'DKG_COMPLAINT';
  readonly culprit: number | undefined;
  constructor(code: CeremonyError['code'], detail: string, culprit?: number) {
    super(`${code}: ${detail}`);
    this.name = 'CeremonyError';
    this.code = code;
    this.culprit = culprit;
  }
}

export class FrostHolder {
  readonly me: number;
  readonly identifier: string;
  readonly #cfg: HolderConfig;
  readonly #wire: WireContext;
  readonly #inbox = new Map<string, { cursor: number; items: Inbound[] }>();
  readonly #ownRound1 = new Map<string, FrostMsg>();
  readonly #ownDeletion = new Map<string, FrostMsg>();

  constructor(cfg: HolderConfig) {
    this.#cfg = cfg;
    this.me = cfg.index;
    this.identifier = holderId(cfg.index);
    this.#wire = { dealId: cfg.dealId, slot: cfg.slot, holders: cfg.holders };
  }

  /** Core's view of the holders (device ids distinct, keys pinned). */
  directory(sessionId: Uint8Array): DkgContext {
    const holders: HolderKey[] = this.#cfg.holders.map((h) => ({
      holder: h.keyId,
      role: h.role as Role,
      edPub: h.edPub,
      deviceId: h.deviceId,
    }));
    return { sessionId, slot: this.#cfg.slot, holders };
  }

  readonly signer = {
    sign: (m: Uint8Array): Uint8Array => ed25519.sign(m, this.#cfg.keys.edSecret),
  };

  async send(message: RelayMessage): Promise<void> {
    await this.#cfg.relay.send(signRelayMessage(message, this.#cfg.keys));
  }

  async #sendCore(core: FrostMsg, extra?: Parameters<typeof toWire>[2]): Promise<void> {
    await this.#cfg.relay.send(signRelayMessage(toWire(this.#wire, core, extra), this.#cfg.keys));
  }

  /** Pulls new messages of a session into the inbox, checking every one. An abort from anyone ends the round. */
  async #pull(sessionId: string): Promise<Inbound[]> {
    const box = this.#inbox.get(sessionId) ?? { cursor: -1, items: [] };
    this.#inbox.set(sessionId, box);
    const got: readonly RelayedMessage[] = await this.#cfg.relay.receive(
      sessionId as never,
      this.identifier as never,
      box.cursor,
    );
    for (const r of got) {
      const { decoded, core } = openRelayed(this.#wire, r.message);
      // a message of another session is a replay, whatever its signatures say
      if (decoded.message.session_id !== sessionId)
        throw new FrostError('SESSION_MISMATCH', 'session id', Number(idScalar(decoded.message.from)));
      box.items.push({ seq: r.seq, signed: r.message, message: decoded.message, core });
      box.cursor = Math.max(box.cursor, r.seq);
    }
    return box.items;
  }

  /** Waits until `count` messages of `kind` (to me or broadcast) are in, throwing on an abort or a timeout. */
  async collect(sessionId: string, kind: RelayMessage['kind'], count: number): Promise<Inbound[]> {
    const deadline = Date.now() + (this.#cfg.timeoutMs ?? 10_000);
    for (;;) {
      const items = await this.#pull(sessionId);
      const abort = items.find((i) => i.message.kind === 'abort');
      if (abort && kind !== 'abort')
        throw new CeremonyError(
          'SESSION_ABORTED',
          (abort.message as { reason: string }).reason,
          Number(idScalar(abort.message.from)),
        );
      const hits = items.filter((i) => i.message.kind === kind);
      if (hits.length >= count) return hits.slice(0, count);
      if (Date.now() > deadline) throw new CeremonyError('TIMEOUT', `${kind} ${hits.length}/${count}`);
      await sleep(this.#cfg.pollMs ?? 5);
    }
  }

  async #abort(sessionId: string, e: unknown): Promise<void> {
    const code = e instanceof Error && 'code' in e && /^[A-Z_]{1,64}$/.test(String(e.code)) ? String(e.code) : 'FAILED';
    try {
      await this.send({
        session_id: sessionId,
        deal_id: this.#cfg.dealId,
        slot: this.#cfg.slot,
        from: this.identifier,
        kind: 'abort',
        reason: code,
      } as RelayMessage);
    } catch {
      // the session may already be closed by someone else's abort
    }
  }

  /** Runs `fn`; on failure, publishes a signed abort that names no share, then rethrows. */
  async guarded<T>(sessionId: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      if (!(e instanceof CeremonyError && e.code === 'SESSION_ABORTED')) await this.#abort(sessionId, e);
      throw e;
    }
  }

  // ---------- key generation ----------

  /** All five DKG steps for this holder. A complaint from anyone is judged here, and the DKG aborts naming the guilty. */
  async dkg(
    sessionId: string,
    hooks: { tamper?: (m: FrostMsg) => Promise<FrostMsg> | FrostMsg } = {},
  ): Promise<{
    key: DkgKey;
    ctx: DkgContext;
    round1: FrostMsg[];
    echoes: FrostMsg[];
  }> {
    return await this.guarded(sessionId, async () => {
      const ctx = this.directory(hexToBytes(sessionId));
      const deps = { signer: this.signer, cipher: this.#cfg.cipher, pinned: this.#cfg.pinned };
      const start = dkgStart(ctx, this.me, deps);
      const own = start.out[0] as FrostMsg;
      this.#ownRound1.set(sessionId, own);
      await this.#sendCore(own);
      const r1 = (await this.collect(sessionId, 'dkg.round1', 2)).map((i) => i.core);
      const afterR1 = dkgReceiveRound1(start.state, r1);
      await this.#sendCore(afterR1.out[0] as FrostMsg);
      const echoes = (await this.collect(sessionId, 'dkg.echo', 2)).map((i) => i.core);
      const afterEcho = await dkgReceiveEcho(start.state, echoes);
      for (const m of afterEcho.out) await this.#sendCore(hooks.tamper ? await hooks.tamper(m) : m);
      const r2 = await this.#collectRound2(sessionId);
      const done = await dkgReceiveRound2(
        start.state,
        r2.map((i) => i.core),
      );
      if (!done.key) {
        const complaint = done.out[0] as FrostMsg;
        const accused = new DataView(
          (complaint.fields[0] as Uint8Array).buffer,
          (complaint.fields[0] as Uint8Array).byteOffset,
        ).getUint32(0);
        const accusedMessage = r2.find((i) => i.core.from === accused) as Inbound;
        await this.#sendCore(complaint, {
          complaint: { accusedMessage: accusedMessage.signed, decryptedShare: new Uint8Array(32) },
        });
        throw new CeremonyError('DKG_COMPLAINT', `holder ${this.me} complained about ${accused}`, accused);
      }
      await this.#complaintWindow(sessionId);
      const all = [own, ...r1];
      return { key: done.key, ctx, round1: all, echoes: [afterR1.out[0] as FrostMsg, ...echoes] };
    });
  }

  /** Round-2 messages to me; a complaint from anyone ends the wait with a judgement. */
  async #collectRound2(sessionId: string): Promise<Inbound[]> {
    const deadline = Date.now() + (this.#cfg.timeoutMs ?? 10_000);
    for (;;) {
      const items = await this.#pull(sessionId);
      const complaint = items.find((i) => i.message.kind === 'dkg.complaint');
      if (complaint) throw await this.#judge(items, complaint);
      const abort = items.find((i) => i.message.kind === 'abort');
      if (abort) throw new CeremonyError('SESSION_ABORTED', (abort.message as { reason: string }).reason);
      const mine = items.filter((i) => i.message.kind === 'dkg.round2');
      if (mine.length >= 2) return mine.slice(0, 2);
      if (Date.now() > deadline) throw new CeremonyError('TIMEOUT', 'dkg.round2');
      await sleep(this.#cfg.pollMs ?? 5);
    }
  }

  /** A complaint or an abort that arrives in the window means the DKG failed, whatever this holder's own shares say. */
  async #complaintWindow(sessionId: string): Promise<void> {
    const end = Date.now() + (this.#cfg.complaintWindowMs ?? 50);
    do {
      const items = await this.#pull(sessionId);
      const complaint = items.find((i) => i.message.kind === 'dkg.complaint');
      if (complaint) throw await this.#judge(items, complaint);
      const abort = items.find((i) => i.message.kind === 'abort');
      if (abort) throw new CeremonyError('SESSION_ABORTED', (abort.message as { reason: string }).reason);
      await sleep(this.#cfg.pollMs ?? 5);
    } while (Date.now() < end);
  }

  async #judge(items: Inbound[], complaint: Inbound): Promise<CeremonyError> {
    const ctx = this.directory(complaint.core.session);
    const own = this.#ownRound1.get(bytesToHex(complaint.core.session));
    const round1 = [...(own ? [own] : []), ...items.filter((i) => i.message.kind === 'dkg.round1').map((i) => i.core)];
    const verdict = await judgeComplaint(ctx, round1, complaint.core, this.#cfg.cipher);
    return new CeremonyError('DKG_COMPLAINT', verdict.reason, verdict.guilty);
  }

  // ---------- signing ----------

  /** One signing attempt in `sessionId`: the lower index of the pair aggregates. Returns the verified aggregate signature. */
  async sign(sessionId: string, o: SignOptions): Promise<Uint8Array> {
    return await this.guarded(sessionId, async () => {
      const session = o.pair[0] === this.me ? await this.#aggregator(sessionId, o) : await this.#follower(sessionId, o);
      return session;
    });
  }

  #header(sessionId: string) {
    return { session_id: sessionId, deal_id: this.#cfg.dealId, slot: this.#cfg.slot, from: this.identifier };
  }

  async #aggregator(sessionId: string, o: SignOptions): Promise<Uint8Array> {
    if (!o.msg) throw new FrostError('INPUT_INVALID', 'the aggregator needs the message');
    const msg = o.msg;
    const s = SigningSession.open(o.share, o.pub, msg);
    const mine = s.commitment;
    const beginMsg: SignBegin = {
      ...this.#header(sessionId),
      kind: 'sign.begin',
      message: hex(msg),
      message_kind: o.kind,
      commitment: { identifier: mine.identifier, hiding: hex(mine.hiding), binding: hex(mine.binding) },
      ...(o.approval ? { approval: o.approval } : {}),
      ...(o.tagged ? { tagged: { tag: o.tagged.tag, parts: o.tagged.parts.map(hex) } } : {}),
    } as SignBegin;
    await this.send(beginMsg);
    const other = (await this.collect(sessionId, 'sign.commit', 1))[0] as Inbound;
    const theirs = commitmentOf(other.message as Extract<RelayMessage, { kind: 'sign.commit' }>);
    const list = [mine, theirs];
    const request = {
      ...this.#header(sessionId),
      kind: 'sign.request',
      message: hex(msg),
      message_kind: o.kind,
      commitments: list.map((c) => ({ identifier: c.identifier, hiding: hex(c.hiding), binding: hex(c.binding) })),
      ...(o.approval ? { approval: o.approval } : {}),
    } as RelayMessage;
    await this.send(request);
    return await this.#shares(sessionId, o, msg, s, list, request as SignMessage, beginMsg);
  }

  async #follower(sessionId: string, o: SignOptions): Promise<Uint8Array> {
    const begin = (await this.collect(sessionId, 'sign.begin', 1))[0] as Inbound;
    const b = begin.message as Extract<RelayMessage, { kind: 'sign.begin' }>;
    const from = this.#cfg.holders.find((h) => h.identifier === b.from) as HolderInfo;
    const msg = hexToBytes(b.message);
    if (o.msg && hex(o.msg) !== b.message) throw new FrostError('SESSION_MISMATCH', 'message differs from the begin');
    if (b.tagged && hex(taggedMessage(b.tagged.tag, b.tagged.parts.map(hexToBytes))) !== b.message)
      throw new FrostError('SESSION_MISMATCH', 'the message is not the hash of its preimage');
    await o.onBegin?.(b, from);
    const s = SigningSession.open(o.share, o.pub, msg);
    const c = s.commitment;
    await this.send({
      ...this.#header(sessionId),
      kind: 'sign.commit',
      message_hash: hex(sha256(msg)),
      commitment: { identifier: c.identifier, hiding: hex(c.hiding), binding: hex(c.binding) },
    } as RelayMessage);
    const req = (await this.collect(sessionId, 'sign.request', 1))[0] as Inbound;
    const r = req.message as SignMessage;
    if (r.message !== b.message || r.from !== b.from)
      throw new FrostError('SESSION_MISMATCH', 'request differs from the begin');
    const list = r.commitments.map(commitmentOf);
    return await this.#shares(sessionId, o, msg, s, list, r, b);
  }

  /** Signs my share (through the atomic nonce release when the holder is a server), then waits for the other and aggregates. */
  async #shares(
    sessionId: string,
    o: SignOptions,
    msg: Uint8Array,
    s: SigningSession,
    list: readonly Commitment[],
    request: SignMessage,
    begin: SignBegin,
  ): Promise<Uint8Array> {
    const mine = list.find((c) => c.identifier === this.identifier) as Commitment;
    const produce = () => s.signShare(msg, list, (m, l) => o.check(m, l, { request, begin }));
    const share = o.release ? await o.release(mine, produce, msg) : produce();
    await this.send({
      ...this.#header(sessionId),
      kind: 'sign.share',
      message_hash: hex(sha256(msg)),
      commitments_hash: commitmentsDigest(list),
      share: hex(share),
    } as RelayMessage);
    const other = (await this.collect(sessionId, 'sign.share', 1))[0] as Inbound;
    const theirs = other.message as Extract<RelayMessage, { kind: 'sign.share' }>;
    const shares = { [this.identifier]: share, [theirs.from]: hexToBytes(theirs.share) };
    const signature = aggregateChecked(o.pub, list, msg, shares);
    await o.onSigned?.({ signature, shares: Object.keys(shares), list, msg });
    return signature;
  }

  // ---------- refresh ----------

  /**
   * A zero-sum re-sharing among `participants` (DESIGN 6.4). Every sub-share is checked against its dealer's Feldman
   * commitments; one that fails names the dealer and aborts, and no share is replaced. The caller installs the new
   * share and only then calls `signDeletion`: a deletion statement is a statement about the old share.
   */
  async refresh(
    sessionId: string,
    o: {
      share: KeyShare;
      pub: SlotPublic;
      participants: readonly number[];
      epoch: number;
      /** Test hook: rewrites an outgoing sub-share (a dishonest dealer). */
      tamper?: (m: FrostMsg) => Promise<FrostMsg> | FrostMsg;
    },
  ): Promise<{ share: KeyShare; pub: SlotPublic; ctx: RefreshContext }> {
    return await this.guarded(sessionId, async () => {
      const dir = this.directory(hexToBytes(sessionId));
      const ctx: RefreshContext = { ...dir, pub: o.pub, participants: o.participants };
      const refreshExtra = { refresh: { epoch: o.epoch } };
      const start = refreshStart(ctx, this.me, o.share, { signer: this.signer, cipher: this.#cfg.cipher });
      await this.#sendCore(start.out[0] as FrostMsg, refreshExtra);
      const others = o.participants.length - 1;
      const commits = (await this.collect(sessionId, 'refresh.commit', others)).map((i) => i.core);
      const shares = await refreshReceiveCommits(start.state, commits);
      for (const m of shares.out) await this.#sendCore(o.tamper ? await o.tamper(m) : m, refreshExtra);
      const subs = (await this.collect(sessionId, 'refresh.subshare', others)).map((i) => i.core);
      const done = await refreshReceiveShares(start.state, subs);
      // like the DKG: nobody installs a new share while a failed round may still be announced
      await this.#complaintWindow(sessionId);
      return { ...done, ctx };
    });
  }

  /** The signed statement that this holder deleted its old share after the refresh; sent to everyone. */
  async signDeletion(sessionId: string, ctx: RefreshContext, newPub: SlotPublic, epoch: number): Promise<void> {
    const statement = deletionStatement(this.signer, ctx, this.me, newPub);
    this.#ownDeletion.set(sessionId, statement);
    await this.#sendCore(statement, { refresh: { epoch } });
  }

  /**
   * Reads the deletion statements that have arrived and builds the `frost.refreshed` record from them. It is COMPLETE
   * only when every remaining holder signed one (P1.15-18); otherwise it lists who is missing. It does not wait.
   */
  async refreshStatus(sessionId: string, ctx: RefreshContext, newPub: SlotPublic): Promise<FrostRefreshed> {
    const items = await this.#pull(sessionId);
    const own = this.#ownDeletion.get(sessionId);
    return refreshedEvent(ctx, newPub, [
      ...(own ? [own] : []),
      ...items.filter((i) => i.message.kind === 'refresh.deleted').map((i) => i.core),
    ]);
  }

  // ---------- repair ----------

  /**
   * A new device gets a fresh share with two helpers and without the old share (ZF `repairable`, DESIGN 6.4). The
   * helpers run this with `newIndex` set to the index being repaired; the new holder runs `repairReceive`.
   */
  async repairHelp(
    sessionId: string,
    o: { share: KeyShare; pub: SlotPublic; helpers: readonly number[]; newIndex: number },
  ) {
    return await this.guarded(sessionId, async () => {
      await this.#hello(sessionId);
      const hellos = await this.collect(sessionId, 'repair.hello', 2);
      const kem = (idx: number) => this.#kemOf(hellos, idx);
      const { deltas, commitments } = repairDelta(o.pub, o.helpers, o.share, o.newIndex);
      const mine = [...commitments].map(([to, c]) => ({ to: holderId(to), commitment: hex(c) }));
      const dc = mine as unknown as Extract<RelayMessage, { kind: 'repair.delta' }>['delta_commitments'];
      const sid = hexToBytes(sessionId);
      const sealTo = async (to: number, kind: string, pt: Uint8Array) =>
        sealedBox(
          this.#cfg.holders[to - 1] as HolderInfo,
          await this.#cfg.cipher.seal(kem(to), repairAad(sid, kind, this.me, to), pt),
        );
      const other = o.helpers.find((h) => h !== this.me) as number;
      await this.send({
        ...this.#header(sessionId),
        kind: 'repair.delta',
        to: holderId(other),
        box: await sealTo(other, 'delta', deltas.get(other) as Uint8Array),
        delta_commitments: dc,
      } as RelayMessage);
      // the new holder also gets the public commitments (its box holds nothing secret)
      await this.send({
        ...this.#header(sessionId),
        kind: 'repair.delta',
        to: holderId(o.newIndex),
        box: await sealTo(o.newIndex, 'delta', new Uint8Array(32)),
        delta_commitments: dc,
      } as RelayMessage);
      const incoming = (await this.collect(sessionId, 'repair.delta', 1))[0] as Inbound;
      const msg = incoming.message as Extract<RelayMessage, { kind: 'repair.delta' }>;
      const from = indexOf(msg.from);
      const theirCommit = new Map(msg.delta_commitments.map((c) => [indexOf(c.to), hexToBytes(c.commitment)]));
      const delta = await this.#cfg.cipher.open(
        this.#kemSecret(sessionId),
        repairAad(sid, 'delta', from, this.me),
        boxBytes(msg.box),
      );
      checkDelta(this.me, from, delta, theirCommit);
      const sigma = repairSigma([deltas.get(this.me) as Uint8Array, delta]);
      await this.send({
        ...this.#header(sessionId),
        kind: 'repair.sigma',
        to: holderId(o.newIndex),
        box: await sealTo(o.newIndex, 'sigma', sigma),
      } as RelayMessage);
    });
  }

  /** The new holder's side: collects both helpers' commitments and sigmas, and installs the share only if it fits. */
  async repairReceive(sessionId: string, o: { pub: SlotPublic; helpers: readonly number[] }): Promise<KeyShare> {
    return await this.guarded(sessionId, async () => {
      await this.#hello(sessionId);
      await this.collect(sessionId, 'repair.hello', 2);
      const deltas = await this.collect(sessionId, 'repair.delta', 2);
      const sigmas = await this.collect(sessionId, 'repair.sigma', 2);
      const sid = hexToBytes(sessionId);
      const contributions = [];
      for (const d of deltas) {
        const dm = d.message as Extract<RelayMessage, { kind: 'repair.delta' }>;
        const from = indexOf(dm.from);
        const sm = sigmas.find((x) => x.message.from === dm.from)?.message as Extract<
          RelayMessage,
          { kind: 'repair.sigma' }
        >;
        const sigma = await this.#cfg.cipher.open(
          this.#kemSecret(sessionId),
          repairAad(sid, 'sigma', from, this.me),
          boxBytes(sm.box),
        );
        contributions.push({
          from,
          sigma,
          commitments: new Map(dm.delta_commitments.map((c) => [indexOf(c.to), hexToBytes(c.commitment)])),
        });
      }
      return repairFinish(o.pub, this.me, contributions);
    });
  }

  readonly #kem = new Map<string, { publicKey: Uint8Array; secretKey: Uint8Array }>();
  #kemSecret(sessionId: string): Uint8Array {
    return (this.#kem.get(sessionId) as { secretKey: Uint8Array }).secretKey;
  }
  #kemOf(hellos: Inbound[], idx: number): Uint8Array {
    const m = hellos.find((h) => indexOf(h.message.from) === idx)?.message as Extract<
      RelayMessage,
      { kind: 'repair.hello' }
    >;
    return b64d(m.kem_pub);
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

const commitmentOf = (
  m:
    | { commitment?: { identifier: string; hiding: string; binding: string } }
    | { identifier: string; hiding: string; binding: string },
): Commitment => {
  const c =
    'commitment' in m && m.commitment ? m.commitment : (m as { identifier: string; hiding: string; binding: string });
  return { identifier: c.identifier, hiding: hexToBytes(c.hiding), binding: hexToBytes(c.binding) };
};
const indexOf = (id: string): number => Number(idScalar(id));
const repairAad = (session: Uint8Array, kind: string, from: number, to: number): Uint8Array =>
  tupleHash('legx/frost-repair/v1', [session, new TextEncoder().encode(kind), u32(from), u32(to)]);
const boxBytes = (b: { enc: string; ciphertext: string }): Uint8Array =>
  new Uint8Array([...b64d(b.enc), ...b64d(b.ciphertext)]);
const sealedBox = (to: HolderInfo, blob: Uint8Array) => ({
  suite: 'hpke-xwing-v1' as const,
  recipient_key_id: to.keyId,
  enc: toBase64(blob.slice(0, XWING_ENC_LENGTH)),
  ciphertext: toBase64(blob.slice(XWING_ENC_LENGTH)),
});
