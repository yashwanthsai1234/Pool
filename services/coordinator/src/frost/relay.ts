// The FROST relay (DESIGN 6.3, 6.4; IMPLEMENTATION 3.9): a message box with timeouts. It routes by
// (session, round, participant), refuses any message whose enrollment signatures do not verify under the key pinned
// in the `enrollment_key` table for that participant, and forwards the stored bytes. It imports no signing, share or
// nonce function: a test pins that (P3.9-02). A stalled signing attempt times out and the next pair is asked in a new
// session with fresh commitments; the old attempt is closed so its late messages cannot mix with the new one.
// Source: https://frost.zfnd.org/tutorial/dkg.html (round 2 needs authenticated, confidential channels)
// Source: https://www.rfc-editor.org/rfc/rfc9591#section-5 (fresh nonces for every signing round)
import { randomBytes } from 'node:crypto';
import type { FrostSignedMessage } from '@legx/contracts/frost';
import type { FrostRelayPort, RelayedMessage } from '@legx/contracts/ports';
import { fromBase64Strict, mldsaVerify } from '@legx/core/pq';
import { KeyNotRecorded } from '@legx/db';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { z } from 'zod';
import type { CoordinatorDeps } from '../deps.ts';
import { ApiError } from '../errors.ts';
import { DIRECT_KINDS, decodeSigned, type RelayKind, recipientOf, signedBytes, WireError } from './schema.ts';
import type { Participant, Purpose, RelayStore, SessionRow } from './store.ts';

/** The ML-DSA context both halves use for relay messages (the wire note in schema.ts; request to contracts in 3.9.md). */
const RELAY_CONTEXT = 'legx/dsse/v1';

export const DEFAULT_SIGN_TIMEOUT_MS = 30_000;

const KINDS: Record<Purpose, readonly RelayKind[]> = {
  dkg: ['dkg.round1', 'dkg.echo', 'dkg.round2', 'dkg.complaint', 'abort'],
  sign: ['sign.begin', 'sign.request', 'sign.commit', 'sign.share', 'abort'],
  refresh: ['refresh.commit', 'refresh.subshare', 'refresh.deleted', 'abort'],
  repair: ['repair.hello', 'repair.delta', 'repair.sigma', 'abort'],
};

/** What must already be in the session before a kind is accepted (the honest relay keeps the rounds in order). */
const NEEDS: Partial<Record<RelayKind, (have: ReadonlySet<string>, s: SessionRow) => boolean>> = {
  'dkg.echo': (have) => count(have, 'dkg.round1') === 3,
  'dkg.round2': (have) => count(have, 'dkg.echo') === 3,
  'dkg.complaint': (have) => count(have, 'dkg.round2') >= 1,
  'refresh.subshare': (have, s) => count(have, 'refresh.commit') === s.participants.length,
  'repair.delta': (have) => count(have, 'repair.hello') === 3,
  'repair.sigma': (have) => count(have, 'repair.hello') === 3,
  'sign.share': (have) => count(have, 'sign.request') >= 1,
};
const count = (have: ReadonlySet<string>, kind: string): number =>
  [...have].filter((h) => h.startsWith(`${kind}|`)).length;

export type RelayCode =
  | 'malformed'
  | 'session_unknown'
  | 'session_closed'
  | 'wrong_deal_or_slot'
  | 'kind_not_allowed'
  | 'sender_unknown'
  | 'key_not_pinned'
  | 'key_mismatch'
  | 'bad_signature'
  | 'not_in_pair'
  | 'bad_recipient'
  | 'out_of_order'
  | 'duplicate';

const STATUS: Record<RelayCode, number> = {
  malformed: 400,
  session_unknown: 404,
  session_closed: 409,
  wrong_deal_or_slot: 403,
  kind_not_allowed: 403,
  sender_unknown: 403,
  key_not_pinned: 403,
  key_mismatch: 403,
  bad_signature: 403,
  not_in_pair: 403,
  bad_recipient: 400,
  out_of_order: 409,
  duplicate: 409,
};

export const refuse = (code: RelayCode, detail?: string): ApiError =>
  new ApiError(STATUS[code], `relay_${code}`, detail ? `${code}: ${detail}` : code);

export interface SessionStatusView {
  readonly sessionId: string;
  readonly status: SessionRow['status'];
  readonly attempt: number;
  readonly pair: readonly [string, string] | null;
  readonly deadlineMs: number | null;
  /** Set when this attempt timed out: the session to use next, with fresh commitments. */
  readonly next: string | null;
}

export interface RelayOptions {
  readonly now?: () => number;
  readonly signTimeoutMs?: number;
}

const PAIRS: readonly (readonly [number, number])[] = [
  [1, 2],
  [1, 3],
  [2, 3],
];

export class FrostRelay implements FrostRelayPort {
  readonly #deps: Pick<CoordinatorDeps, 'db' | 'ledger'>;
  readonly #store: RelayStore;
  readonly #now: () => number;
  readonly #timeout: number;

  constructor(deps: Pick<CoordinatorDeps, 'db' | 'ledger'>, store: RelayStore, opts: RelayOptions = {}) {
    this.#deps = deps;
    this.#store = store;
    this.#now = opts.now ?? Date.now;
    this.#timeout = opts.signTimeoutMs ?? DEFAULT_SIGN_TIMEOUT_MS;
  }

  /**
   * Opens a session. Every participant must be a pinned key of this deal and slot, in the role stated, and the three
   * must be the slot's holders: the coordinator cannot add a key of its own choosing (DESIGN 6.3).
   */
  async openSession(input: {
    dealId: string;
    slot: string;
    purpose: Purpose;
    participants: readonly Participant[];
    pair?: readonly [string, string];
  }): Promise<string> {
    const { dealId, slot, purpose, participants } = input;
    if (new Set(participants.map((p) => p.identifier)).size !== participants.length || participants.length !== 3)
      throw refuse('malformed', 'three distinct participants');
    for (const p of participants) {
      const row = await this.#pinned(p.keyId);
      if (row.deal_id !== dealId || row.slot !== slot || row.holder_role !== p.role)
        throw refuse('key_mismatch', p.keyId);
    }
    // The opener names the signing pair (contracts `frost.openSession.pair`, task 4.7): two distinct participants.
    if (
      input.pair &&
      (input.pair[0] === input.pair[1] || !input.pair.every((id) => participants.some((p) => p.identifier === id)))
    )
      throw refuse('malformed', 'the pair must be two distinct participants');
    const pair =
      purpose === 'sign' ? (input.pair ?? this.#pairIds(participants, PAIRS[0] as readonly [number, number])) : null;
    const row: SessionRow = {
      sessionId: randomBytes(32).toString('hex'),
      dealId,
      slot,
      purpose,
      participants,
      status: 'open',
      attempt: 0,
      parent: null,
      pair,
      deadlineMs: purpose === 'sign' ? this.#now() + this.#timeout : null,
    };
    await this.#store.createSession(row);
    return row.sessionId;
  }

  #pairIds(ps: readonly Participant[], pair: readonly [number, number]): [string, string] {
    return [(ps[pair[0] - 1] as Participant).identifier, (ps[pair[1] - 1] as Participant).identifier];
  }

  async #pinned(keyId: string) {
    try {
      return await this.#deps.db.repos.enrollmentKeys.getUsable(keyId);
    } catch (e) {
      if (e instanceof KeyNotRecorded) throw refuse('key_not_pinned', keyId);
      throw e;
    }
  }

  async send(signed: z.infer<typeof FrostSignedMessage>): Promise<{ readonly seq: number }> {
    let d: ReturnType<typeof decodeSigned>;
    try {
      d = decodeSigned(signed);
    } catch (e) {
      if (e instanceof WireError) throw refuse('malformed', e.code);
      throw e;
    }
    const m = d.message;
    const session = await this.#live(m.session_id);
    if (m.deal_id !== session.dealId || m.slot !== session.slot) throw refuse('wrong_deal_or_slot');
    if (!KINDS[session.purpose].includes(m.kind))
      throw refuse('kind_not_allowed', `${m.kind} in a ${session.purpose} session`);
    const sender = session.participants.find((p) => p.identifier === m.from);
    if (!sender) throw refuse('sender_unknown', m.from);
    if (sender.keyId !== d.keyId) throw refuse('key_mismatch', d.keyId);
    if (session.purpose === 'sign' && session.pair && !session.pair.includes(m.from)) throw refuse('not_in_pair');

    const row = await this.#pinned(sender.keyId);
    const header = await this.#deps.ledger.validatedLedger();
    if (header.closeTime < row.valid_from || (row.valid_to !== undefined && header.closeTime > row.valid_to))
      throw refuse('key_not_pinned', 'outside its validity window');
    const pq = fromBase64Strict(row.mldsa65_pub);
    const bytes = signedBytes(d);
    const edKey = new Uint8Array(Buffer.from(row.ed25519_pub, 'hex'));
    // Strict RFC 8032 verification (zip215: false), a hard rule (IMPLEMENTATION 1.3).
    if (
      !pq ||
      edKey.length !== 32 ||
      d.edSig.length !== 64 ||
      !ed25519.verify(d.edSig, bytes, edKey, { zip215: false }) ||
      !mldsaVerify('ml-dsa-65', pq, bytes, d.pqSig, RELAY_CONTEXT)
    )
      throw refuse('bad_signature', m.from);

    const to = recipientOf(m);
    if (DIRECT_KINDS.has(m.kind)) {
      if (!to || to === m.from || !session.participants.some((p) => p.identifier === to)) throw refuse('bad_recipient');
    }
    const stored = await this.#store.messages(session.sessionId, -1);
    const have = new Set(stored.map((x) => `${x.kind}|${x.from}`));
    const needs = NEEDS[m.kind];
    if (needs && !needs(have, session)) throw refuse('out_of_order', m.kind);

    const seq = await this.#store.append(session.sessionId, { kind: m.kind, from: m.from, to: to ?? null, signed });
    if (seq === 'duplicate') throw refuse('duplicate', `${m.kind} from ${m.from}`);
    if (m.kind === 'abort') await this.#store.close(session.sessionId, 'aborted');
    return { seq };
  }

  /** The three holders of a session, as `openSession` recorded them. */
  async participants(sessionId: string): Promise<readonly Participant[]> {
    const s = await this.#store.session(sessionId);
    if (!s) throw refuse('session_unknown');
    return s.participants;
  }

  async receive(sessionId: string, recipient: string, afterSeq: number): Promise<readonly RelayedMessage[]> {
    const session = await this.#store.session(sessionId);
    if (!session) throw refuse('session_unknown');
    if (!session.participants.some((p) => p.identifier === recipient)) throw refuse('sender_unknown', recipient);
    // A signing attempt past its deadline is closed by the first read that notices, so a waiting holder stops waiting.
    if (session.status === 'open' && (await this.#expired(session))) {
      await this.#timeOut(session);
      throw refuse('session_closed', 'timed out');
    }
    if (session.status === 'timed_out') throw refuse('session_closed', 'timed out');
    const all = await this.#store.messages(sessionId, afterSeq);
    return all
      .filter((x) => (x.to === null ? x.from !== recipient : x.to === recipient))
      .map((x) => ({ seq: x.seq, message: x.signed }));
  }

  /** Messages of a session in the order they arrived, for the participants that need the full transcript (echo, complaint). */
  async transcript(sessionId: string): Promise<readonly RelayedMessage[]> {
    return (await this.#store.messages(sessionId, -1)).map((x) => ({ seq: x.seq, message: x.signed }));
  }

  /** A session that accepts messages now; a signing attempt past its deadline is timed out here, lazily. */
  async #live(sessionId: string): Promise<SessionRow> {
    const s = await this.#store.session(sessionId);
    if (!s) throw refuse('session_unknown');
    if (s.status === 'open' && (await this.#expired(s))) {
      await this.#timeOut(s);
      throw refuse('session_closed', 'timed out');
    }
    if (s.status !== 'open') throw refuse('session_closed', s.status);
    return s;
  }

  async #expired(s: SessionRow): Promise<boolean> {
    if (s.purpose !== 'sign' || s.deadlineMs === null || this.#now() < s.deadlineMs) return false;
    return !(await this.#signed(s));
  }

  /** Both members of the pair have sent their signature share. */
  async #signed(s: SessionRow): Promise<boolean> {
    const shares = (await this.#store.messages(s.sessionId, -1)).filter((x) => x.kind === 'sign.share');
    return (s.pair ?? []).every((id) => shares.some((x) => x.from === id));
  }

  async #timeOut(s: SessionRow): Promise<SessionStatusView> {
    if (!(await this.#store.close(s.sessionId, 'timed_out'))) {
      // another caller won the close and is opening the next attempt: wait for it, so both answer the same
      for (let i = 0; i < 100 && !(await this.#store.child(s.sessionId)); i++) {
        if ((await this.#store.session(s.sessionId))?.status === 'failed') break;
        await new Promise((r) => setTimeout(r, 20));
      }
      return await this.#view((await this.#store.session(s.sessionId)) as SessionRow);
    }
    const sent = new Set((await this.#store.messages(s.sessionId, -1)).map((x) => x.from));
    const stalled = new Set((s.pair ?? []).filter((id) => !sent.has(id)));
    const tried = await this.#triedPairs(s);
    const ids = s.participants.map((p) => p.identifier);
    const next = PAIRS.map(([a, b]) => [ids[a - 1], ids[b - 1]] as [string, string])
      .filter((p) => !tried.has(p.join()))
      .sort((p, q) => p.filter((x) => stalled.has(x)).length - q.filter((x) => stalled.has(x)).length)[0];
    if (!next) {
      await this.#store.fail(s.sessionId);
      return await this.#view((await this.#store.session(s.sessionId)) as SessionRow);
    }
    const childId = randomBytes(32).toString('hex');
    await this.#store.createSession({
      ...s,
      sessionId: childId,
      status: 'open',
      attempt: s.attempt + 1,
      parent: s.sessionId,
      pair: next,
      deadlineMs: this.#now() + this.#timeout,
    });
    return await this.#view((await this.#store.session(s.sessionId)) as SessionRow);
  }

  async #triedPairs(s: SessionRow): Promise<Set<string>> {
    const tried = new Set<string>();
    for (let cur: SessionRow | undefined = s; cur; cur = cur.parent ? await this.#store.session(cur.parent) : undefined)
      if (cur.pair) tried.add(cur.pair.join());
    return tried;
  }

  async #view(s: SessionRow): Promise<SessionStatusView> {
    const child = s.status === 'timed_out' ? await this.#store.child(s.sessionId) : undefined;
    return {
      sessionId: s.sessionId,
      status: s.status,
      attempt: s.attempt,
      pair: s.pair,
      deadlineMs: s.deadlineMs,
      next: child?.sessionId ?? null,
    };
  }

  /** The state of a session. For a signing attempt past its deadline this times it out and names the next attempt. */
  async status(sessionId: string): Promise<SessionStatusView> {
    const s = await this.#store.session(sessionId);
    if (!s) throw refuse('session_unknown');
    if (s.status === 'open' && (await this.#expired(s))) return await this.#timeOut(s);
    return await this.#view(s);
  }
}
