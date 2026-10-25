// Test world for the FROST browser code: an in-memory relay with 3.9's checks (pinned keys, both signatures, kinds per
// purpose, round order, recipients, duplicates, aborts), parties with real Ed25519 and ML-DSA-65 enrollment keys, and
// knobs for a hostile relay (drop, reorder, repeat, rewrite per recipient).
// Source: services/coordinator/src/frost/relay.ts (the checks mirrored here)
import type { RelayedMessage } from '@legx/contracts/ports';
import { holderId, type Role, verifyEd25519Strict } from '@legx/core/frost';
import { mldsaSign, mldsaVerify, pqKeygen } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import type { SessionSource } from '../../src/frost/dkg.ts';
import type { Purpose, RelayPort } from '../../src/frost/transport.ts';
import {
  bytesToSign,
  decodeSigned,
  type HolderInfo,
  type PartyKeys,
  RELAY_CONTEXT,
  type RelayKind,
  type RelayMessage,
  type Signed,
} from '../../src/frost/wire.ts';

export type Party = { info: HolderInfo; keys: PartyKeys; edSecret: Uint8Array; pqSecret: Uint8Array };

let n = 0;
/** A holder with fresh noble keys (the remote holders, and local ones where WebCrypto is not under test). */
export function party(index: number, role: Role, label: string, deviceId = `device-${index}-${n++}`): Party {
  const edSecret = ed25519.utils.randomSecretKey();
  const pq = pqKeygen();
  const keyId = `key-${bytesToHex(randomBytes(6))}`;
  const edPub = new Uint8Array([0xed, ...ed25519.getPublicKey(edSecret)]);
  return {
    edSecret,
    pqSecret: pq.secretKey,
    info: { identifier: holderId(index), keyId, role, edPub, pqPub: pq.publicKey, deviceId, label },
    keys: {
      keyId,
      signEd: async (m) => ed25519.sign(m, edSecret),
      signPq: async (m) => mldsaSign('ml-dsa-65', pq.secretKey, m, RELAY_CONTEXT),
    },
  };
}

const KINDS: Record<Purpose, readonly RelayKind[]> = {
  dkg: ['dkg.round1', 'dkg.echo', 'dkg.round2', 'dkg.complaint', 'abort'],
  sign: ['sign.begin', 'sign.request', 'sign.commit', 'sign.share', 'abort'],
  refresh: ['refresh.commit', 'refresh.subshare', 'refresh.deleted', 'abort'],
  repair: ['repair.hello', 'repair.delta', 'repair.sigma', 'abort'],
};
const DIRECT = new Set<RelayKind>(['dkg.round2', 'refresh.subshare', 'repair.delta', 'repair.sigma']);

type Row = { seq: number; kind: RelayKind; from: string; to: string | null; signed: Signed };
export type Session = {
  id: string;
  purpose: Purpose;
  holders: readonly HolderInfo[];
  pair?: readonly [string, string];
  rows: Row[];
  closed: boolean;
};

export class RelayRefused extends Error {}

/** The relay; `deliver` lets a test act as a hostile relay toward one recipient. */
export class MemoryRelay implements RelayPort {
  readonly sessions: Session[] = [];
  readonly pinned = new Map<string, HolderInfo>();
  readonly log: Signed[] = [];
  deliver?: (recipient: string, rows: RelayedMessage[], session: Session) => RelayedMessage[];
  #seq = 0;
  #waiters: (() => void)[] = [];

  pin(...hs: HolderInfo[]): void {
    for (const h of hs) this.pinned.set(h.keyId, h);
  }

  async openSession(input: { purpose: Purpose; holders: readonly HolderInfo[]; pair?: readonly [string, string] }) {
    for (const h of input.holders) if (!this.pinned.has(h.keyId)) throw new RelayRefused(`key_not_pinned ${h.keyId}`);
    const s: Session = {
      id: bytesToHex(randomBytes(32)),
      purpose: input.purpose,
      holders: input.holders,
      ...(input.purpose === 'sign'
        ? { pair: input.pair ?? [String(input.holders[0]?.identifier), String(input.holders[1]?.identifier)] }
        : {}),
      rows: [],
      closed: false,
    };
    this.sessions.push(s);
    for (const w of this.#waiters.splice(0)) w();
    return s.id;
  }

  /** A session source for a device that is not the opener: the k-th session of this purpose and pair. */
  joiner(): SessionSource {
    const used = new Set<string>();
    return async (purpose, pair) => {
      for (;;) {
        const s = this.sessions.find(
          (x) =>
            !used.has(x.id) && x.purpose === purpose && (!pair || (x.pair && pair.every((p) => x.pair?.includes(p)))),
        );
        if (s) {
          used.add(s.id);
          return s.id;
        }
        await new Promise<void>((r) => this.#waiters.push(r));
      }
    };
  }

  async send(signed: Signed): Promise<{ seq: number }> {
    const d = decodeSigned(signed);
    const m: RelayMessage = d.message;
    const s = this.sessions.find((x) => x.id === m.session_id);
    if (!s) throw new RelayRefused('session_unknown');
    if (s.closed) throw new RelayRefused('session_closed');
    if (!KINDS[s.purpose].includes(m.kind)) throw new RelayRefused(`kind_not_allowed ${m.kind}`);
    const sender = s.holders.find((h) => h.identifier === m.from);
    if (!sender || sender.keyId !== signed.key_id) throw new RelayRefused('key_mismatch');
    if (s.pair && !s.pair.includes(m.from)) throw new RelayRefused('not_in_pair');
    const bytes = bytesToSign(m, d.payload);
    if (
      !verifyEd25519Strict(d.edSig, bytes, sender.edPub) ||
      !mldsaVerify('ml-dsa-65', sender.pqPub, bytes, d.pqSig, RELAY_CONTEXT)
    )
      throw new RelayRefused('bad_signature');
    const to = 'to' in m ? m.to : null;
    if (DIRECT.has(m.kind) && (!to || to === m.from || !s.holders.some((h) => h.identifier === to)))
      throw new RelayRefused('bad_recipient');
    if (s.rows.some((r) => r.kind === m.kind && r.from === m.from && r.to === to)) throw new RelayRefused('duplicate');
    const row: Row = { seq: this.#seq++, kind: m.kind, from: m.from, to, signed };
    s.rows.push(row);
    this.log.push(signed);
    if (m.kind === 'abort') s.closed = true;
    return { seq: row.seq };
  }

  async receive(sessionId: string, recipient: string, afterSeq: number): Promise<readonly RelayedMessage[]> {
    const s = this.sessions.find((x) => x.id === sessionId);
    if (!s) throw new RelayRefused('session_unknown');
    const rows = s.rows
      .filter((r) => r.seq > afterSeq && (r.to === null ? r.from !== recipient : r.to === recipient))
      .map((r) => ({ seq: r.seq, message: r.signed }));
    return this.deliver ? this.deliver(recipient, rows, s) : rows;
  }

  /** Kinds in the session, for assertions. */
  kinds(sessionId: string): string[] {
    return (this.sessions.find((s) => s.id === sessionId)?.rows ?? []).map((r) => r.kind);
  }
}

/** A client slot: phone (1), second device (2), recovery agent (3), all pinned at the relay. */
export function clientSlot(relay = new MemoryRelay()) {
  const phone = party(1, 'phone', 'Your phone');
  const second = party(2, 'second-authenticator', 'Your second device');
  const agent = party(3, 'recovery-agent', 'Recovery agent (Example Recovery Ltd)');
  relay.pin(phone.info, second.info, agent.info);
  return { relay, phone, second, agent, holders: [phone.info, second.info, agent.info] };
}
