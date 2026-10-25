// Test helpers for the FROST tests: real X-Wing HPKE, enrollment keys, and an in-process DKG.
import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core';
import { XWing } from '@hpke/hybridkem-x-wing';
import { ed25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import {
  aggregateChecked,
  type Commitment,
  type EnrollmentSigner,
  type FrostMsg,
  type HolderKey,
  type KeyShare,
  type Role,
  SigningSession,
  type SlotName,
  type SlotPublic,
} from '../../src/frost.ts';
import {
  type DkgContext,
  type DkgKey,
  type DkgState,
  dkgReceiveEcho,
  dkgReceiveRound1,
  dkgReceiveRound2,
  dkgStart,
  type ShareCipher,
} from '../../src/frostDkg.ts';
import {
  type RefreshContext,
  type RefreshState,
  refreshReceiveCommits,
  refreshReceiveShares,
  refreshStart,
} from '../../src/frostRefresh.ts';
import { checkDelta, repairDelta, repairSigma } from '../../src/frostRepair.ts';

export const enc = (s: string) => new TextEncoder().encode(s);
export const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
export const unhex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
export const allow = () => ({ ok: true as const });

/** Real X-Wing HPKE (DESIGN 6.13) through @hpke, with noble for key generation; the ciphertext is enc || ct. */
const suite = new CipherSuite({ kem: new XWing(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
const ENC_LEN = 1120;
export const xwing: ShareCipher = {
  suite: 'hpke-xwing-v1',
  keygen: () => ml_kem768_x25519.keygen(),
  publicKeyOf: (sk) => ml_kem768_x25519.getPublicKey(sk),
  async seal(pk, aad, pt) {
    const { ct, enc } = await suite.seal({ recipientPublicKey: await suite.kem.deserializePublicKey(pk) }, pt, aad);
    return new Uint8Array([...new Uint8Array(enc), ...new Uint8Array(ct)]);
  },
  async open(sk, aad, ct) {
    const recipientKey = await suite.kem.deserializePrivateKey(sk);
    const pt = await suite.open({ recipientKey, enc: ct.slice(0, ENC_LEN).buffer }, ct.slice(ENC_LEN), aad);
    return new Uint8Array(pt);
  },
};

export type Enrolled = { key: HolderKey; signer: EnrollmentSigner; secret: Uint8Array };
export function enroll(holder: string, role: Role, deviceId = holder): Enrolled {
  const secret = ed25519.utils.randomSecretKey();
  const edPub = new Uint8Array([0xed, ...ed25519.getPublicKey(secret)]);
  return { key: { holder, role, edPub, deviceId }, signer: { sign: (m) => ed25519.sign(m, secret) }, secret };
}

export const ROLES: Record<'client' | 'lawyer', Role[]> = {
  client: ['phone', 'second-authenticator', 'recovery-agent'],
  lawyer: ['console', 'firm-hsm', 'partner'],
};

export function slotSetup(slot: SlotName = 'A') {
  const roles = slot === 'A' || slot === 'B' ? ROLES.client : ROLES.lawyer;
  const holders = roles.map((r) => enroll(`${slot}/${r}`, r));
  const ctx: DkgContext = { sessionId: randomBytes(32), slot, holders: holders.map((h) => h.key) };
  return { ctx, holders };
}
export const noPinCheck = () => {};

/** Runs every round for all three holders; `tamper` may rewrite messages in flight. */
export async function runDkg(
  ctx: DkgContext,
  holders: Enrolled[],
  tamper: {
    r1?: (m: FrostMsg, to: number) => FrostMsg;
    r2?: (m: FrostMsg, round1: FrostMsg[]) => FrostMsg | Promise<FrostMsg>;
  } = {},
) {
  const starts = holders.map((h, i) => dkgStart(ctx, i + 1, { signer: h.signer, cipher: xwing, pinned: noPinCheck }));
  const round1 = starts.flatMap((s) => s.out);
  const states: DkgState[] = starts.map((s) => s.state);
  const echoes = states.map(
    (s) =>
      dkgReceiveRound1(
        s,
        round1.filter((m) => m.from !== s.me).map((m) => (tamper.r1 ? tamper.r1(m, s.me) : m)),
      ).out[0] as FrostMsg,
  );
  const r2: FrostMsg[] = [];
  for (const s of states)
    r2.push(
      ...(
        await dkgReceiveEcho(
          s,
          echoes.filter((e) => e.from !== s.me),
        )
      ).out,
    );
  const r2Sent = tamper.r2 ? await Promise.all(r2.map((m) => tamper.r2?.(m, round1) ?? m)) : r2;
  const results = [];
  for (const s of states)
    results.push(
      await dkgReceiveRound2(
        s,
        r2Sent.filter((m) => m.to === s.me),
      ),
    );
  return { round1, echoes, r2: r2Sent, results, states };
}

export async function dkgKeys(slot: SlotName = 'A') {
  const { ctx, holders } = slotSetup(slot);
  const run = await runDkg(ctx, holders);
  const keys = run.results.map((r) => r.key as DkgKey);
  return { ctx, holders, run, keys, pub: (keys[0] as DkgKey).public };
}

/** Two-round signing by the given holders' shares, through SigningSession and aggregateChecked. */
export function frostSign(pub: SlotPublic, shares: KeyShare[], msg: Uint8Array): Uint8Array {
  const sessions = shares.map((s) => SigningSession.open(s, pub, msg));
  const list: Commitment[] = sessions.map((s) => s.commitment);
  const sigShares = Object.fromEntries(shares.map((s, i) => [s.identifier, sessions[i]!.signShare(msg, list, allow)]));
  return aggregateChecked(pub, list, msg, sigShares);
}

/** noble's rng for a chosen scalar: randomScalar maps 48 bytes b to (LE(b) mod (n-1)) + 1. */
export const scalarRngBytes = (s: bigint): Uint8Array => {
  const out = new Uint8Array(48);
  let v = s - 1n;
  for (let i = 0; i < 48; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};
/** An rng that hands out the given chunks in order (then fails). */
export function chunkRng(chunks: Uint8Array[]) {
  const queue = [...chunks];
  return (n?: number) => {
    const c = queue.shift();
    if (!c || (n !== undefined && c.length !== n)) throw new Error(`rng: unexpected request ${n}`);
    return c;
  };
}

// ---------- refresh and repair, shared with packages/xrpl test-int (I-2.8-d) ----------

/** What a refresh or repair needs of a slot made by `dkgKeys` (or any kit of the same shape). */
export type SlotKit = {
  ctx: DkgContext;
  pub: SlotPublic;
  keys: readonly { secret: KeyShare }[];
  holders: readonly { signer: EnrollmentSigner }[];
};
export const refreshCtx = (s: SlotKit, participants = [1, 2, 3]): RefreshContext => ({
  ...s.ctx,
  sessionId: crypto.getRandomValues(new Uint8Array(32)),
  pub: s.pub,
  participants,
});

/**
 * Runs a refresh among `ctx.participants` (default: everyone, a fresh session); `rngs` injects each dealer's
 * coefficient, `tamper` rewrites sub-share messages in flight. Returns each participant's result.
 */
export async function refreshSlot(
  s: SlotKit,
  ctx: RefreshContext = refreshCtx(s),
  opts: { rngs?: bigint[]; tamper?: (m: FrostMsg, states: RefreshState[]) => FrostMsg | Promise<FrostMsg> } = {},
) {
  const starts = ctx.participants.map((p, k) =>
    refreshStart(ctx, p, (s.keys[p - 1] as { secret: KeyShare }).secret, {
      signer: (s.holders[p - 1] as { signer: EnrollmentSigner }).signer,
      cipher: xwing,
      rng: opts.rngs ? chunkRng([scalarRngBytes(opts.rngs[k] as bigint)]) : undefined,
    }),
  );
  const commits = starts.flatMap((x) => x.out);
  const states = starts.map((x) => x.state);
  const subs: FrostMsg[] = [];
  for (const st of states) {
    subs.push(
      ...(
        await refreshReceiveCommits(
          st,
          commits.filter((m) => m.from !== st.me),
        )
      ).out,
    );
  }
  const tamper = opts.tamper;
  const sent = tamper ? await Promise.all(subs.map((m) => tamper(m, states))) : subs;
  const results = [];
  for (const st of states)
    results.push(
      await refreshReceiveShares(
        st,
        sent.filter((m) => m.to === st.me),
      ),
    );
  return { ctx, results, commits, states };
}

/** `helpers` rebuild `participant`'s share without its old share (T-U-30): the contributions the new holder receives. */
export function repairShare(pub: SlotPublic, helpers: number[], shares: readonly KeyShare[], participant: number) {
  const dealt = helpers.map((h) => ({
    from: h,
    ...repairDelta(pub, helpers, shares[h - 1] as KeyShare, participant),
  }));
  return helpers.map((j) => {
    for (const d of dealt) checkDelta(j, d.from, d.deltas.get(j) as Uint8Array, d.commitments);
    return {
      from: j,
      sigma: repairSigma(dealt.map((d) => d.deltas.get(j) as Uint8Array)),
      commitments: (dealt.find((d) => d.from === j) as (typeof dealt)[number]).commitments,
    };
  });
}
