// E2E-P1 helper: one FROST slot made by a real DKG (X-Wing transport), with three ML-DSA-65 holder keys, hybrid
// holder signers, a three-pair test-signing and the frost.dkg.completed record. Signing goes through
// SigningSession, aggregateChecked and a caller-supplied checkMessage (the holders' allow-list in the deal builder).
import type { SignerPort } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  aggregateChecked,
  type CheckResult,
  type Commitment,
  SigningSession,
  type SlotName,
  slotPolicy,
  slotPubkey,
} from '../../src/frost.ts';
import { type DkgKey, dkgCompletedRecord, testSignCheck, testSignMessage } from '../../src/frostDkg.ts';
import { nobleHybridSigner, pqKeygen, pqKeyHash } from '../../src/pq.ts';
import type { KeyRow, SlotHolders } from '../../src/releaseGate.ts';
import { dkgKeys } from '../helpers/frost.ts';

export type Check = (msg: Uint8Array, list: readonly Commitment[]) => CheckResult;
const allowAll: Check = () => ({ ok: true });
const PAIRS = [
  [1, 2],
  [1, 3],
  [2, 3],
] as const;
const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();

export async function makeSlot(slot: SlotName, pqSeedByte: number) {
  const k = await dkgKeys(slot);
  const keys = k.keys as DkgKey[];
  const pub = k.pub;
  const share = (i: number) => (keys[i] as DkgKey).secret;
  const pq = k.holders.map((_, j) => pqKeygen(new Uint8Array(32).fill(pqSeedByte + j)));
  const roles = k.holders.map((h) => h.key.role);
  const ids = k.holders.map((h, j) => ({
    ed25519: `${slot}/${h.key.role}/ed`,
    mlDsa65: `${slot}/${h.key.role}/pq`,
    j,
  }));
  const rows: KeyRow[] = ids.flatMap(({ ed25519: e, mlDsa65: m, j }) => [
    {
      keyId: e,
      alg: 'ed25519',
      publicKey: (k.holders[j] as (typeof k.holders)[0]).key.edPub.slice(1),
      validFrom: 1,
      logged: true,
      pair: `${slot}/${j}`,
    },
    {
      keyId: m,
      alg: 'ml-dsa-65',
      publicKey: (pq[j] as { publicKey: Uint8Array }).publicKey,
      validFrom: 1,
      logged: true,
      pair: `${slot}/${j}`,
    },
  ]);

  /** Two holders (0-based indexes) sign `msg`; every holder runs `check` before it releases its share. */
  const sign = (msg: Uint8Array, check: Check = allowAll, a = 0, b = 1): Uint8Array => {
    const sessions = [a, b].map((i) => SigningSession.open(share(i), pub, msg));
    const list = sessions.map((s) => s.commitment);
    const shares = Object.fromEntries(
      [a, b].map((i, n) => [share(i).identifier, (sessions[n] as SigningSession).signShare(msg, list, check)]),
    );
    return aggregateChecked(pub, list, msg, shares);
  };

  // Test-signing: each pair signs its own fixed message, and each holder's check refuses any other message.
  const testSignatures = PAIRS.map(([a, b]) => {
    const msg = testSignMessage(k.ctx, pub, [a, b]);
    const sessions = [a, b].map((i) => SigningSession.open(share(i - 1), pub, msg));
    const list = sessions.map((s) => s.commitment);
    const shares = Object.fromEntries(
      [a, b].map((i, n) => [
        share(i - 1).identifier,
        (sessions[n] as SigningSession).signShare(msg, list, testSignCheck(k.ctx, pub, i)),
      ]),
    );
    return { pair: [a, b] as [number, number], sig: aggregateChecked(pub, list, msg, shares) };
  });
  const completed = dkgCompletedRecord({ ctx: k.ctx, pub, round1: k.run.round1, echoes: k.run.echoes, testSignatures });
  const pubHex = up(slotPubkey(pub));
  const policy = bytesToHex(slotPolicy(slot, roles));
  const hybrid = (j: number): SignerPort => {
    const h = k.holders[j] as (typeof k.holders)[0];
    const id = ids[j] as (typeof ids)[0];
    return nobleHybridSigner(
      { keyId: id.ed25519 as KeyId, publicKey: h.key.edPub.slice(1), sign: async (m) => ed25519.sign(m, h.secret) },
      { keyId: id.mlDsa65 as KeyId, secretKey: (pq[j] as { secretKey: Uint8Array }).secretKey },
    );
  };
  // The frost.dkg.completed event data as the gate reads it (releaseGate.ts SLOT_SETUP_OK).
  const dkgData = {
    slot,
    session_id: bytesToHex(k.ctx.sessionId),
    group_pub: pubHex,
    slot_policy: policy,
    roles,
    transcript_hash: bytesToHex(completed.transcriptHash),
    holder_sigs: ids.map(({ ed25519: e }, j) => ({
      key_id: e,
      sig: bytesToHex(completed.transcriptSigs[j] as Uint8Array),
    })),
    verifying_shares: Object.entries(pub.verifyingShares).map(([identifier, s]) => ({
      identifier,
      share: bytesToHex(s),
    })),
    test_sigs: completed.testSignatures.map((t) => bytesToHex(t.sig)),
  };
  return {
    slot,
    k,
    pub,
    pubHex,
    roles,
    policy,
    rows,
    sign,
    share,
    pq,
    pqKeyHash: bytesToHex(pqKeyHash(pq.map((p) => p.publicKey) as [Uint8Array, Uint8Array, Uint8Array])),
    holders: ids.map(({ ed25519: e, mlDsa65: m }) => ({ ed25519: e, mlDsa65: m })) as unknown as SlotHolders,
    hybrid,
    completed,
    dkgData,
    testSignatures,
  };
}
export type Slot = Awaited<ReturnType<typeof makeSlot>>;
