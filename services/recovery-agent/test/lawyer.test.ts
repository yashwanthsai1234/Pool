// P3.9-25: a lawyer slot's recovery starts only with a request signed by the firm's operations account.
import { pinEnrollmentKey } from '@legx/coordinator/enroll';
import { lawyerRecoveryMessage } from '@legx/core/frostRules';
import { toBase64 } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ECDSA, Wallet } from 'xrpl';
import { MemoryEvidence } from '../src/events.ts';
import { RecordedProofs } from '../src/proofs.ts';
import { RecoveryService } from '../src/recovery.ts';
import { HOUR, T0 } from './support/agent.ts';
import { hex, makeMember, makeWorld, rnd, type World } from './support/world.ts';

let w: World;
const ops = Wallet.generate(ECDSA.ed25519);
const opsSecret = new Uint8Array(Buffer.from(ops.privateKey.slice(2), 'hex'));
const clock = { now: T0 };
const evidence = new MemoryEvidence();
const notices: { to: string; kind: string }[] = [];
let recoveries: RecoveryService;
let newKeyId: string;

beforeAll(async () => {
  w = await makeWorld({ slot: 'LA' });
  recoveries = new RecoveryService({
    db: w.deps.db,
    evidence,
    notices: { notify: async (n) => void notices.push(n) },
    proofs: new RecordedProofs({ find: async () => undefined }),
    deal: {
      opsAccount: async () => ops.classicAddress,
      onboardingIdentifier: async () => 'unused',
      sealed: async () => {
        throw new Error('unused');
      },
      allowsSigning: async () => true,
    },
    now: () => clock.now,
  });
  const m = makeMember(1, 'LA', 'console');
  newKeyId = m.keys.keyId;
  await pinEnrollmentKey(w.deps, w.dealId, {
    key_id: newKeyId,
    slot: 'LA',
    holder_role: 'console',
    ed25519_pub: hex(m.info.edPub.slice(1)),
    mldsa65_pub: toBase64(m.info.pqPub),
    valid_from: 0,
  } as never);
});
afterAll(async () => {
  await w.close();
});

describe('lawyer recovery', () => {
  it("starts with the operations account's signature; any other key is refused and nothing is logged", async () => {
    // The signed message is bound to this deal, slot, new key and ledger index (I-S-F1).
    const request = lawyerRecoveryMessage(w.dealId, 'LA', newKeyId, 1000);
    const opsPub = new Uint8Array(Buffer.from(ops.publicKey, 'hex'));
    const start = (sig: Uint8Array, pub = opsPub) =>
      recoveries.startLawyer({ dealId: w.dealId, slot: 'LA', newKeyId, ledgerIndex: 1000, opsPub: pub, sig });
    const code = async (p: Promise<unknown>) => (await p.then(() => 'started').catch((e) => e.code)) as string;
    const stranger = Wallet.generate(ECDSA.ed25519);
    const strangerSecret = new Uint8Array(Buffer.from(stranger.privateKey.slice(2), 'hex'));
    // any other key: its own public key does not give the operations account
    expect(
      await code(start(ed25519.sign(request, strangerSecret), new Uint8Array(Buffer.from(stranger.publicKey, 'hex')))),
    ).toBe('OPS_SIGNATURE_INVALID');
    // the operations public key with a signature by another key, and a signature over other bytes
    expect(await code(start(ed25519.sign(request, strangerSecret)))).toBe('OPS_SIGNATURE_INVALID');
    expect(await code(start(ed25519.sign(rnd(60), opsSecret)))).toBe('OPS_SIGNATURE_INVALID');
    expect(evidence.ofKind('frost.recovery.requested')).toHaveLength(0);
    const view = await recoveries.startLawyer({
      dealId: w.dealId,
      slot: 'LA',
      newKeyId,
      ledgerIndex: 1000,
      opsPub,
      sig: ed25519.sign(request, opsSecret),
    });
    expect(view.state).toBe('waiting');
    expect(evidence.ofKind('frost.recovery.requested')).toHaveLength(1);
    expect(notices.map((n) => n.to).sort()).toEqual(['lawyerA', 'lawyerB', 'old-device']);
  });

  it('is not authorized before hour 72, and then is', async () => {
    clock.now += 71 * HOUR;
    await expect(recoveries.authorize(w.dealId, 'LA')).rejects.toMatchObject({ code: 'RECOVERY_DELAY' });
    clock.now += HOUR;
    expect((await recoveries.authorize(w.dealId, 'LA')).state).toBe('ready');
    expect(evidence.ofKind('frost.recovery.authorized')).toHaveLength(1);
  });
});
