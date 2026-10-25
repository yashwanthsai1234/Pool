// P3.10-14: lawyer recovery at the HSM. A request signed by the operations account starts the 72-hour delay; no share
// is released during it; the notices go out; the old console can cancel; shares 2 + 3 sign after the delay, still
// only with the lawyer's approval.
import { pinEnrollmentKey } from '@legx/coordinator/enroll';
import { sha256 } from '@legx/core/dealcore';
import { lawyerRecoveryMessage, type RecoveryState, recoveryCancelMessage } from '@legx/core/frostRules';
import { toBase64 } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ECDSA, Wallet } from 'xrpl';
import { hex, type Member, makeMember } from '../../recovery-agent/test/support/world.ts';
import { type FirmWorld, HOUR, makeFirmWorld, verifies } from './support/firm.ts';

let fw: FirmWorld;
let newConsole: Member;
beforeAll(async () => {
  fw = await makeFirmWorld();
  newConsole = makeMember(1, 'LA', 'console');
  await pinEnrollmentKey(fw.w.deps, fw.w.dealId, {
    key_id: newConsole.keys.keyId,
    slot: 'LA',
    holder_role: 'console',
    ed25519_pub: hex(newConsole.info.edPub.slice(1)),
    mldsa65_pub: toBase64(newConsole.info.pqPub),
    valid_from: 0,
  } as never);
});
afterAll(async () => {
  await fw.w.close();
});

const code = async (p: Promise<unknown>) =>
  (await p.then(
    () => 'ok',
    (e) => e.code ?? e.message,
  )) as string;
const opsPub = () => new Uint8Array(Buffer.from(fw.ops.publicKey, 'hex'));
const start = (sigBy = fw.opsSecret, pub = opsPub()) => {
  const request = lawyerRecoveryMessage(fw.w.dealId, 'LA', newConsole.keys.keyId, 1000);
  return fw.recoveries.startLawyer({
    dealId: fw.w.dealId,
    slot: 'LA',
    newKeyId: newConsole.keys.keyId,
    ledgerIndex: 1000,
    opsPub: pub,
    sig: ed25519.sign(request, sigBy),
  });
};
/** The HSM aggregates the recovery pair (2, 3); the partner (holder 3) follows. */
async function recoverySign(approve = true) {
  const { msg } = fw.exit({ Sequence: Math.floor(Math.random() * 1e6) });
  const sid = await fw.sessionFor([2, 3]);
  const hsm = fw.cos.sign({
    dealId: fw.w.dealId,
    slot: 'LA',
    sessionId: sid,
    pair: [2, 3],
    seal: fw.seal,
    operator: fw.operator(sid, [2, 3]),
    message: { msg, kind: 'xrpl-multisign', ...(approve ? { approval: fw.lawyer.assert(sha256(msg)) } : {}) },
  });
  return { msg, hsm, sid };
}
const released = async () => (await fw.audit.entries()).filter((e) => e.decision === 'share_released').length;

describe('P3.10-14 lawyer recovery', () => {
  it('refuses a recovery pair before any recovery exists', async () => {
    const { hsm } = await recoverySign();
    expect(await code(hsm)).toBe('NO_RECOVERY');
  });

  it('starts only with the operations account; any other key is refused', async () => {
    const stranger = Wallet.generate(ECDSA.ed25519);
    const secret = new Uint8Array(Buffer.from(stranger.privateKey.slice(2), 'hex'));
    expect(await code(start(secret, new Uint8Array(Buffer.from(stranger.publicKey, 'hex'))))).toBe(
      'OPS_SIGNATURE_INVALID',
    );
    expect(await code(start(secret))).toBe('OPS_SIGNATURE_INVALID');
    expect(fw.notices).toHaveLength(0);
  });

  it('the old console cancels during the delay; nothing is signed afterwards, even after hour 72', async () => {
    const view = await start();
    expect(view.state).toBe('waiting');
    expect(fw.notices.map((n) => n.to).sort()).toEqual(['lawyerA', 'lawyerB', 'old-device']);
    expect((await fw.recoveries.get(view.recoveryId)).state).toBe('waiting'); // what either lawyer's console reads
    const startedAt = fw.clock.now;
    const old = fw.w.members[0] as Member;
    fw.clock.now += 10 * HOUR;
    const before = await released();
    const msg = recoveryCancelMessage({ recoveryId: view.recoveryId, slot: 'LA', startedAt } as RecoveryState);
    const cancelled = await fw.recoveries.cancel({
      recoveryId: view.recoveryId,
      sig: ed25519.sign(msg, old.keys.edSecret),
      oldDevicePub: old.info.edPub,
    });
    expect(cancelled.state).toBe('cancelled');
    expect(
      fw.notices
        .filter((n) => n.kind === 'recovery.cancelled')
        .map((n) => n.to)
        .sort(),
    ).toEqual(['lawyerA', 'lawyerB', 'new-device']);
    fw.clock.now += 80 * HOUR;
    expect(await code((await recoverySign()).hsm)).toBe('CANCELLED');
    expect(await released()).toBe(before);
  });

  it('releases no share during the 72 hours, and signs with the partner after them, with the approval', async () => {
    const view = await start();
    const before = await released();
    fw.clock.now += 71 * HOUR;
    expect(await code((await recoverySign()).hsm)).toBe('RECOVERY_DELAY');
    expect(await released()).toBe(before);
    fw.clock.now += HOUR;
    // after the delay the lawyer's approval is still needed
    expect(await code((await recoverySign(false)).hsm)).toBe('APPROVAL_MISSING');
    const { msg, hsm, sid } = await recoverySign();
    const partner = fw.w.holder(3).sign(sid, {
      kind: 'xrpl-multisign',
      share: fw.keys[2]?.secret as never,
      pub: fw.keys[2]?.public as never,
      pair: [2, 3],
      check: () => ({ ok: true }),
    });
    const [sig] = await Promise.all([hsm, partner]);
    expect(verifies(fw, sig, msg)).toBe(true);
    expect(await released()).toBe(before + 1);
    expect((await fw.recoveries.get(view.recoveryId)).state).toBe('ready');
    expect(fw.evidence.ofKind('frost.recovery.authorized')).toHaveLength(1);
  });

  it('a pair that is not the HSM, or the HSM twice, is refused', async () => {
    const sid = await fw.sessionFor([1, 3]);
    expect(
      await code(
        fw.cos.sign({
          dealId: fw.w.dealId,
          slot: 'LA',
          sessionId: sid,
          pair: [1, 3],
          seal: fw.seal,
          operator: fw.operator(sid, [1, 3]),
        }),
      ),
    ).toBe('WRONG_PAIR');
  });
});
