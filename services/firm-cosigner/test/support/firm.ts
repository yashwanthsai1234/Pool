// A firm world: the lawyer slot LA (console, firm HSM, partner) on the 3.9 relay world, with the HSM co-signer as
// holder 2 and scripted holders 1 and 3. The relay world, DKG helpers and ports are the recovery agent's test support.
import { bytesToHex, sha256 } from '@legx/core/dealcore';
import { type FrostMsg, verifyEd25519Strict } from '@legx/core/frost';
import { type DkgKey, dkgCompletedRecord, testSignCheck, testSignMessage } from '@legx/core/frostDkg';
import type { SealedDeal } from '@legx/core/frostRules';
import { MemoryEvidence } from '@legx/recovery-agent/events';
import type { DealInfoPort, NoticePort } from '@legx/recovery-agent/ports';
import { RecordedProofs } from '@legx/recovery-agent/proofs';
import { RecoveryService } from '@legx/recovery-agent/recovery';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveAddress, ECDSA, encodeForMultiSigning, Wallet } from 'xrpl';
import { PAIRS } from '../../../recovery-agent/test/support/setup.ts';
import { type Member, makeWorld, rnd, type World } from '../../../recovery-agent/test/support/world.ts';
import { LawyerApprovals, type WireApproval } from '../../src/approval.ts';
import { AuditLog } from '../../src/audit.ts';
import { FirmCosigner, operatorRequestMessage, type SignRequest } from '../../src/cosigner.ts';
import { FirmShareVault, wrapKeyFrom } from '../../src/vault.ts';
import { FixtureAuthenticator, ORIGIN, RP_ID } from './authenticator.ts';

export const HOUR = 3_600_000;
const T0 = 1_800_000_000_000;
const hex = bytesToHex;

interface NormalOpts {
  readonly kind?: 'xrpl-multisign' | 'tagged';
  readonly tagged?: { tag: string; parts: Uint8Array[] };
  readonly approval?: WireApproval;
  readonly seal?: string;
  readonly operator?: SignRequest['operator'];
}

export interface FirmWorld {
  w: World;
  cos: FirmCosigner;
  audit: AuditLog;
  evidence: MemoryEvidence;
  approvals: LawyerApprovals;
  vault: FirmShareVault;
  recoveries: RecoveryService;
  notices: Parameters<NoticePort['notify']>[0][];
  clock: { now: number };
  deal: { allows: boolean; sealed: SealedDeal };
  ops: Wallet;
  opsSecret: Uint8Array;
  lawyer: FixtureAuthenticator;
  keys: DkgKey[];
  groupKey: Uint8Array;
  seal: string;
  /** The operations account's signed request for one session. */
  operator(
    sessionId: string,
    pair: [number, number],
    over?: { secret?: Uint8Array; pub?: Uint8Array; seal?: string },
  ): SignRequest['operator'];
  exit(over?: Record<string, unknown>): { msg: Uint8Array; tx: Record<string, unknown> };
  sessionFor(pair: [number, number]): Promise<string>;
  /** Console (holder 1) and the HSM sign `msg` together; the console aggregates. */
  signNormal(msg: Uint8Array, o?: NormalOpts): Promise<{ sig: Uint8Array; sessionId: string }>;
}

export async function makeFirmWorld(db?: World['db']): Promise<FirmWorld> {
  const w = await makeWorld({ slot: 'LA', ...(db ? { db } : {}) });
  const evidence = new MemoryEvidence();
  const notices: FirmWorld['notices'] = [];
  const clock = { now: T0 };
  const ops = Wallet.generate(ECDSA.ed25519);
  const opsSecret = new Uint8Array(Buffer.from(ops.privateKey.slice(2), 'hex'));
  const addr = () => Wallet.generate(ECDSA.ed25519).classicAddress;
  const sealed: SealedDeal = {
    walletAddress: addr(),
    contractRoot: rnd(32),
    dealSeal: rnd(32),
    payoutA: { account: addr(), tag: 7 },
    payoutB: { account: addr() },
    exitAmountDrops: '5000000000',
    maxFeeDrops: '1000',
    slotPubs: { A: rnd(33), B: rnd(33), LA: new Uint8Array(33), LB: rnd(33) } as SealedDeal['slotPubs'],
  };
  const deal = { allows: true, sealed };
  const dealInfo: DealInfoPort = {
    opsAccount: async () => ops.classicAddress,
    onboardingIdentifier: async () => 'unused',
    sealed: async () => deal.sealed,
    allowsSigning: async () => deal.allows,
  };
  const lawyer = new FixtureAuthenticator();
  const signer = nodeSigner(generateNodeSignerKeys('hsm-ed' as never, 'hsm-pq' as never));
  const vault = new FirmShareVault(w.deps.db, await wrapKeyFrom(signer));
  const audit = new AuditLog(w.deps.db, evidence as never);
  const approvals = new LawyerApprovals(w.deps.db, { rpId: RP_ID, origin: ORIGIN });
  const recoveries = new RecoveryService({
    db: w.deps.db,
    evidence,
    notices: { notify: async (n) => void notices.push(n) },
    proofs: new RecordedProofs({ find: async () => undefined }),
    deal: dealInfo,
    now: () => clock.now,
  });
  const cos = new FirmCosigner({
    db: w.deps.db,
    keys: (w.members[1] as Member).keys,
    vault,
    recoveries,
    approvals,
    audit,
    deal: dealInfo,
    relay: w.relay,
    directory: async () => w.members.map((m) => m.info),
    pinned: w.registry.check,
    pollMs: 2,
    timeoutMs: 20_000,
  });
  await approvals.register(w.dealId, 'LA', Buffer.from(lawyer.credentialId).toString('base64'), lawyer.cosePublicKey());

  const idsOf = (pair: [number, number]) =>
    pair.map((i) => (w.members[i - 1] as Member).info.identifier) as [string, string];
  const sessionFor = async (pair: [number, number]) =>
    await w.relay.openSession({
      dealId: w.dealId,
      slot: 'LA',
      purpose: 'sign',
      participants: w.participants(),
      pair: idsOf(pair),
    });

  // DKG and the three test signatures, with the HSM as holder 2
  const dkgSession = await w.relay.openSession({
    dealId: w.dealId,
    slot: 'LA',
    purpose: 'dkg',
    participants: w.participants(),
  });
  const runs = await Promise.all([
    w.holder(1).dkg(dkgSession),
    cos.dkg(w.dealId, 'LA', dkgSession),
    w.holder(3).dkg(dkgSession),
  ]);
  const r1 = runs[0];
  const keys = [r1.key, undefined, runs[2].key] as unknown as DkgKey[];
  const pub = r1.key.public;
  const sigs: { pair: [number, number]; sig: Uint8Array }[] = [];
  for (const pair of PAIRS) {
    const sid = await sessionFor(pair);
    const msg = testSignMessage(r1.ctx, pub, pair);
    const scripted = pair
      .filter((i) => i !== 2)
      .map((i) =>
        w.holder(i).sign(sid, {
          msg,
          kind: 'tagged',
          share: (keys[i - 1] as DkgKey).secret,
          pub,
          pair,
          check: (m, l) => testSignCheck(r1.ctx, pub, i)(m, l),
        }),
      );
    const hsm = pair.includes(2) ? [cos.testSign(w.dealId, 'LA', sid, pair)] : [];
    const out = await Promise.all([...scripted, ...hsm]);
    sigs.push({ pair, sig: out[0] as Uint8Array });
  }
  const record = dkgCompletedRecord({
    ctx: r1.ctx,
    pub,
    round1: r1.round1 as FrostMsg[],
    echoes: r1.echoes,
    testSignatures: sigs,
  });
  deal.sealed = { ...sealed, slotPubs: { ...sealed.slotPubs, LA: record.slotPub } };

  const seal = hex(sealed.dealSeal as Uint8Array);
  const operator: FirmWorld['operator'] = (sessionId, pair, over = {}) => {
    const m = operatorRequestMessage({ dealId: w.dealId, slot: 'LA', sessionId, seal: over.seal ?? seal, pair });
    return {
      opsPub: over.pub ?? new Uint8Array(Buffer.from(ops.publicKey, 'hex')),
      sig: ed25519.sign(m, over.secret ?? opsSecret),
    };
  };
  return {
    w,
    cos,
    audit,
    evidence,
    approvals,
    vault,
    recoveries,
    notices,
    clock,
    deal,
    ops,
    opsSecret,
    lawyer,
    keys,
    groupKey: record.slotPub,
    seal,
    operator,
    sessionFor,
    exit: (over = {}) => {
      const s = deal.sealed;
      const tx = {
        TransactionType: 'Payment',
        Account: s.walletAddress,
        Destination: s.payoutB.account,
        Amount: '5000000000',
        Fee: '120',
        Sequence: 5,
        SigningPubKey: '',
        ...over,
      };
      const signerAddr = deriveAddress(hex(record.slotPub).toUpperCase());
      return { tx, msg: new Uint8Array(Buffer.from(encodeForMultiSigning(tx as never, signerAddr), 'hex')) };
    },
    signNormal: async (msg, o = {}) => {
      const sessionId = await sessionFor([1, 2]);
      const [console1, hsm] = await Promise.allSettled([
        w.holder(1).sign(sessionId, {
          msg,
          kind: o.kind ?? 'xrpl-multisign',
          share: (keys[0] as DkgKey).secret,
          pub,
          pair: [1, 2],
          check: () => ({ ok: true }),
          approval: o.approval ?? lawyer.assert(sha256(msg)),
          ...(o.tagged ? { tagged: o.tagged } : {}),
        }),
        cos.sign({
          dealId: w.dealId,
          slot: 'LA',
          sessionId,
          pair: [1, 2],
          seal: o.seal ?? seal,
          operator: o.operator ?? operator(sessionId, [1, 2], o.seal ? { seal: o.seal } : {}),
        }),
      ]);
      // the HSM's own verdict is the one a test asserts; the console only sees the session abort
      if (hsm.status === 'rejected') throw hsm.reason;
      if (console1.status === 'rejected') throw console1.reason;
      return { sig: console1.value, sessionId };
    },
  };
}

export const verifies = (fw: FirmWorld, sig: Uint8Array, msg: Uint8Array) => verifyEd25519Strict(sig, msg, fw.groupKey);
