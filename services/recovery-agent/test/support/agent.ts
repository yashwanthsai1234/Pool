import type { ZkVerification } from '@legx/contracts/records';
import { pinEnrollmentKey } from '@legx/coordinator/enroll';
import { bytesToHex } from '@legx/core/dealcore';
import type { FrostMsg, KeyShare, Role, SlotPublic } from '@legx/core/frost';
import { type DkgKey, dkgCompletedRecord, testSignCheck, testSignMessage } from '@legx/core/frostDkg';
import type { SealedDeal } from '@legx/core/frostRules';
import { type EnrollmentRegistry, enrollmentKeyHash } from '@legx/core/frostSetup';
import { toBase64 } from '@legx/core/pq';
import { deriveAddress, ECDSA, encodeForMultiSigning, Wallet } from 'xrpl';
import { RecoveryAgent } from '../../src/agent.ts';
import { MemoryEvidence } from '../../src/events.ts';
import type { DealInfoPort, NoticePort } from '../../src/ports.ts';
import { RecordedProofs, recoveryBoundValue, type VerifiedRecord } from '../../src/proofs.ts';
import { RecoveryService } from '../../src/recovery.ts';
import { ShareVault } from '../../src/vault.ts';
import { PAIRS } from './setup.ts';
import { hex, type Member, makeMember, rnd, type World } from './world.ts';

export const HOUR = 3_600_000;
export const T0 = 1_800_000_000_000;

export interface AgentWorld {
  agent: RecoveryAgent;
  evidence: MemoryEvidence;
  notices: Parameters<NoticePort['notify']>[0][];
  clock: { now: number };
  deal: { allows: boolean; sealed: SealedDeal; onboardingId: string; opsAccount: Record<string, string> };
  vault: ShareVault;
  recoveries: RecoveryService;
  records: Map<string, VerifiedRecord>;
  setup: Awaited<ReturnType<typeof slotSetupWithAgent>>;
  holders: Member[];
  registry: EnrollmentRegistry;
  proof(opts: {
    identifier?: string;
    newKeyId: string;
    faceMatch?: boolean;
    ageMs?: number;
    bound?: string;
  }): ZkVerification;
  newPhone(): Promise<Member>;
  /** The holders the agent has pinned for the slot; a recovery replaces the phone. */
  directory: Member['info'][];
  exit(to?: 'payoutB' | 'attacker'): { msg: Uint8Array; tx: Record<string, unknown> };
}

const sha = (b: string) => b;

/** DKG and the three test signatures, with the agent as holder 3 and scripted holders 1 and 2. */
async function slotSetupWithAgent(w: World, agent: RecoveryAgent) {
  const session = await w.relay.openSession({
    dealId: w.dealId,
    slot: w.slot,
    purpose: 'dkg',
    participants: w.participants(),
  });
  const [r1, r2] = await Promise.all([
    w.holder(1).dkg(session),
    w.holder(2).dkg(session),
    agent.dkg(w.dealId, w.slot, session),
  ]).then((x) => [x[0], x[1]] as const);
  const keys = [r1.key, r2.key] as DkgKey[];
  const pub = r1.key.public;
  const ctx = r1.ctx;
  const sigs: { pair: [number, number]; sig: Uint8Array }[] = [];
  for (const pair of PAIRS) {
    const ids = pair.map((i) => (w.members[i - 1] as Member).info.identifier) as [string, string];
    const sid = await w.relay.openSession({
      dealId: w.dealId,
      slot: w.slot,
      purpose: 'sign',
      participants: w.participants(),
      pair: ids,
    });
    const msg = testSignMessage(ctx, pub, pair);
    const scripted = pair
      .filter((i) => i !== 3)
      .map((i) =>
        w.holder(i).sign(sid, {
          msg,
          kind: 'tagged',
          share: (keys[i - 1] as DkgKey).secret,
          pub,
          pair,
          check: (m, l) => testSignCheck(ctx, pub, i)(m, l),
        }),
      );
    const withAgent = pair.includes(3) ? [agent.testSign(w.dealId, w.slot, sid, pair)] : [];
    const out = await Promise.all([...scripted, ...withAgent]);
    sigs.push({ pair, sig: out[0] as Uint8Array });
  }
  const record = dkgCompletedRecord({
    ctx,
    pub,
    round1: r1.round1 as FrostMsg[],
    echoes: r1.echoes,
    testSignatures: sigs,
  });
  return { session, ctx, pub, keys, record, groupKey: record.slotPub };
}

export async function makeAgentWorld(w: World): Promise<AgentWorld> {
  const evidence = new MemoryEvidence();
  const notices: AgentWorld['notices'] = [];
  const clock = { now: T0 };
  const records = new Map<string, VerifiedRecord>();
  const wallet = Wallet.generate(ECDSA.ed25519);
  const payoutA = Wallet.generate(ECDSA.ed25519).classicAddress;
  const payoutB = Wallet.generate(ECDSA.ed25519).classicAddress;
  const lawyerSlots = Object.fromEntries(['B', 'LA', 'LB'].map((s) => [s, new Uint8Array([0xed, ...rnd(32)])]));
  const sealed: SealedDeal = {
    walletAddress: wallet.classicAddress,
    contractRoot: rnd(32),
    payoutA: { account: payoutA, tag: 7 },
    payoutB: { account: payoutB },
    exitAmountDrops: '5000000000',
    maxFeeDrops: '1000',
    slotPubs: { A: new Uint8Array(33), ...lawyerSlots } as SealedDeal['slotPubs'],
  };
  const deal = { allows: true, sealed, onboardingId: '1234567890123456789', opsAccount: {} as Record<string, string> };
  const dealInfo: DealInfoPort = {
    opsAccount: async (_d, s) => deal.opsAccount[s] as string,
    onboardingIdentifier: async () => deal.onboardingId,
    sealed: async () => deal.sealed,
    allowsSigning: async () => deal.allows,
  };
  const vault = new ShareVault(w.db, rnd(32));
  const recoveries = new RecoveryService({
    db: w.deps.db,
    evidence,
    notices: { notify: async (n) => void notices.push(n) },
    proofs: new RecordedProofs({ find: async (h) => records.get(h) }),
    deal: dealInfo,
    now: () => clock.now,
  });
  const dirRef = { list: w.members.map((m) => m.info) };
  const agent = new RecoveryAgent({
    db: w.deps.db,
    keys: (w.members[2] as Member).keys,
    vault,
    recoveries,
    evidence,
    deal: dealInfo,
    relay: w.relay,
    directory: async () => dirRef.list,
    pinned: w.registry.check,
    pollMs: 2,
    timeoutMs: 20_000,
  });
  const setup = await slotSetupWithAgent(w, agent);
  deal.sealed = { ...sealed, slotPubs: { ...sealed.slotPubs, A: setup.groupKey } };
  const aw: AgentWorld = {
    get directory() {
      return dirRef.list;
    },
    set directory(v) {
      dirRef.list = v;
    },
    agent,
    evidence,
    notices,
    clock,
    deal,
    vault,
    recoveries,
    records,
    setup,
    holders: w.members,
    registry: w.registry,
    proof: ({ identifier = deal.onboardingId, newKeyId, faceMatch = true, ageMs = 60_000, bound }) => {
      const sha256 = hex(rnd(32));
      const v = {
        verified: true,
        uniqueIdentifier: identifier,
        uniqueIdentifierType: 'SALTED',
        queryResultErrors: {},
        proofSha256: sha256,
        vkeyHash: `0x${hex(rnd(32))}`,
        version: '0.19.2',
        committedInputs: { custom_data: bound ?? recoveryBoundValue(w.dealId, newKeyId) },
        scope: `legx/v1/${w.dealId}`,
        domain: 'legx.app',
        trust: {
          chainId: 11155111,
          blockNumber: 1,
          blockHash: `0x${hex(rnd(32))}`,
          registryAddress: `0x${hex(rnd(20))}`,
          root: `0x${hex(rnd(32))}`,
          circuitManifestVersion: '0.19.2',
          vkeyHashes: [`0x${hex(rnd(32))}`],
          devMode: false,
        },
      } as unknown as ZkVerification;
      records.set(sha256, { result: v, verifiedAt: clock.now - ageMs, faceMatch });
      return v;
    },
    newPhone: async () => {
      const m = makeMember(1, 'A', 'phone');
      await pinEnrollmentKey(w.deps, w.dealId, {
        key_id: m.keys.keyId,
        slot: 'A',
        holder_role: 'phone',
        ed25519_pub: hex(m.info.edPub.slice(1)),
        mldsa65_pub: toBase64(m.info.pqPub),
        valid_from: 0,
      } as never);
      const entry = { holder: m.keys.keyId, role: 'phone' as Role, edPub: m.info.edPub };
      w.registry.pin(entry);
      w.registry.markLogged(enrollmentKeyHash(entry));
      return m;
    },
    exit: (to = 'payoutB') => {
      const s = deal.sealed;
      const tx = {
        TransactionType: 'Payment',
        Account: s.walletAddress,
        Destination: to === 'payoutB' ? s.payoutB.account : Wallet.generate(ECDSA.ed25519).classicAddress,
        Amount: '5000000000',
        Fee: '120',
        Sequence: 5,
        SigningPubKey: '',
      };
      const signer = deriveAddress(bytesToHex(setup.groupKey).toUpperCase());
      return { tx, msg: new Uint8Array(Buffer.from(encodeForMultiSigning(tx as never, signer), 'hex')) };
    },
  };
  return aw;
}
