// The recovery agent and the firm HSM co-signer, mounted in the DEMO profile only (production runs them as separate
// processes with their own `register`; `assertProfile` refuses them in this one). What the demo composition does for
// them, in place of the old stubs (I-W-13):
//   - their evidence goes into the deal's log as coordinator-signed events (`frost.*`), durable and chained, not to memory;
//   - their notices are `alert` outbox rows, not a no-op;
//   - the deal facts (operations account, sealed deal data, state) are read from the coordinator's own records;
//   - the HSM has a key pair of its own in the data folder, a key list signed by it, and a real `FirmCosigner` behind
//     `firmHsm.sign`; it pins the enrollment keys of a deal from the database (the demo trusts the coordinator's records,
//     production pins them out of band, DESIGN 6.3).
// The recovery proof port still refuses: nothing records recovery proofs yet (I-21), so no recovery can start.
// Source: DESIGN 6.4 (recovery and signing rules), 6.3 (key directory)

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { SignerPort } from '@legx/contracts/ports';
import { loadConfig } from '@legx/coordinator/deal';
import type { CoordinatorDeps } from '@legx/coordinator/deps';
import { FrostRelay, RelayStore } from '@legx/coordinator/frost/index';
import { derivePublicData } from '@legx/coordinator/publicData';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@legx/core/dealcore';
import { holderId, type Role, type SlotName } from '@legx/core/frost';
import type { SealedDeal } from '@legx/core/frostRules';
import { EnrollmentRegistry, enrollmentKeyHash } from '@legx/core/frostSetup';
import { fromBase64Strict, pqKeygen, toBase64 } from '@legx/core/pq';
import {
  AuditLog,
  type AuditSink,
  buildFirmKeyList,
  FirmCosigner,
  FirmShareVault,
  LawyerApprovals,
  wrapKeyFrom,
} from '@legx/firm-cosigner';
import { type DealInfoPort, type EvidencePort, RecoveryService, Refusal } from '@legx/recovery-agent';
import { buildKeyList, signKeyList } from '@legx/recovery-agent/keylist';
import type { AgentHttpDeps } from '@legx/recovery-agent/routes';
import type { HolderInfo, HolderKeys } from '@legx/recovery-agent/wire';
import { ed25519 } from '@noble/curves/ed25519.js';
import { watcherEvidence } from './wiring.ts';

/** The signing route's deps and the cosigner behind them, as `compose.ts` mounts them. */
export type FirmDeps = AgentHttpDeps & {
  readonly cosigner: FirmCosigner;
  readonly onError?: (e: unknown) => void;
};

const NOT_COMPOSED = () => {
  throw new Error('not wired in the demo composition');
};

/** The agents' evidence port: each event is signed by the coordinator and stored in the deal's log, in one transaction. */
function coordinatorEvidence(c: CoordinatorDeps): EvidencePort & AuditSink {
  const write = watcherEvidence(c.db, c.signer, c.ledger);
  return {
    append: async (dealId: string, kind: string, data: Record<string, unknown>) =>
      write({ kind, dealId, payload: data }),
  };
}

/** The deal facts the agents compare requests with, read from the coordinator's records (public data of the sealed deal). */
function dealFacts(c: CoordinatorDeps, maxFeeDrops: string): DealInfoPort {
  const payout = (p: string) => {
    const [account, tag] = p.split(':');
    return { account: account as string, ...(tag === undefined ? {} : { tag: Number(tag) }) };
  };
  return {
    opsAccount: async (dealId, slot) => {
      const deal = await c.db.repos.deals.get(dealId);
      const a = slot === 'LA' ? deal?.lawyer_ops_a : deal?.lawyer_ops_b;
      if (!a) throw new Error('unknown deal');
      return a;
    },
    onboardingIdentifier: async () => NOT_COMPOSED(),
    sealed: async (dealId): Promise<SealedDeal> => {
      const deal = await c.db.repos.deals.get(dealId);
      if (!deal) throw new Error('unknown deal');
      const pd = await derivePublicData(c.db.repos, deal, (await loadConfig(c.db.repos, dealId)).identity_policy);
      if (pd.status !== 'complete') throw new Error(`the deal is not sealed: ${pd.missing.join(', ')}`);
      const d = pd.publicData;
      const key = (k: string) => hexToBytes(k.toLowerCase());
      return {
        dealId,
        walletAddress: d.walletAddress,
        contractRoot: key(d.contractRoot),
        dealSeal: key(pd.dealSeal),
        payoutA: payout(d.payoutA),
        payoutB: payout(d.payoutB),
        exitAmountDrops: deal.amount_drops,
        maxFeeDrops,
        slotPubs: { A: key(d.xPubA), B: key(d.xPubB), LA: key(d.lawyerPubA), LB: key(d.lawyerPubB) },
      };
    },
    allowsSigning: async (dealId) => (await c.db.repos.deals.get(dealId))?.state !== 'CLOSED',
  };
}

interface KeyFile {
  keyId: string;
  edSecret: string;
  pqPublic: string;
  pqSecret: string;
}

/**
 * A service's enrollment key pair, made once and kept in the data folder (mode 0600), so a restart keeps it and the key
 * list it published still names it. Demo only: production holds these in the HSM.
 */
function holderKeys(dir: string, file: string, keyId: string): HolderKeys & { readonly pqPublic: Uint8Array } {
  const path = join(dir, file);
  if (!existsSync(path)) {
    const pq = pqKeygen();
    const made: KeyFile = {
      keyId,
      edSecret: bytesToHex(ed25519.utils.randomSecretKey()),
      pqPublic: toBase64(pq.publicKey),
      pqSecret: toBase64(pq.secretKey),
    };
    writeFileSync(path, JSON.stringify(made), { mode: 0o600 });
  }
  const f = JSON.parse(readFileSync(path, 'utf8')) as KeyFile;
  return {
    keyId: f.keyId,
    edSecret: hexToBytes(f.edSecret),
    pqSecret: fromBase64Strict(f.pqSecret) as Uint8Array,
    pqPublic: fromBase64Strict(f.pqPublic) as Uint8Array,
  };
}

const listedKey = (k: ReturnType<typeof holderKeys>) => ({
  holder: k.keyId,
  ed25519: `ED${bytesToHex(ed25519.getPublicKey(k.edSecret)).toUpperCase()}`,
  mldsa65: toBase64(k.pqPublic),
});

const notices = (c: CoordinatorDeps) => ({
  notify: async (n: object) => {
    await c.db.repos.outbox.enqueue({ topic: 'alert', payload: utf8ToBytes(JSON.stringify(n)) });
  },
});

const MAX_FEE_DROPS = '1000000';

/** The recovery agent's routes: durable evidence and notices, real deal facts. Its proof port refuses (I-21). */
export function demoAgentDeps(
  coordinator: CoordinatorDeps,
  o: { dir: string; now?: () => number; maxFeeDrops?: string },
): AgentHttpDeps {
  const keys = holderKeys(o.dir, 'recovery-agent-keys.json', 'recovery-agent');
  const recoveries = new RecoveryService({
    db: coordinator.db,
    evidence: coordinatorEvidence(coordinator),
    notices: notices(coordinator),
    proofs: {
      check: async () => {
        throw new Refusal('PROOF_NOT_VERIFIED'); // nothing records recovery proofs yet (I-21)
      },
    },
    deal: dealFacts(coordinator, o.maxFeeDrops ?? MAX_FEE_DROPS),
    now: o.now ?? Date.now,
  });
  const list = signKeyList(buildKeyList([{ ...listedKey(keys), role: 'recovery-agent' }]), keys.edSecret);
  return { auth: coordinator, recoveries, keyList: () => list };
}

const LAWYER_ROLE_ORDER: readonly Role[] = ['console', 'firm-hsm', 'partner'];

/**
 * The firm HSM: its own recovery routes (mounted under `/firm`) and the signing route. The three holders of a lawyer
 * slot are read from the deal's enrollment keys; each is pinned and marked logged in the HSM's own registry first,
 * because a key row exists only after its hash was recorded as evidence (`getUsable`).
 */
export async function demoFirmDeps(
  coordinator: CoordinatorDeps,
  o: {
    dir: string;
    signer: SignerPort;
    rp: { rpId: string; origin: string };
    now?: () => number;
    maxFeeDrops?: string;
  },
): Promise<FirmDeps & { readonly holder: HolderKeys }> {
  const keys = holderKeys(o.dir, 'firm-hsm-keys.json', 'firm-hsm');
  const evidence = coordinatorEvidence(coordinator);
  const deal = dealFacts(coordinator, o.maxFeeDrops ?? MAX_FEE_DROPS);
  const registry = new EnrollmentRegistry();
  const recoveries = new RecoveryService({
    db: coordinator.db,
    evidence,
    notices: notices(coordinator),
    proofs: {
      check: async () => {
        throw new Refusal('PROOF_NOT_VERIFIED');
      },
    },
    deal,
    now: o.now ?? Date.now,
  });
  const directory = async (dealId: string, slot: SlotName): Promise<readonly HolderInfo[]> => {
    const rows = (await coordinator.db.repos.enrollmentKeys.listForDeal(dealId)).filter(
      (k) => k.slot === slot && k.valid_to === undefined,
    );
    return LAWYER_ROLE_ORDER.map((role, i) => {
      const k = rows.find((r) => r.holder_role === role);
      if (!k) throw new Error(`slot ${slot} has no ${role} key`);
      const edPub = new Uint8Array([0xed, ...hexToBytes(k.ed25519_pub)]);
      const entry = { holder: k.key_id, role, edPub };
      registry.pin(entry);
      registry.markLogged(enrollmentKeyHash(entry));
      return {
        identifier: holderId(i + 1),
        keyId: k.key_id,
        role,
        edPub,
        pqPub: fromBase64Strict(k.mldsa65_pub) as Uint8Array,
        deviceId: k.key_id,
      };
    });
  };
  const cosigner = new FirmCosigner({
    db: coordinator.db,
    keys,
    vault: new FirmShareVault(coordinator.db, await wrapKeyFrom(o.signer)),
    recoveries,
    approvals: new LawyerApprovals(coordinator.db, o.rp),
    audit: new AuditLog(coordinator.db, evidence),
    deal,
    relay: new FrostRelay(coordinator, new RelayStore(coordinator.db)),
    directory,
    pinned: registry.check,
  });
  const list = signKeyList(buildFirmKeyList([{ ...listedKey(keys), role: 'firm-hsm' }]), keys.edSecret);
  return {
    auth: coordinator,
    recoveries,
    keyList: () => list,
    cosigner,
    holder: keys,
    onError: (e) => process.stderr.write(`legx firm hsm: ${e instanceof Error ? e.message : String(e)}\n`),
  };
}
