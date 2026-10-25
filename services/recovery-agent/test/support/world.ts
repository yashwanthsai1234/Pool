// A relay world for the scripted-participant tests: PGlite, a stub ledger, one deal, one client slot of three holders
// whose enrollment keys are pinned in `enrollment_key`, and the relay over them.
import { randomBytes } from 'node:crypto';
import type { LedgerPort } from '@legx/contracts/ports';
import { createDeal } from '@legx/coordinator/deal';
import type { CoordinatorDeps } from '@legx/coordinator/deps';
import { pinEnrollmentKey } from '@legx/coordinator/enroll';
import { FrostRelay, RelayStore } from '@legx/coordinator/frost/index';
import { holderId, type Role, type SlotName } from '@legx/core/frost';
import { EnrollmentRegistry, enrollmentKeyHash } from '@legx/core/frostSetup';
import { pqKeygen, toBase64 } from '@legx/core/pq';
import type { KyselyDatabase } from '@legx/db/client';
import { openPglite } from '@legx/db/pglite';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { ed25519 } from '@noble/curves/ed25519.js';
import { vi } from 'vitest';
import { ECDSA, Wallet } from 'xrpl';
import { xwingShareCipher } from '../../src/cipher.ts';
import { FrostHolder, type HolderConfig } from '../../src/holder.ts';
import type { HolderInfo, HolderKeys } from '../../src/wire.ts';

// ML-DSA in pure JS is slow and the unit files run in parallel: give hooks and tests room.
vi.setConfig({ testTimeout: 600_000, hookTimeout: 600_000 });

export const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const unhex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
/** A value a test needs to be there. */
export const must = <T>(x: T | undefined): T => {
  if (x === undefined) throw new Error('expected a value');
  return x;
};
export const rnd = (n: number) => new Uint8Array(randomBytes(n));

const ROLES: Record<'client' | 'lawyer', Role[]> = {
  client: ['phone', 'second-authenticator', 'recovery-agent'],
  lawyer: ['console', 'firm-hsm', 'partner'],
};

export interface Member {
  readonly keys: HolderKeys;
  readonly info: HolderInfo;
}

export function makeMember(index: number, slot: SlotName, role: Role): Member {
  const edSecret = ed25519.utils.randomSecretKey();
  const pq = pqKeygen();
  const keyId = `${slot}-${role}-${hex(rnd(3))}`;
  return {
    keys: { keyId, edSecret, pqSecret: pq.secretKey },
    info: {
      identifier: holderId(index),
      keyId,
      role,
      edPub: new Uint8Array([0xed, ...ed25519.getPublicKey(edSecret)]),
      pqPub: pq.publicKey,
      deviceId: `${keyId}-device`,
    },
  };
}

export interface World {
  db: KyselyDatabase;
  deps: CoordinatorDeps;
  dealId: string;
  slot: SlotName;
  members: Member[];
  registry: EnrollmentRegistry;
  relay: FrostRelay;
  clock: { now: number };
  ledger: LedgerPort;
  holder(i: number, over?: Partial<HolderConfig>): FrostHolder;
  participants(): { identifier: string; keyId: string; role: string }[];
  close(): Promise<void>;
}

export async function makeWorld(
  over: { slot?: SlotName; signTimeoutMs?: number; db?: KyselyDatabase } = {},
): Promise<World> {
  const slot = over.slot ?? 'A';
  const db = over.db ?? openPglite();
  await db.migrate();
  const ledger = {
    network: 'standalone',
    validatedLedger: async () => ({ ledgerIndex: 1000, ledgerHash: 'A'.repeat(64), closeTime: 800_000_000 }),
  } as unknown as LedgerPort;
  const signer = nodeSigner(generateNodeSignerKeys('coordinator-ed' as never, 'coordinator-pq' as never));
  const deps: CoordinatorDeps = {
    db,
    ledger,
    signer,
    gate: { run: async () => ({ ok: true }) },
    lawyerKeys: () => undefined,
  };
  const addr = () => Wallet.generate(ECDSA.ed25519).classicAddress;
  const deal = await createDeal(deps, {
    network: 'standalone',
    identityPolicy: 'zk-or-chip',
    amountDrops: '5000000000',
    payoutA: `${addr()}:7`,
    payoutB: addr(),
    lawyerOpsA: addr(),
    lawyerOpsB: addr(),
  });
  const roles = slot === 'A' || slot === 'B' ? ROLES.client : ROLES.lawyer;
  const members = roles.map((r, i) => makeMember(i + 1, slot, r));
  const registry = new EnrollmentRegistry();
  for (const m of members) {
    await pinEnrollmentKey(deps, deal.dealId, {
      key_id: m.keys.keyId,
      slot,
      holder_role: m.info.role,
      ed25519_pub: hex(m.info.edPub.slice(1)),
      mldsa65_pub: toBase64(m.info.pqPub),
      valid_from: 0,
    } as never);
    const entry = { holder: m.keys.keyId, role: m.info.role as Role, edPub: m.info.edPub };
    registry.pin(entry);
    registry.markLogged(enrollmentKeyHash(entry));
  }
  const clock = { now: 1_000_000 };
  const store = new RelayStore(db);
  const base = new FrostRelay(deps, store, { now: () => clock.now, signTimeoutMs: over.signTimeoutMs ?? 30_000 });
  const relay = base;
  const w: World = {
    db,
    deps,
    dealId: deal.dealId,
    slot,
    members,
    registry,
    relay,
    clock,
    ledger,
    holder: (i, o = {}) =>
      new FrostHolder({
        index: i,
        keys: (members[i - 1] as Member).keys,
        dealId: deal.dealId,
        slot,
        holders: members.map((m) => m.info),
        relay,
        cipher: xwingShareCipher,
        pinned: registry.check,
        pollMs: 2,
        timeoutMs: 20_000,
        ...o,
      }),
    participants: () => members.map((m) => ({ identifier: m.info.identifier, keyId: m.keys.keyId, role: m.info.role })),
    close: () => db.close(),
  };
  return w;
}
