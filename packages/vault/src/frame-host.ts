// What the vault frame can do with its own enrollment keys (DESIGN 6.3, 8.10): make them once, publish the public halves,
// sign API requests (OD-5) and sign relay messages for a ceremony. The private halves never leave the frame: only
// public keys and signatures cross the port.
// Source: DESIGN.md 6.3, 8.10; build/DECISIONS.md OD-5
import type { ApiAuth } from '@legx/contracts/api';
import type { HybridPublicKeys, HybridSignature } from '@legx/contracts/ports';
import { tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import type { SealedDeal } from '@legx/core/frostRules';
import type { SealedPackage } from '@legx/core/pq';
import type { CeremonyHost } from './ceremony.ts';
import { dsseDealOf } from './dsse.ts';
import { enrollmentKeys } from './enrollment.ts';
import { VaultError } from './errors.ts';
import { RELAY_CONTEXT } from './frost/wire.ts';
import { pairIds } from './pairs.ts';
import { apiRequestSigner } from './pq/apiRequest.ts';
import { pqKeys, type ZkBoxKind } from './pq/keys.ts';
import type { PartyRole } from './rules.ts';
import { sealKeeper } from './seal.ts';
import { type ShellInfo, shellKey } from './shell.ts';

export type EnrollResult = { ed25519: Uint8Array; mlDsa65: Uint8Array; xwing: Uint8Array };
export type SignApiInput = {
  dealId: string;
  /** The registered key pair id (`<pair>#ed25519`, `<pair>#ml-dsa-65`). */
  /** Default: the pair id remembered at `enroll`. */
  pairId?: string;
  method: string;
  /** The path and query as the server receives them. */
  path: string;
  body: Uint8Array;
  ledgerIndex: number;
};

export interface FrameHost extends CeremonyHost {
  /** The shell setup key: made once, address known (DESIGN D17). */
  shellKey(dealId: string): Promise<ShellInfo>;
  /** One signed setup transaction of the lock sequence, as a blob; the key is wiped after DisableMaster. */
  signShell(dealId: string, tx: Record<string, unknown>): Promise<string>;
  /** Makes the keys (once). `pairId` is the registered key pair id; it is remembered so later requests need not repeat it. */
  enroll(dealId: string, pairId?: string): Promise<EnrollResult>;
  /** The deals this namespace holds enrollment keys for (OD-35: how the lawyer console lists its deals). */
  deals(): Promise<string[]>;
  signApi(input: SignApiInput): Promise<ReturnType<typeof ApiAuth.parse>>;
  /** The lawyer console's evidence signer (I-W-10): both halves over a DSSE statement of this deal, under `legx/dsse/v1`, and nothing else. */
  signHybrid(dealId: string, msg: Uint8Array): Promise<HybridSignature>;
  /** The public halves and key ids of the signer above. */
  signerKeys(dealId: string): Promise<HybridPublicKeys>;
  /** OD-36: pins the deal seal at join time (set once). */
  pinSeal(dealId: string, seal: string): Promise<void>;
  /** OD-36: loads public deal data; accepted only if its recomputed seal is the pinned one. */
  loadDeal(dealId: string, data: unknown, exitAmountDrops: string): Promise<void>;
  /** The vault's `deals` dependency in the frame: the verified deal, or NOT_FOUND. */
  sealedDeal(dealId: string): Promise<SealedDeal>;
  /** OD-32: opens the `zk-salt` or `zk-disclosure` box of the client this lawyer represents (lawyer A: side A, lawyer B: side B). */
  openBox(dealId: string, kind: ZkBoxKind, side: 'A' | 'B', pkg: SealedPackage): Promise<Uint8Array>;
}

/** The client side a lawyer role represents; a client role represents none. */
const SIDE_OF_LAWYER: Partial<Record<PartyRole, 'A' | 'B'>> = { lawyerA: 'A', lawyerB: 'B' };
// Source: packages/core/src/zkIdentity.ts `boxAad` (not exported); the test seals with core and opens here.
const boxAad = (dealId: string, side: string) =>
  tupleHash('legx/zk-box-aad/v1', [utf8ToBytes(dealId), utf8ToBytes(side)]);

export function vaultFrameHost(opts: { role: PartyRole; dbName?: string }): FrameHost {
  const ed = enrollmentKeys(opts);
  const pq = pqKeys(opts);
  const shell = shellKey(opts);
  const pairs = pairIds(opts);
  const seals = sealKeeper(opts);
  const pairOf = async (dealId: string, given?: string) => {
    const pair = given ?? (await pairs.get(dealId));
    if (pair === undefined) throw new VaultError('NOT_FOUND');
    return pair;
  };
  return {
    shellKey: (dealId) => shell.create(dealId),
    signShell: (dealId, tx) => shell.sign(dealId, tx),
    async enroll(dealId, pairId) {
      const [ed25519, keys] = await Promise.all([ed.create(dealId), pq.create(dealId)]);
      if (pairId !== undefined) await pairs.set(dealId, pairId);
      return { ed25519, ...keys };
    },
    deals: () => pairs.deals(),
    async signApi({ dealId, pairId, method, path, body, ledgerIndex }) {
      const { signRaw } = await pq.hybridSigner(dealId, await pairOf(dealId, pairId));
      return apiRequestSigner(signRaw, async () => ledgerIndex)({ method, path, body });
    },
    async signHybrid(dealId, msg) {
      const { signRaw } = await pq.hybridSigner(dealId, await pairOf(dealId));
      if (!dsseDealOf(msg, dealId)) throw new VaultError('MESSAGE_REFUSED');
      return signRaw(msg, 'legx/dsse/v1');
    },
    pinSeal: (dealId, seal) => seals.pin(dealId, seal),
    loadDeal: (dealId, data, amount) => seals.load(dealId, data, amount),
    sealedDeal: (dealId) => seals.get(dealId),
    async openBox(dealId, kind, side, pkg) {
      if (SIDE_OF_LAWYER[opts.role] !== side) throw new VaultError('ROLE_REFUSED');
      return pq.openBox(dealId, kind, pkg, boxAad(dealId, side));
    },
    async signerKeys(dealId) {
      return (await pq.hybridSigner(dealId, await pairOf(dealId))).publicKeys();
    },
    async partyKeys({ dealId, keyId }) {
      const half = await pq.half(dealId, keyId);
      return {
        keyId,
        signEd: (msg) => ed.sign(dealId, msg),
        signPq: (msg) => half.sign(msg, RELAY_CONTEXT),
      };
    },
  };
}
