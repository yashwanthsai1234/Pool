// The real lawyer console ports (I-W-10), composed like the party app's `createPartyServices`: the signed API client, the vault frame
// and the public XRPL node, and nothing else. Every key stays where it is made: the evidence signer and the slot share are in the
// vault frame (the page asks, the frame checks and signs), the operations account key is a non-extractable WebCrypto key, and the
// identity boxes are opened in the frame. A port that has no source in the contracts is absent and says so, never faked.
// Source: DESIGN.md 4.4, 6.3 (pinned registry), 6.4 (firm HSM), 6.14 (operations account); build/DECISIONS.md OD-10, OD-32, OD-35
import type { PublicDealData } from '@legx/contracts/deal';
import type { SignerPort } from '@legx/contracts/ports';
import type { ZkVerifyRequest } from '@legx/contracts/records';
import type { Profile } from '@legx/core/attest';
import { bytesToHex, dealSeal, hexToBytes, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import { holderId, type SlotPublic } from '@legx/core/frost';
import type { KeyRegistry } from '@legx/core/hybridEnvelope';
import { fromBase64Strict, toBase64 } from '@legx/core/pq';
import type { LedgerHeader as GateHeader, KeyRow } from '@legx/core/releaseGate';
import type { connectVault, enrollmentKeys } from '@legx/vault';
import { apiRelay } from '@legx/vault/frost/transport';
import { deriveAddress } from 'xrpl';
import type { ApiClient } from '../../../lib/api.ts';
import { loadSealedDeal } from '../../../lib/seal.ts';
import { contractLedgerRelay } from './compose.ts';
import {
  type ConsoleDeps,
  ConsoleError,
  type EvidencePort,
  type OpsKey,
  type PublicLedger,
  type Role,
  SIDE_OF,
  type SlotPort,
} from './ports.ts';

type FrameVault = ReturnType<typeof connectVault>;
const ZERO32 = '00'.repeat(32);
const SLOT_OF: Record<Role, 'LA' | 'LB'> = { LA: 'LA', LB: 'LB' };

/** The evidence signer: both halves in the frame, over DSSE statements of this deal only (the frame refuses the rest). */
const frameSigner = (vault: Pick<FrameVault, 'signHybrid' | 'signerKeys'>, dealId: string): SignerPort => ({
  signHybrid: async (msg, ctx) => {
    if (ctx !== 'legx/dsse/v1') throw new ConsoleError('CONTEXT_REFUSED', ctx);
    return vault.signHybrid(dealId, msg);
  },
  publicKeys: () => vault.signerKeys(dealId),
});

/**
 * The operations account key of one deal: a non-extractable WebCrypto Ed25519 key in this origin's own store (it is not a share,
 * and the account is funded and single-signed by design, DESIGN 6.14). `store` is `enrollmentKeys` under its own database name.
 */
async function opsKey(
  store: Pick<ReturnType<typeof enrollmentKeys>, 'create' | 'sign'>,
  dealId: string,
): Promise<OpsKey> {
  const pubHex = `ED${bytesToHex(await store.create(dealId)).toUpperCase()}`;
  return { address: deriveAddress(pubHex), pubHex, sign: (msg) => store.sign(dealId, msg) };
}

/**
 * What the operations account signs to ask the firm HSM to join one signing session.
 * Source: services/firm-cosigner/src/cosigner.ts `operatorRequestMessage` (the test compares the two)
 */
export const firmCosignRequestMessage = (r: {
  dealId: string;
  slot: string;
  sessionId: string;
  seal: string;
  pair: readonly [number, number];
}): Uint8Array =>
  tupleHash('legx/firm-cosign-request/v1', [r.dealId, r.slot, r.sessionId, r.seal, r.pair.join(',')].map(utf8ToBytes));

type WireHolders = Parameters<FrameVault['signSlot']>[0]['holders'];

/**
 * The lawyer slot: share 1 in the frame, share 2 at the firm HSM. The page relays the frame's FROST messages through the API
 * (`frost.*`) and asks the HSM to join through `firm-hsm/sign`, authorized by the operations key; the lawyer's approval is already
 * in hand (`signWithApproval`) and goes to the frame, which checks it is over the hash of the bytes it derived itself.
 */
function firmHsmSlot(o: {
  dealId: string;
  role: Role;
  /** The registered key pair id of this console's own enrollment key. */
  keyId: string;
  holders: WireHolders;
  pub: SlotPublic;
  data: PublicDealData;
  api: ApiClient;
  vault: Pick<FrameVault, 'signSlot'>;
  ops: OpsKey;
}): SlotPort {
  const slot = SLOT_OF[o.role];
  const seal = bytesToHex(dealSeal(o.data));
  const pair = [1, 2] as const; // the console and the HSM: the console aggregates, so no message travels in the HTTP call
  return {
    pub: o.pub,
    sign: (request, approval) =>
      o.vault.signSlot(
        { dealId: o.dealId, slot, holders: o.holders, localIndex: 1, remote: 2, keyId: o.keyId, request, approval },
        {
          relay: apiRelay(o.api as never, { dealId: o.dealId, slot }),
          start: async ({ sessionId, approval: a }) => {
            const sig = await o.ops.sign(firmCosignRequestMessage({ dealId: o.dealId, slot, sessionId, seal, pair }));
            await o.api.firmHsm.sign({
              dealId: o.dealId,
              slot,
              sessionId: sessionId as never,
              pair: [...pair],
              seal: seal as never,
              operator: { opsPub: o.ops.pubHex as never, sig: bytesToHex(sig) as never },
              ...(a ? { approval: a } : {}),
            });
          },
        },
      ),
  };
}

/** A UUIDv7 for `at` (Unix ms). Source: https://www.rfc-editor.org/rfc/rfc9562#section-5.7 */
function uuid7(at: number): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  new DataView(b.buffer).setUint16(0, Math.floor(at / 2 ** 32) & 0xffff);
  new DataView(b.buffer).setUint32(2, at >>> 0);
  b[6] = 0x70 | ((b[6] as number) & 0x0f);
  b[8] = 0x80 | ((b[8] as number) & 0x3f);
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * The evidence port over `events.head` and `events.append`. A lost race (`seq_taken`) is an error the caller retries with fresh
 * fields. Two operations need no upload: the ZK route stores the public proof set it verified (services/zk-verifier/src/store.ts),
 * and the coordinator reads the release condition from the validated EscrowCreate (I-S-M2).
 */
function apiEvidence(api: ApiClient, dealId: string, nowMs: () => number = Date.now): EvidencePort {
  return {
    async fields() {
      const head = await api.events.head({ dealId });
      const at = nowMs();
      return {
        event_id: uuid7(at),
        seq: head.nextSeq,
        occurred_at: new Date(at).toISOString(),
        prev_hash: head.prevHash,
        payload_commitment: ZERO32, // inline data only: no off-ledger payload, as the coordinator's own events
      };
    },
    async append(envelope) {
      const r = await api.events.append({ dealId, envelope: toBase64(envelope) as never });
      if (r.status !== 'stored') throw new ConsoleError('SEQ_TAKEN');
    },
    attach: async () => undefined,
    condition: async () => undefined,
  };
}

/**
 * The release-stage proofs the client's phone has handed over, by presence message. The ZKPassport flow (`PassportProof`) fills it;
 * the console's passport check reads it, and with no proof for a message the check cannot run.
 */
export class ReleaseProofs {
  readonly #by = new Map<string, { request: ZkVerifyRequest; proofSet: Uint8Array }>();
  offer(presenceMsg: Uint8Array, request: ZkVerifyRequest, proofSet: Uint8Array): void {
    this.#by.set(bytesToHex(presenceMsg), { request, proofSet });
  }
  take(presenceMsg: Uint8Array): { request: ZkVerifyRequest; proofSet: Uint8Array } {
    const found = this.#by.get(bytesToHex(presenceMsg));
    if (!found) throw new ConsoleError('NO_PROOF', 'the client has not sent a passport proof for this request');
    return found;
  }
}

export interface ConsoleServiceDeps {
  dealId: string;
  role: Role;
  api: ApiClient;
  vault: Pick<FrameVault, 'signHybrid' | 'signerKeys' | 'signSlot' | 'openBox' | 'pinSeal' | 'loadDeal'>;
  /** `enrollmentKeys` of this origin's own database (the operations key). */
  opsStore: Parameters<typeof opsKey>[0];
  publicLedger: PublicLedger;
  confirm: ConsoleDeps['confirm'];
  requestApproval: ConsoleDeps['requestApproval'];
  /** What the lawyer was given out of band: the clauses and their salts (no contract route serves them). */
  contract: ConsoleDeps['deal']['contract'];
  /** The CSCA master list for the chip method. Empty means every chip check fails closed. */
  trustList?: readonly Uint8Array[];
  proofs: ReleaseProofs;
}

const slotPubOf = (pubHex: string): SlotPublic => ({
  signers: { min: 2, max: 3 },
  commitments: [hexToBytes(pubHex).slice(1)],
  verifyingShares: {},
});

/**
 * The console's dependencies for one deal and one lawyer role. The deal, the registry, the slot holders and the ledger history
 * come from ONE validated snapshot (`ledger.snapshot`), re-read by every gate run; the console still checks what it reads.
 */
export async function createConsoleDeps(d: ConsoleServiceDeps): Promise<ConsoleDeps> {
  const ledger = contractLedgerRelay(d.api);
  let snap = await ledger.snapshot(d.dealId);
  const headers = new Map<number, GateHeader>();
  const remember = (s: typeof snap) => {
    for (const h of [...s.ledger.history, s.ledger]) headers.set(h.index, h);
  };
  remember(snap);
  const rows = (): readonly KeyRow[] => snap.records.keys;
  const registry: KeyRegistry = (id) => rows().find((r) => r.keyId === id);
  const slot = SLOT_OF[d.role];
  const holderKeys = snap.records.slotHolders[slot];
  const keyRow = (id: string) => {
    const row = registry(id);
    if (!row) throw new ConsoleError('KEY_UNKNOWN', id);
    return row;
  };
  const roles = ['console', 'firm-hsm', 'partner'] as const;
  const holders = holderKeys.map((h, i) => {
    const role = roles[i] as (typeof roles)[number];
    return {
      identifier: holderId(i + 1),
      keyId: h.ed25519.split('#')[0] as string,
      role,
      edPub: new Uint8Array([0xed, ...keyRow(h.ed25519).publicKey]),
      pqPub: keyRow(h.mlDsa65).publicKey,
      deviceId: role,
      label: role,
    };
  });
  const ops = await opsKey(d.opsStore, d.dealId);
  // The frame remembers the pair id it enrolled under; the console reads it back instead of keeping a second copy.
  const keyId = (await d.vault.signerKeys(d.dealId)).keyIds.ed25519.split('#')[0] as string;
  const data = snap.deal.data;
  await loadSealedDeal(d.vault, d.dealId, data, (await d.api.deals.get({ dealId: d.dealId })).amountDrops);
  const publicLedger: PublicLedger = {
    latest: async () => {
      const h = await d.publicLedger.latest();
      headers.set(h.index, h);
      return h;
    },
    hashAt: (i) => d.publicLedger.hashAt(i),
  };
  const side = SIDE_OF[d.role];
  // OD-36 b: the client's salt is a box sealed to this lawyer's vault key; the coordinator serves it to this side's lawyer only.
  const salt = async () => {
    const { boxes } = await d.api.identityBox.get({ dealId: d.dealId, side });
    const found = boxes.find((b) => b.kind === 'zk-salt')?.box;
    const enc = found && fromBase64Strict(found.enc);
    const ct = found && fromBase64Strict(found.ciphertext);
    if (!found || !enc || !ct) throw new ConsoleError('NO_SALT_BOX', 'the client has not sent the sealed salt');
    return d.vault.openBox(d.dealId, 'zk-salt', side, { suite: found.suite, enc, ct });
  };
  const lawyerKey = (r: 'LA' | 'LB') => {
    const h = snap.records.slotHolders[r][0];
    return [h.ed25519, h.mlDsa65];
  };
  return {
    role: d.role,
    deal: { id: d.dealId, data, profile: snap.profile as Profile, contract: d.contract },
    slot: firmHsmSlot({
      dealId: d.dealId,
      role: d.role,
      keyId,
      holders: holders as unknown as WireHolders,
      pub: slotPubOf(d.role === 'LA' ? data.lawyerPubA : data.lawyerPubB),
      data,
      api: d.api,
      vault: d.vault,
      ops,
    }),
    signer: frameSigner(d.vault, d.dealId),
    confirm: d.confirm,
    requestApproval: d.requestApproval,
    ops,
    ledger: {
      ...ledger,
      snapshot: async (dealId) => {
        snap = await ledger.snapshot(dealId);
        remember(snap);
        return snap;
      },
    },
    publicLedger,
    evidence: apiEvidence(d.api, d.dealId),
    registry,
    lawyerKeyIds: { A: lawyerKey('LA'), B: lawyerKey('LB') },
    ledgerLookup: (i) => headers.get(i),
    identity: {
      salt,
      trustList: d.trustList ?? [],
      zkVerify: async (request) =>
        d.api.zk.verify({ dealId: d.dealId, side, request, zkSalt32: bytesToHex(await salt()) as never }) as never,
      zkRequest: (msg) => d.proofs.take(msg),
    },
    onboarding: {
      openDisclosure: async (box, dealId, s) => {
        try {
          const facts = JSON.parse(new TextDecoder().decode(await d.vault.openBox(dealId, 'zk-disclosure', s, box)));
          return { ok: true, facts };
        } catch {
          return { ok: false, code: 'OPEN_FAILED' };
        }
      },
    },
    now: () => Math.max(...[...headers.values()].map((h) => h.closeTime)),
  };
}
