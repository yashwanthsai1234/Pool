// The lawyer console's test world: a complete valid deal from core's gate helper (4 slots, real FROST, real hybrid
// signatures), fakes for the ports that tasks 4.3 and 3.10 wire, and a public ledger fake that can disagree.
import type { PublicDealData } from '@legx/contracts/deal';
import { bytesToHex, hexToBytes } from '@legx/core/dealcore';
import type { SlotPublic } from '@legx/core/frost';
import type { KeyRegistry } from '@legx/core/hybridEnvelope';
import type { KeyRow, ReleaseInput } from '@legx/core/releaseGate';
import { messageFor } from '@legx/vault/vault';
import { ed25519 } from '@noble/curves/ed25519.js';
import { vi } from 'vitest';
import { decode, verifySignature } from 'xrpl';
import {
  DEAL_ID,
  LEDGER,
  makeWorld,
  mutable,
  NOW,
  OPS,
  type World,
} from '../../../../packages/core/test/helpers/gate.ts';
import { createLawyerConsole } from '../../src/routes/lawyers/-console/index.ts';
import type {
  ApprovalWire,
  ConsoleDeps,
  LedgerHeader,
  Role,
  SignRequest,
} from '../../src/routes/lawyers/-console/ports.ts';

export type { World };
export { DEAL_ID, LEDGER, mutable, NOW, OPS };

let worldP: Promise<World> | undefined;
export const world = () => {
  worldP ??= makeWorld();
  return worldP;
};

const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();
/** A sealed deal with another contract root (the root the clauses in a test give). */
export const withRoot = (data: PublicDealData, rootHex: string): PublicDealData =>
  ({ ...data, contractRoot: rootHex }) as PublicDealData;

export const slotPubOf = (hex: string): SlotPublic => ({
  signers: { min: 2, max: 3 },
  commitments: [hexToBytes(hex).slice(1)],
  verifyingShares: {},
});

export interface Options {
  role: Role;
  /** Whose operations account this console holds (default: its own). A wrong one is a submitter the seal does not name. */
  opsRole?: Role;
  input?: ReleaseInput;
  data?: PublicDealData;
  contract?: { clauses: Uint8Array[]; salts: Uint8Array[] };
  now?: number;
  /** What the public node says. Default: it agrees with the relay. */
  publicHash?: (index: number) => string | undefined;
  latest?: LedgerHeader;
  identity?: Partial<ConsoleDeps['identity']>;
  confirm?: ConsoleDeps['confirm'];
  /** Replaces the relay's snapshot (for example with the MSW-backed HTTP adapter). */
  snapshot?: ConsoleDeps['ledger']['snapshot'];
}

/** A console half over the valid world, with spies on every outbound port. */
export async function makeConsole(o: Options) {
  const w = await world();
  const input = o.input ?? mutable(w.input);
  const data = o.data ?? input.deal.data;
  const slotKey = o.role === 'LA' ? 'LA' : 'LB';
  const S = w.S[slotKey];
  const pub = slotPubOf(S.pubHex);
  const header: LedgerHeader = o.latest ?? { index: LEDGER.index, hash: LEDGER.hash, closeTime: LEDGER.closeTime };
  const ops = OPS[o.opsRole ?? o.role];
  const rows = input.records.keys as readonly KeyRow[];
  const registry: KeyRegistry = (id) => rows.find((r) => r.keyId === id);
  const appended: Uint8Array[] = [];
  const conditions: string[] = [];
  const submitted: string[] = [];
  let seq = 0;

  const slot = {
    pub,
    sign: vi.fn(async (request: SignRequest, _approval?: ApprovalWire) => S.sign(messageFor(pub, request))),
  };
  const requestApproval = vi.fn(
    async (hash: Uint8Array): Promise<ApprovalWire> =>
      ({
        credential_id: 'AA==',
        authenticator_data: 'AA==',
        client_data_json: 'AA==',
        signature: 'AA==',
        message_hash: bytesToHex(hash),
      }) as ApprovalWire,
  );
  const confirm = vi.fn(o.confirm ?? (async () => true));
  const ledger = {
    snapshot: vi.fn(o.snapshot ?? (async () => mutable(input) as ReleaseInput)),
    accountSequence: vi.fn(async () => 5),
    submit: vi.fn(async (blob: string) => {
      submitted.push(blob);
      const tx = decode(blob) as { TransactionType?: string };
      if (!verifySignature(blob)) return { validated: false, hash: '', ledgerIndex: 0, result: 'temBAD_SIGNATURE' };
      void tx;
      return { validated: true, hash: 'AB'.repeat(32), ledgerIndex: header.index + 1, result: 'tesSUCCESS' };
    }),
  };
  const publicLedger = {
    latest: vi.fn(async () => header),
    hashAt: vi.fn(async (i: number) =>
      o.publicHash ? o.publicHash(i) : i === input.ledger.index ? input.ledger.hash : undefined,
    ),
  };
  const evidence = {
    fields: vi.fn(async () => ({
      event_id: `0192f1a0-7b3c-7d4e-8f00-${String(seq + 1).padStart(12, '0')}`,
      seq: seq++,
      occurred_at: '2026-10-24T12:00:00Z',
      prev_hash: '00'.repeat(32),
      payload_commitment: '44'.repeat(32),
    })),
    append: vi.fn(async (b: Uint8Array) => void appended.push(b)),
    condition: vi.fn(async (c: string) => void conditions.push(c)),
    attach: vi.fn(async (_kind?: string, _side?: string, _bytes?: Uint8Array) => {}),
  };
  const deps: ConsoleDeps = {
    role: o.role,
    deal: {
      id: DEAL_ID,
      data,
      profile: 'production',
      contract: o.contract ?? { clauses: [], salts: [] },
    },
    slot,
    signer: o.role === 'LA' ? w.lawyerSigner.A : w.lawyerSigner.B,
    confirm,
    requestApproval,
    ops: {
      address: ops.address,
      pubHex: ops.pub,
      sign: async (m) => ed25519.sign(m, ops.sk),
    },
    ledger,
    publicLedger,
    evidence,
    registry,
    lawyerKeyIds: {
      A: [w.S.LA.holders[0]?.ed25519 as string, w.S.LA.holders[0]?.mlDsa65 as string],
      B: [w.S.LB.holders[0]?.ed25519 as string, w.S.LB.holders[0]?.mlDsa65 as string],
    },
    ledgerLookup: (i) => [...input.ledger.history, input.ledger].find((h) => h.index === i),
    identity: {
      salt: async () => new Uint8Array(32).fill(0x5a),
      trustList: [],
      zkVerify: async () => {
        throw new Error('no zk adapter in this test');
      },
      zkRequest: () => {
        throw new Error('no zk adapter in this test');
      },
      ...o.identity,
    },
    now: () => o.now ?? NOW,
  };
  return {
    c: createLawyerConsole(deps),
    deps,
    input,
    w,
    spies: { slot, requestApproval, confirm, ledger, publicLedger, evidence, appended, conditions, submitted },
    up,
  };
}
