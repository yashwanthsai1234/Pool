// The dashboard's view of one deal, computed from the live feed rows (OD-9: a `deal.event` row is
// `{ envelope, summary }`; the envelope is the stored DSSE, whose payload is the in-toto statement of DESIGN 8.1).
// Everything here is a pure function of the rows and an attack result: the dashboard only reads.

import { GATE_CODES, LOCK_CODES } from '@legx/contracts/records';
import type { DealState } from '@legx/contracts/values';
import type { LiveRow } from '../../lib/live.ts';
import type { AttackResult } from './-attack-api.ts';

type ItemStatus = 'pass' | 'fail' | 'pending';
export interface Item {
  readonly code: string;
  readonly status: ItemStatus;
  readonly detail?: string;
}
export interface LedgerEntry {
  readonly key: string;
  readonly label: string;
  readonly txHash: string;
  readonly ledgerIndex: number;
}
export interface FrostEntry {
  readonly slot: string;
  readonly pair?: readonly [string, string];
}
export interface EvidenceView {
  readonly events: readonly { seq: number; kind: string }[];
  readonly chain: 'empty' | 'intact' | 'broken';
  readonly checkpoint?: { treeSize: number; root: string; anchorTx: string; anchorLedger: number };
}
export interface DashboardView {
  readonly state: (typeof DealState.options)[number] | undefined;
  readonly lock: readonly Item[];
  readonly gate: readonly Item[];
  readonly ledger: readonly LedgerEntry[];
  readonly evidence: EvidenceView;
  readonly frost: readonly FrostEntry[];
}

type Json = Record<string, unknown>;
const obj = (x: unknown): Json => (typeof x === 'object' && x !== null ? (x as Json) : {});
const str = (x: unknown): string | undefined => (typeof x === 'string' ? x : undefined);

function b64Json(b64: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))));
  } catch {
    return undefined;
  }
}

interface Decoded {
  readonly seq?: number;
  readonly kind: string;
  readonly state?: string;
  readonly ledger?: { tx_hash: string; ledger_index: number };
  readonly data: Json;
}

/** A `deal.event` row: the summary says what it is; the envelope (when it decodes) says everything else. */
function decodeEvent(row: LiveRow): Decoded | undefined {
  if (row.topic !== 'deal.event') return undefined;
  const body = obj(b64Json(row.payload));
  const summary = obj(body.summary);
  const kind = str(summary.kind);
  if (!kind) return undefined;
  const statement = obj(b64Json(str(obj(b64Json(str(body.envelope) ?? '')).payload) ?? ''));
  const predicate = obj(statement.predicate);
  const l = obj(summary.ledger);
  const ledger =
    typeof l.tx_hash === 'string' && typeof l.ledger_index === 'number'
      ? { tx_hash: l.tx_hash, ledger_index: l.ledger_index }
      : undefined;
  return {
    ...(typeof predicate.seq === 'number' ? { seq: predicate.seq } : {}),
    kind,
    ...(str(summary.state) ? { state: str(summary.state) as string } : {}),
    ...(ledger ? { ledger } : {}),
    data: obj(predicate.data),
  };
}

// ---------- lock steps (DESIGN 5.2 5a to 5g, in ledger order) ----------

/** The seven lock steps and the lock checker codes each one makes true; `type` is the XRPL transaction type. */
export const LOCK_STEPS: readonly { id: string; type: string; codes: readonly string[] }[] = [
  {
    id: '5a',
    type: 'SignerListSet',
    codes: ['ONE_SIGNER_LIST', 'SIGNERS_MATCH_KEYS', 'QUORUM_MATCH', 'QUORUM_NEEDS_EVERY_SIGNER'],
  },
  { id: '5b', type: 'AccountSet', codes: ['DOMAIN_IS_SEAL', 'DEPOSIT_AUTH_ON'] },
  {
    id: '5c',
    type: 'AccountSet',
    codes: ['DISALLOW_NFT_OFFER', 'DISALLOW_CHECK', 'DISALLOW_PAYCHAN', 'DISALLOW_TRUSTLINE'],
  },
  { id: '5d', type: 'DepositPreauth', codes: ['RELEASER_IS_OPS_B', 'ONE_PREAUTH', 'PREAUTH_ONLY_RELEASER'] },
  { id: '5e', type: 'CredentialCreate', codes: ['CREDENTIAL_SUBJECT_EXPECTED'] },
  { id: '5f', type: 'CredentialAccept', codes: ['CREDENTIAL_ACCEPTED'] },
  {
    id: '5g',
    type: 'AccountSet',
    codes: [
      'MASTER_DISABLED',
      'NO_REGULARKEY',
      'NO_NFTOKENMINTER',
      'NO_MINTEDNFTOKENS',
      'NO_AMMID',
      'NO_VAULTID',
      'NO_LOANBROKERID',
      'NO_SPONSOR',
      'NO_SPONSORINGOWNERCOUNT',
      'NO_SPONSORINGACCOUNTCOUNT',
      'TICKET_ALLOWED',
      'OWNER_COUNT_MATCHES',
    ],
  },
];
/** The escrow findings are true once the quarantine escrow exists (step 3). */
const ESCROW_CODES = [
  'QUARANTINE_PRESENT',
  'ESCROW_AMOUNT_AND_CONDITION',
  'NO_FINISH_DELAY_TRAP',
  'CANCEL_AFTER_MARGIN',
  'FOREIGN_INCOMING_ESCROW',
];

interface Observation {
  readonly type: string;
}
/** `ledger.observation` rows (the watcher's `{ hash, ledger_index, account, tx_type }`), in feed order. */
function observations(rows: readonly LiveRow[]): Observation[] {
  return rows.flatMap((r) => {
    if (r.topic !== 'ledger.observation') return [];
    const t = str(obj(b64Json(r.payload)).tx_type);
    return t ? [{ type: t }] : [];
  });
}

/** How many lock steps have validated: each observation must be the next expected step's transaction type. */
function lockStepsDone(rows: readonly LiveRow[], events: readonly Decoded[]): number {
  if (events.some((e) => e.kind === 'wallet.locked' || e.kind === 'lock.verified')) return LOCK_STEPS.length;
  let done = 0;
  for (const o of observations(rows)) if (LOCK_STEPS[done]?.type === o.type) done += 1;
  return done;
}

/** The failing findings of the last attack, by code: the checker or the gate turns red while the result is on screen. */
const failedByAttack = (attack: AttackResult | undefined) =>
  new Map((attack?.findings ?? []).filter((f) => !f.ok).map((f) => [f.code as string, f.detail ?? 'attack']));

function lockItems(rows: readonly LiveRow[], events: readonly Decoded[], attack: AttackResult | undefined): Item[] {
  const done = lockStepsDone(rows, events);
  const verified = events.findLast((e) => e.kind === 'lock.verified');
  const findings = Array.isArray(verified?.data.findings) ? (verified?.data.findings as Json[]) : [];
  const escrow = events.some((e) => e.kind === 'escrow.created');
  const passed = new Set<string>(LOCK_STEPS.slice(0, done).flatMap((s) => s.codes));
  if (escrow || verified) for (const c of ESCROW_CODES) passed.add(c);
  const attacked = failedByAttack(attack);
  return LOCK_CODES.map((code): Item => {
    const f = findings.find((x) => x.code === code);
    if (attacked.has(code)) return { code, status: 'fail', detail: attacked.get(code) as string };
    if (f)
      return {
        code,
        status: f.ok === true ? 'pass' : 'fail',
        ...(str(f.detail) ? { detail: str(f.detail) as string } : {}),
      };
    return { code, status: passed.has(code) ? 'pass' : 'pending' };
  });
}

function gateItems(events: readonly Decoded[], attack: AttackResult | undefined): Item[] {
  const gate = events.findLast((e) => e.kind === 'release.gate.passed');
  const findings = Array.isArray(obj(gate?.data.gate).findings) ? (obj(gate?.data.gate).findings as Json[]) : [];
  const attacked = failedByAttack(attack);
  return GATE_CODES.map((code): Item => {
    if (attacked.has(code)) return { code, status: 'fail', detail: attacked.get(code) as string };
    const f = findings.find((x) => x.code === code);
    if (f) return { code, status: f.ok === true ? 'pass' : 'fail' };
    return { code, status: 'pending' };
  });
}

const LABEL: Record<string, string> = {
  'shell.opened': 'Shell opened',
  'nft.minted': 'Contract NFT minted',
  'escrow.created': 'Escrow created',
  'wallet.locked': 'Wallet locked',
  'release.performed': 'Escrow released',
  'exit.validated': 'Exit paid',
  'escrow.cancelled': 'Escrow cancelled',
  'wallet.closed': 'Wallet closed',
  'checkpoint.anchored': 'Evidence anchored',
};

function evidenceView(events: readonly Decoded[]): EvidenceView {
  const seqs = events.flatMap((e) => (e.seq === undefined ? [] : [e.seq]));
  const intact = seqs.every((s, i) => s === i);
  const cp = events.findLast((e) => e.kind === 'checkpoint.anchored');
  const d = cp?.data ?? {};
  return {
    events: events.map((e, i) => ({ seq: e.seq ?? i, kind: e.kind })),
    chain: events.length === 0 ? 'empty' : intact ? 'intact' : 'broken',
    ...(cp &&
    typeof d.tree_size === 'number' &&
    str(d.root) &&
    str(d.anchor_tx_hash) &&
    typeof d.anchor_ledger === 'number'
      ? {
          checkpoint: {
            treeSize: d.tree_size,
            root: str(d.root) as string,
            anchorTx: str(d.anchor_tx_hash) as string,
            anchorLedger: d.anchor_ledger,
          },
        }
      : {}),
  };
}

const SLOTS = ['A', 'LA', 'B', 'LB'] as const;

export function buildView(
  rows: readonly LiveRow[],
  state: DashboardView['state'],
  attack?: AttackResult,
): DashboardView {
  const events = rows.flatMap((r) => decodeEvent(r) ?? []);
  const ledger: LedgerEntry[] = events.flatMap((e, i) =>
    e.ledger
      ? [
          {
            key: `${i}-${e.ledger.tx_hash}`,
            label: LABEL[e.kind] ?? e.kind,
            txHash: e.ledger.tx_hash,
            ledgerIndex: e.ledger.ledger_index,
          },
        ]
      : [],
  );
  const frost = SLOTS.map((slot): FrostEntry => {
    const s = events.findLast((e) => e.kind === 'frost.signed' && e.data.slot === slot);
    const raw = s?.data.signer_key_ids;
    const ids = Array.isArray(raw) ? raw.map(String) : [];
    return ids.length === 2 ? { slot, pair: [ids[0] as string, ids[1] as string] } : { slot };
  });
  return {
    state,
    lock: lockItems(rows, events, attack),
    gate: gateItems(events, attack),
    ledger,
    evidence: evidenceView(events),
    frost,
  };
}
