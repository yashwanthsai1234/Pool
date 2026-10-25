// Reliable submission (IMPLEMENTATION 2.2; DESIGN 7.5 steps 5 and 6) and the LedgerPort built on it.
//
// A transaction is tracked by its slot: account plus Sequence, or account plus TicketSequence. One slot can be
// used by one transaction only, so the validated ledger answers "did ours apply?" even when a multisigned copy
// validated under another hash. The engine result of `submit` is only a hint, with one exception: tem and most
// tef codes mean this blob can never apply. `tefPAST_SEQ`, `tefALREADY`, `tefMAX_LEDGER` and `tefNO_TICKET` say
// the slot is taken or closed, possibly by our own earlier submission, so the ledger decides those.
// Source: https://xrpl.org/docs/concepts/transactions/reliable-transaction-submission
// Source: https://xrpl.org/docs/concepts/transactions/finality-of-results/transaction-malleability
// Source: https://xrpl.org/docs/references/protocol/transactions/transaction-results
import type { LedgerPort, SubmitResult, ValidatedTx, XrplJson } from '@legx/contracts/ports';
import { Drops, RippleTime, XrplHash } from '@legx/contracts/values';
import type { Client } from 'xrpl';
import xrpl from 'xrpl';
import type { LedgerEnv } from './env.ts';
import { readFees } from './ledger.ts';
import { assertAt, call, ledgerHeader, pages, type Rpc, record, rippledCode, rpcOf, snapshot, uint } from './read.ts';

/** No final answer yet: the transaction may still validate (timeout) or history is missing. Never a failure. */
export class NotFinalError extends Error {
  override readonly name = 'NotFinalError';
}

export interface SubmitOptions {
  /** Pause between checks of the validated ledger (default 1000 ms). */
  readonly pollMs?: number;
  /** Give up with NotFinalError after this long (default 10 minutes). Calling again with the same blob is safe. */
  readonly timeoutMs?: number;
  /** First ledger the transaction could be in. Default: the validated ledger before the first submit. */
  readonly minLedger?: number;
}

interface Slot {
  readonly account: string;
  readonly kind: 'sequence' | 'ticket';
  readonly n: number;
  readonly lastLedger: number | undefined;
  readonly hash: string;
  /** The transaction without signatures: the same for every malleated copy. */
  readonly body: string;
}

const SIGNATURE_FIELDS = new Set(['TxnSignature', 'Signers', 'SigningPubKey']);
const unsignedBody = (tx: Record<string, unknown>) =>
  xrpl.encode(Object.fromEntries(Object.entries(tx).filter(([k]) => !SIGNATURE_FIELDS.has(k))) as never);

function slotOf(blob: string): Slot {
  const tx = xrpl.decode(blob) as Record<string, unknown>;
  if (typeof tx.Account !== 'string') throw new TypeError('submitReliable: blob has no Account');
  const ticket = tx.TicketSequence;
  const lastLedger =
    tx.LastLedgerSequence === undefined ? undefined : uint(tx.LastLedgerSequence, 'LastLedgerSequence');
  return {
    account: tx.Account,
    kind: ticket === undefined ? 'sequence' : 'ticket',
    n: uint(ticket ?? tx.Sequence, 'Sequence'),
    lastLedger,
    hash: xrpl.hashes.hashSignedTx(blob),
    body: unsignedBody(tx),
  };
}

/** Results that say the slot is taken or closed: whether ours used it is read from the ledger. */
const SLOT_CODES = new Set(['tefPAST_SEQ', 'tefALREADY', 'tefMAX_LEDGER', 'tefNO_TICKET']);
const neverApplies = (code: string) => code.startsWith('tem') || (code.startsWith('tef') && !SLOT_CODES.has(code));
const accepted = (code: string) => code.startsWith('tes') || code.startsWith('tec') || code === 'terQUEUED';

/** True when `complete_ledgers` (for example "1-10,12-40") holds every ledger in lo..hi. */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/server-info-methods/server_info
export function coversRange(complete: string, lo: number, hi: number): boolean {
  if (lo > hi) return true;
  const spans = complete === 'empty' || complete === '' ? [] : complete.split(',');
  const parsed = spans.map((s) => {
    const m = /^(\d+)(?:-(\d+))?$/.exec(s.trim());
    const a = Number(m?.[1]);
    const b = Number(m?.[2] ?? m?.[1]);
    if (!m || a > b) throw new Error(`complete_ledgers: cannot read "${complete}"`);
    return [a, b] as const;
  });
  let next = lo;
  for (const [a, b] of parsed.sort((x, y) => x[0] - y[0])) {
    if (a > next) break;
    next = Math.max(next, b + 1);
  }
  return next > hi;
}

async function validatedState(rpc: Rpc): Promise<{ index: number; complete: string }> {
  const info = record((await call(rpc, { command: 'server_info' })).info, 'server_info.info');
  const v = info.validated_ledger;
  if (v === undefined || typeof info.complete_ledgers !== 'string')
    throw new Error('server_info: the server has no validated ledger');
  return {
    index: uint(record(v, 'server_info.validated_ledger').seq, 'validated_ledger.seq'),
    complete: info.complete_ledgers,
  };
}

/**
 * 'open': nothing used the slot by ledger `at`. 'used': something did. 'gone': the account is not in that ledger.
 * `at` is a validated ledger index, or 'current' for the open ledger (pending, so never a final answer by itself).
 */
async function slotState(rpc: Rpc, slot: Slot, at: number | 'current'): Promise<'open' | 'used' | 'gone'> {
  let sequence: number;
  try {
    const r = await call(rpc, { command: 'account_info', account: slot.account, ledger_index: at });
    if (at !== 'current') assertAt(r, at, 'account_info');
    sequence = uint(record(r.account_data, 'account_data').Sequence, 'account_data.Sequence');
  } catch (e) {
    if (rippledCode(e) === 'actNotFound') return 'gone';
    throw e;
  }
  if (slot.kind === 'sequence') return sequence > slot.n ? 'used' : 'open';
  if (slot.n >= sequence) return 'open'; // the ticket can still be created
  try {
    // Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/ledger-methods/ledger_entry#get-ticket-object
    const r = await call(rpc, {
      command: 'ledger_entry',
      ticket: { account: slot.account, ticket_seq: slot.n },
      ledger_index: at,
    });
    if (at !== 'current') assertAt(r, at, 'ledger_entry');
    return 'open';
  } catch (e) {
    if (rippledCode(e) === 'entryNotFound') return 'used';
    throw e;
  }
}

function createsAccount(metaBlob: unknown, account: string): boolean {
  const meta = xrpl.decode(String(metaBlob)) as { AffectedNodes?: { CreatedNode?: XrplJson }[] };
  return (meta.AffectedNodes ?? []).some((n) => {
    const c = n.CreatedNode;
    return c?.LedgerEntryType === 'AccountRoot' && (c.NewFields as XrplJson | undefined)?.Account === account;
  });
}

type Search = { readonly hash: string; readonly ours: boolean } | 'none' | 'incomplete';

/**
 * Walks the account's validated history back from ledger V to find the transaction in our slot. It stops with
 * 'none' only when the history provably reaches back before the slot: a transaction the account sent with a lower
 * Sequence, or the transaction that created the account. Pages are ordered, but entries inside a page may not be,
 * so 'none' waits until a whole page lies below the stop ledger. Running out of history gives 'incomplete'.
 */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_tx
async function searchSlot(rpc: Rpc, slot: Slot, V: number): Promise<Search> {
  let stopAt: number | undefined;
  const req = {
    command: 'account_tx',
    account: slot.account,
    ledger_index_min: -1,
    ledger_index_max: V,
    binary: true,
    forward: false,
    limit: 200,
  };
  for await (const page of pages(rpc, req)) {
    if (!Array.isArray(page.transactions)) throw new Error('account_tx: transactions is not an array');
    let lowest = Number.POSITIVE_INFINITY;
    for (const t of page.transactions) {
      const e = record(t, 'account_tx entry');
      if (e.validated !== true) throw new Error('account_tx: an entry is not validated');
      const ledger = uint(e.ledger_index, 'account_tx ledger_index');
      lowest = Math.min(lowest, ledger);
      const tx = xrpl.decode(String(e.tx_blob)) as Record<string, unknown>;
      if (tx.Account === slot.account) {
        const inSlot =
          slot.kind === 'sequence' ? tx.Sequence === slot.n : tx.Sequence === 0 && tx.TicketSequence === slot.n;
        if (inSlot) return { hash: xrpl.hashes.hashSignedTx(String(e.tx_blob)), ours: unsignedBody(tx) === slot.body };
        if (typeof tx.Sequence === 'number' && tx.Sequence !== 0 && tx.Sequence < slot.n)
          stopAt = Math.max(stopAt ?? 0, ledger);
      }
      if (createsAccount(e.meta_blob, slot.account)) stopAt = Math.max(stopAt ?? 0, ledger);
    }
    if (stopAt !== undefined && lowest < stopAt) return 'none';
  }
  return stopAt === undefined ? 'incomplete' : 'none';
}

/** The validated transaction with this hash, or undefined when no validated ledger holds it. */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/tx
async function validatedTx(rpc: Rpc, hash: string): Promise<ValidatedTx | undefined> {
  let r: XrplJson;
  try {
    r = await call(rpc, { command: 'tx', transaction: hash });
  } catch (e) {
    if (rippledCode(e) === 'txnNotFound') return undefined;
    throw e;
  }
  if (r.validated !== true) return undefined;
  const tx = record(r.tx_json, 'tx.tx_json');
  return {
    hash: XrplHash.parse(r.hash),
    ledgerIndex: uint(r.ledger_index, 'tx.ledger_index'),
    closeTime: RippleTime.parse(tx.date),
    tx,
    meta: record(r.meta, 'tx.meta'),
  };
}

/** What the slot says at ledger V: our validated result, another transaction's use of it, or nothing yet. */
async function resolveSlot(rpc: Rpc, slot: Slot, V: number): Promise<SubmitResult | undefined> {
  const state = await slotState(rpc, slot, V);
  if (state === 'open') return undefined;
  const found = await searchSlot(rpc, slot, V);
  if (typeof found === 'object') {
    if (!found.ours) return { status: 'rejected', result: slot.kind === 'ticket' ? 'tefNO_TICKET' : 'tefPAST_SEQ' };
    const v = await validatedTx(rpc, found.hash);
    if (!v) throw new Error(`tx ${found.hash}: in validated account_tx but not validated by tx`);
    const result = v.meta.TransactionResult;
    if (typeof result !== 'string') throw new Error(`tx ${found.hash}: meta has no TransactionResult`);
    return { status: 'validated', result, hash: v.hash, ledgerIndex: v.ledgerIndex, meta: v.meta };
  }
  if (state === 'gone') return undefined; // no account and nothing of ours in history: as if open
  if (found === 'incomplete')
    throw new NotFinalError(`slot ${slot.account}/${slot.n} is used, but the history that shows by what is missing`);
  // Used, yet no transaction in the slot: a TicketCreate skipped this Sequence, or the ticket never existed.
  return { status: 'rejected', result: slot.kind === 'ticket' ? 'tefNO_TICKET' : 'tefPAST_SEQ' };
}

/**
 * Absent for good: the validated ledger is past LastLedgerSequence, `complete_ledgers` covers minLedger to
 * LastLedgerSequence, and `tx` over that range (in spans of at most 1000 ledgers) answers txnNotFound, or knows
 * the transaction only as unvalidated (a held transaction that no ledger holds). `searched_all` is not used: Testnet does not return it, and standalone xrpld 3.4.1 returns false even over a
 * covered range (build/tmp/2.2/probe.ts). The caller has already seen the slot open at V.
 */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/tx
async function absent(rpc: Rpc, slot: Slot, v: { index: number; complete: string }, min: number): Promise<boolean> {
  const lls = slot.lastLedger;
  if (lls === undefined || v.index <= lls || !coversRange(v.complete, min, lls)) return false;
  for (let lo = min; lo <= lls; lo += 1000) {
    const hi = Math.min(lo + 999, lls);
    try {
      const r = await call(rpc, { command: 'tx', transaction: slot.hash, min_ledger: lo, max_ledger: hi });
      // A held transaction (terPRE_SEQ, queued) is answered from the server's cache as {hash, validated: false}:
      // known, but in no validated ledger. Only a validated answer means the transaction is on the ledger.
      if (r.validated === true) return false;
    } catch (e) {
      if (e instanceof xrpl.ConnectionError) throw e;
      if (rippledCode(e) !== 'txnNotFound') return false;
    }
  }
  return true;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Submits a signed blob and returns its final outcome: `validated` (tes or tec in a validated ledger), `rejected`
 * (tem or tef: this blob can never apply), or `expired` (LastLedgerSequence passed and the transaction is absent).
 * `tel` and `ter` are never final. After a dropped connection it reconnects, resubmits the same blob (safe: one
 * slot applies at most once) and finds the result by account and sequence. Throws NotFinalError instead of ever
 * guessing. Not built on xrpl.js `submitAndWait`, which waits about 20 ledgers on a tef and refuses blobs without
 * LastLedgerSequence.
 *
 * A REPLAYED blob (an old, already validated one sent again) is answered with its ORIGINAL validated outcome
 * (same hash, same result, usually `tesSUCCESS`), not `tefPAST_SEQ`: the slot search finds the same unsigned body in
 * that slot. This is safe (nothing applies twice) but a caller expecting `tefPAST_SEQ` for a replay sees success. Raw
 * `submit` still says `tefPAST_SEQ`. Pinned by T-A-14 (issue I-2.6-e).
 */
export async function submitReliable(rpc: Rpc, txBlob: string, opts: SubmitOptions = {}): Promise<SubmitResult> {
  const slot = slotOf(txBlob);
  const pollMs = opts.pollMs ?? 1000;
  const deadline = performance.now() + (opts.timeoutMs ?? 600_000);
  let minLedger = opts.minLedger;
  let resubmit = true;
  let final: string | undefined;
  for (;;) {
    try {
      minLedger ??= (await validatedState(rpc)).index;
      if (resubmit) {
        const r = await call(rpc, { command: 'submit', tx_blob: txBlob });
        const code = String(r.engine_result);
        if (neverApplies(code)) final = code;
        resubmit = !accepted(code) && final === undefined;
      }
      const v = await validatedState(rpc);
      const settled = await resolveSlot(rpc, slot, v.index);
      if (settled) return settled;
      // A copy of ours (other signatures) pending in the open ledger can still validate: wait for it.
      if (final && (await slotState(rpc, slot, 'current')) !== 'used') return { status: 'rejected', result: final };
      if (slot.lastLedger !== undefined && (await absent(rpc, slot, v, minLedger)))
        return { status: 'expired', lastLedgerSequence: slot.lastLedger };
    } catch (e) {
      if (!(e instanceof xrpl.ConnectionError)) throw e;
      resubmit = final === undefined; // the server may have lost it; the same blob is safe to send again
      await rpc.connect().catch(() => undefined);
    }
    if (performance.now() > deadline)
      throw new NotFinalError(`submitReliable: not final within the timeout (slot ${slot.account}/${slot.n})`);
    await sleep(pollMs);
  }
}

/** The LedgerPort over one xrpl.js client (contracts `LedgerPort`). */
export function ledgerPort(client: Client, env: LedgerEnv, opts: SubmitOptions = {}): LedgerPort {
  const rpc = rpcOf(client);
  return {
    network: env.name,
    validatedLedger: () => ledgerHeader(rpc, 'validated'),
    ledgerHeader: (i) => ledgerHeader(rpc, i),
    snapshot: (accounts, i, o) => snapshot(rpc, accounts, i, o),
    tx: (hash) => validatedTx(rpc, hash),
    autofill: async (tx, signersCount) => (await client.autofill(tx as never, signersCount)) as XrplJson,
    submitReliable: (blob) => submitReliable(rpc, blob, opts),
    fees: async () => {
      const f = await readFees(client);
      return {
        baseFee: Drops.parse(String(f.baseFeeDrops)),
        reserveBase: Drops.parse(String(f.baseReserveDrops)),
        reserveInc: Drops.parse(String(f.ownerReserveDrops)),
      };
    },
  };
}
