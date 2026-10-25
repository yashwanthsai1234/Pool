// One-ledger reads (IMPLEMENTATION 2.2; DESIGN 0 rule 4, 6.9, 7.5): every read for one decision comes from one
// validated ledger, and every answer is checked against the ledger we asked for.
import type { AccountSnapshot, LedgerHeader, LedgerSnapshot, XrplJson } from '@legx/contracts/ports';
import { Drops, RippleTime, XrplAddress, XrplHash } from '@legx/contracts/values';
import type { Client } from 'xrpl';
import xrpl from 'xrpl';

export type RpcRequest = { readonly command: string } & Readonly<Record<string, unknown>>;

/** The part of an xrpl.js Client this package uses. Tests put a model ledger behind it. */
export interface Rpc {
  request(req: RpcRequest): Promise<{ readonly result: unknown }>;
  isConnected(): boolean;
  connect(): Promise<void>;
}

/**
 * Adapts an xrpl.js Client. A raw socket error that xrpl.js passes through unwrapped (the `ws` library's
 * "WebSocket is not open: readyState 0 (CONNECTING)" while a reconnect is under way) becomes a ConnectionError,
 * so callers treat it as the dropped connection it is.
 */
// Source: xrpl.js 5.3.0 dist/npm/client/connection.js (request: websocketSendAsync rejects with the ws error)
export function rpcOf(client: Client): Rpc {
  return {
    request: (req) =>
      (client.request(req as never) as Promise<{ result: unknown }>).catch((e: unknown) => {
        throw e instanceof xrpl.XrplError ? e : new xrpl.ConnectionError(e instanceof Error ? e.message : String(e));
      }),
    isConnected: () => client.isConnected(),
    connect: () => client.connect(),
  };
}

export function record(x: unknown, what: string): XrplJson {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) throw new Error(`${what}: expected an object`);
  return x as XrplJson;
}

export function uint(x: unknown, what: string): number {
  if (typeof x !== 'number' || !Number.isSafeInteger(x) || x < 0) throw new Error(`${what}: expected an integer`);
  return x;
}

export async function call(rpc: Rpc, req: RpcRequest): Promise<XrplJson> {
  return record((await rpc.request(req)).result, req.command);
}

/** The rippled error code (`txnNotFound`, `actNotFound`, ...) of a failed request, or undefined. */
export function rippledCode(e: unknown): string | undefined {
  if (!(e instanceof xrpl.RippledError)) return undefined;
  const data = e.data as { error?: unknown } | undefined;
  return typeof data?.error === 'string' ? data.error : undefined;
}

/** Checks that a response is validated and comes from exactly the ledger we asked for. */
export function assertAt(r: XrplJson, ledgerIndex: number, what: string, ledgerHash?: string): void {
  if (r.validated !== true) throw new Error(`${what}: answer is not from a validated ledger`);
  if (r.ledger_index !== ledgerIndex)
    throw new Error(`${what}: answered from ledger ${String(r.ledger_index)}, not ${ledgerIndex}`);
  if (ledgerHash !== undefined && r.ledger_hash !== undefined && r.ledger_hash !== ledgerHash)
    throw new Error(`${what}: ledger hash ${String(r.ledger_hash)} is not ${ledgerHash}`);
}

/**
 * Every page of a paged method. Always follows `marker`: the server may clamp `limit` or return an empty page
 * with a marker. A repeated marker is refused, so a broken server cannot loop us forever.
 */
// Source: https://xrpl.org/docs/references/http-websocket-apis/api-conventions/markers-and-pagination
export async function* pages(rpc: Rpc, req: RpcRequest): AsyncGenerator<XrplJson> {
  const seen = new Set<string>();
  let marker: unknown;
  do {
    const page = await call(rpc, marker === undefined ? req : { ...req, marker });
    yield page;
    marker = page.marker;
    const key = JSON.stringify(marker);
    if (marker !== undefined && seen.has(key)) throw new Error(`${req.command}: marker ${key} repeated`);
    seen.add(key);
  } while (marker !== undefined);
}

/** Index, hash and close_time of a validated ledger. Refuses an unvalidated or different ledger. */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/ledger-methods/ledger
export async function ledgerHeader(rpc: Rpc, index: number | 'validated'): Promise<LedgerHeader> {
  const r = await call(rpc, { command: 'ledger', ledger_index: index });
  if (r.validated !== true) throw new Error(`ledger ${index}: not validated`);
  const l = record(r.ledger, 'ledger.ledger');
  const ledgerIndex = uint(l.ledger_index, 'ledger.ledger_index');
  if (index !== 'validated' && ledgerIndex !== index) throw new Error(`ledger: asked for ${index}, got ${ledgerIndex}`);
  return { ledgerIndex, ledgerHash: XrplHash.parse(l.ledger_hash), closeTime: RippleTime.parse(l.close_time) };
}

// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_info
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_objects
async function accountAt(rpc: Rpc, account: XrplAddress, ledger: LedgerHeader): Promise<AccountSnapshot> {
  const at = { account, ledger_index: ledger.ledgerIndex };
  const info = await call(rpc, { command: 'account_info', ...at });
  assertAt(info, ledger.ledgerIndex, 'account_info', ledger.ledgerHash);
  const accountData = record(info.account_data, 'account_info.account_data');
  const objects: XrplJson[] = [];
  const ids = new Set<unknown>();
  for await (const page of pages(rpc, { command: 'account_objects', ...at, limit: 400 })) {
    assertAt(page, ledger.ledgerIndex, 'account_objects', ledger.ledgerHash);
    if (!Array.isArray(page.account_objects)) throw new Error('account_objects: account_objects is not an array');
    for (const o of page.account_objects) {
      const obj = record(o, 'account_objects entry');
      if (typeof obj.index !== 'string') throw new Error('account_objects: an object without index');
      if (ids.has(obj.index)) throw new Error(`account_objects: object ${obj.index} returned twice`);
      ids.add(obj.index);
      objects.push(obj);
    }
  }
  return { accountData, objects };
}

/**
 * `account_info` and every page of `account_objects` for each account, all at one validated ledger index
 * (the latest validated ledger when `ledgerIndex` is omitted). An account that does not exist there fails
 * with the rippled error `actNotFound`, unless `allowMissing` is set: then it is listed in `missing` (I-18).
 */
export async function snapshot(
  rpc: Rpc,
  accounts: readonly XrplAddress[],
  ledgerIndex?: number,
  options: { readonly allowMissing?: boolean } = {},
): Promise<LedgerSnapshot> {
  const ledger = await ledgerHeader(rpc, ledgerIndex ?? 'validated');
  const out: Record<string, AccountSnapshot> = {};
  const missing: string[] = [];
  for (const a of accounts) {
    try {
      out[a] = await accountAt(rpc, a, ledger);
    } catch (e) {
      if (!options.allowMissing || rippledCode(e) !== 'actNotFound') throw e;
      missing.push(a);
    }
  }
  return missing.length > 0 ? { ledger, accounts: out, missing } : { ledger, accounts: out };
}

export type XrplAmount =
  | Drops
  | { readonly currency: string; readonly issuer: XrplAddress; readonly value: string }
  | { readonly mpt_issuance_id: string; readonly value: string };

const DECIMAL = /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?$/;

/**
 * What a payment really delivered: `meta.delivered_amount`, never the transaction's `Amount` (a partial payment
 * can deliver far less). Undefined when the transaction did not succeed or delivered nothing; throws on
 * "unavailable" (old ledgers) or a malformed amount rather than guess.
 */
// Source: https://xrpl.org/docs/concepts/payment-types/partial-payments
// Source: https://xrpl.org/docs/references/protocol/transactions/metadata#delivered_amount
export function deliveredAmount(meta: XrplJson): XrplAmount | undefined {
  if (meta.TransactionResult !== 'tesSUCCESS') return undefined;
  const d = meta.delivered_amount;
  if (d === undefined) return undefined;
  if (d === 'unavailable') throw new Error('delivered_amount is "unavailable": the delivered amount is unknown');
  if (typeof d === 'string') return Drops.parse(d);
  const o = record(d, 'delivered_amount');
  if (typeof o.value !== 'string' || !DECIMAL.test(o.value)) throw new Error('delivered_amount: bad value');
  if (typeof o.mpt_issuance_id === 'string' && /^[0-9A-F]{48}$/i.test(o.mpt_issuance_id))
    return { mpt_issuance_id: o.mpt_issuance_id, value: o.value };
  if (typeof o.currency !== 'string' || o.currency.length === 0) throw new Error('delivered_amount: bad currency');
  return { currency: o.currency, issuer: XrplAddress.parse(o.issuer), value: o.value };
}
