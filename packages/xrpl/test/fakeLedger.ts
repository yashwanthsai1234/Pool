// A small in-memory model of the rippled methods that submit.ts and read.ts call (API v2 shapes, as measured on
// xrpld 3.4.1 in build/tmp/2.2/probe.ts). It keeps validated and open ledgers apart, so tests can ask "what is
// really on the ledger" and compare it with what submitReliable answered.
import xrpl from 'xrpl';
import type { Rpc, RpcRequest } from '../src/read.ts';

const DEST = 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe';
const GENESIS_ADDR = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const GENESIS_WALLET = xrpl.Wallet.fromSeed('snoPBrXtMeMyMHUVTgbuqAfg1SUTb', { algorithm: xrpl.ECDSA.secp256k1 });

interface Entry {
  ledger: number;
  blob: string;
  hash: string;
  account: string;
  seq: number;
  ticket?: number;
  result: string;
}

interface Account {
  created: number;
  seq0: number;
  tickets: number[];
  deleted?: number;
  creationBlob: string;
}

const rippled = (error: string, extra: object = {}) => new xrpl.RippledError(error, { error, ...extra });

export class FakeLedger {
  V = 10;
  firstComplete = 1;
  /** Overrides `complete_ledgers`, for history gaps. */
  complete?: string;
  autoClose = true;
  connected = true;
  accounts = new Map<string, Account>();
  entries: Entry[] = [];
  calls: RpcRequest[] = [];
  /** Engine result override for a submit; return undefined for the normal rules. */
  engine?: (tx: Record<string, unknown>, n: number) => string | undefined;
  /** Drop the connection: 'before' the server sees the request, or 'after' it acted (the response is lost). */
  fail?: (req: RpcRequest, n: number) => 'before' | 'after' | undefined;
  /** Replace a response (hostile or odd server). */
  tamper?: (req: RpcRequest, result: unknown) => unknown;
  private submits = 0;
  private n = 0;

  addAccount(address: string, opts: { seq0?: number; tickets?: number[]; created?: number } = {}): void {
    const created = opts.created ?? 2;
    const creationBlob = GENESIS_WALLET.sign({
      TransactionType: 'Payment',
      Account: GENESIS_ADDR,
      Destination: address,
      Amount: '100000000',
      Fee: '12',
      Sequence: this.accounts.size + 1,
    }).tx_blob;
    this.accounts.set(address, { created, seq0: opts.seq0 ?? created, tickets: opts.tickets ?? [], creationBlob });
  }

  /** Validate the open ledger. */
  close(): void {
    this.V += 1;
  }

  /** Put a signed blob straight into a ledger (another party submitted it). */
  include(blob: string, ledger = this.V + 1, result = 'tesSUCCESS'): Entry {
    const tx = xrpl.decode(blob) as Record<string, unknown>;
    const e: Entry = {
      ledger,
      blob,
      hash: xrpl.hashes.hashSignedTx(blob),
      account: tx.Account as string,
      seq: tx.Sequence as number,
      result,
      ...(tx.TicketSequence === undefined ? {} : { ticket: tx.TicketSequence as number }),
    };
    this.entries.push(e);
    return e;
  }

  validatedEntries(account: string): Entry[] {
    return this.entries.filter((e) => e.account === account && e.ledger <= this.V);
  }

  private nextSeq(account: string, upTo: number): number {
    const a = this.accounts.get(account);
    if (!a) throw new Error('no account');
    const used = this.entries.filter((e) => e.account === account && e.ledger <= upTo && e.ticket === undefined);
    return a.seq0 + used.length;
  }

  private ticketExists(account: string, t: number, upTo: number): boolean {
    const a = this.accounts.get(account);
    return (
      !!a &&
      a.tickets.includes(t) &&
      !this.entries.some((e) => e.account === account && e.ticket === t && e.ledger <= upTo)
    );
  }

  rpc(): Rpc {
    return {
      isConnected: () => this.connected,
      connect: async () => {
        this.connected = true;
      },
      request: async (req: RpcRequest) => {
        this.calls.push(req);
        const n = this.n++;
        if (!this.connected) throw new xrpl.NotConnectedError('not connected');
        const f = this.fail?.(req, n);
        if (f === 'before') {
          this.connected = false;
          throw new xrpl.DisconnectedError('websocket was closed');
        }
        const result = this.handle(req);
        if (f === 'after') {
          this.connected = false;
          throw new xrpl.DisconnectedError('websocket was closed');
        }
        return { result: this.tamper ? this.tamper(req, result) : result };
      },
    };
  }

  private ledgerOf(req: RpcRequest): number {
    const li = req.ledger_index;
    if (li === 'validated' || li === undefined) return this.V;
    if (li === 'current') return Number.POSITIVE_INFINITY; // the open ledger, with queued transactions
    if (typeof li !== 'number' || li > this.V || li < this.firstComplete) throw rippled('lgrNotFound');
    return li;
  }

  private handle(req: RpcRequest): unknown {
    switch (req.command) {
      case 'server_info':
        if (this.autoClose) this.close();
        return {
          info: {
            validated_ledger: { seq: this.V },
            complete_ledgers: this.complete ?? `${this.firstComplete}-${this.V}`,
          },
        };
      case 'submit':
        return this.submit(req.tx_blob as string);
      case 'account_info': {
        const N = this.ledgerOf(req);
        const a = this.accounts.get(req.account as string);
        if (!a || a.created > N || (a.deleted !== undefined && a.deleted <= N)) throw rippled('actNotFound');
        return {
          account_data: { Account: req.account, Sequence: this.nextSeq(req.account as string, N), Balance: '1' },
          ledger_index: N,
          ledger_hash: hashOf(N),
          validated: true,
        };
      }
      case 'ledger_entry': {
        const N = this.ledgerOf(req);
        const t = req.ticket as { account: string; ticket_seq: number };
        if (!this.ticketExists(t.account, t.ticket_seq, N)) throw rippled('entryNotFound');
        return { node: { LedgerEntryType: 'Ticket', TicketSequence: t.ticket_seq }, ledger_index: N, validated: true };
      }
      case 'account_tx':
        return this.accountTx(req);
      case 'tx':
        return this.tx(req);
      default:
        throw new Error(`fake ledger: unexpected ${req.command}`);
    }
  }

  private submit(blob: string): unknown {
    const tx = xrpl.decode(blob) as Record<string, unknown>;
    const account = tx.Account as string;
    let r = this.engine?.(tx, this.submits++);
    if (r === undefined) {
      const lls = tx.LastLedgerSequence as number | undefined;
      const ticket = tx.TicketSequence as number | undefined;
      const next = this.nextSeq(account, Number.POSITIVE_INFINITY); // open and queued count
      if (ticket !== undefined)
        r = this.ticketExists(account, ticket, Number.POSITIVE_INFINITY) ? 'tesSUCCESS' : 'tefNO_TICKET';
      else if ((tx.Sequence as number) < next) r = 'tefPAST_SEQ';
      else if ((tx.Sequence as number) > next) r = 'terPRE_SEQ';
      else r = 'tesSUCCESS';
      if (r === 'tesSUCCESS' && lls !== undefined && lls < this.V + 1) r = 'tefMAX_LEDGER';
    }
    if (/^tes|^tec/.test(r)) this.include(blob, this.V + 1, r);
    if (r === 'terQUEUED') this.include(blob, this.V + 2, 'tesSUCCESS');
    return { engine_result: r, engine_result_message: r };
  }

  private accountTx(req: RpcRequest): unknown {
    const account = req.account as string;
    const a = this.accounts.get(account);
    const max = Math.min(typeof req.ledger_index_max === 'number' ? req.ledger_index_max : this.V, this.V);
    const rows: { ledger_index: number; tx_blob: string; meta_blob: string; validated: true }[] = [];
    const meta = (result: string, created?: string) =>
      xrpl.encode({
        TransactionIndex: 0,
        TransactionResult: result,
        AffectedNodes: created
          ? [
              {
                CreatedNode: {
                  LedgerEntryType: 'AccountRoot',
                  LedgerIndex: '00'.repeat(32),
                  NewFields: { Account: created, Sequence: 1, Balance: '1' },
                },
              },
            ]
          : [],
      } as never);
    for (const e of this.entries.filter((x) => x.account === account && x.ledger <= max).reverse())
      if (e.ledger >= this.firstComplete)
        rows.push({ ledger_index: e.ledger, tx_blob: e.blob, meta_blob: meta(e.result), validated: true });
    if (a && a.created <= max && a.created >= this.firstComplete)
      rows.push({
        ledger_index: a.created,
        tx_blob: a.creationBlob,
        meta_blob: meta('tesSUCCESS', account),
        validated: true,
      });
    rows.sort((x, y) => y.ledger_index - x.ledger_index);
    const start = typeof req.marker === 'number' ? req.marker : 0;
    const page = rows.slice(start, start + 2); // tiny pages: paging is always exercised
    return {
      account,
      transactions: page,
      validated: true,
      ...(start + 2 < rows.length ? { marker: start + 2 } : {}),
    };
  }

  private tx(req: RpcRequest): unknown {
    const lo = req.min_ledger as number | undefined;
    const hi = req.max_ledger as number | undefined;
    if (lo !== undefined && hi !== undefined) {
      if (hi - lo > 1000) throw rippled('excessiveLgrRange');
      if (lo > hi) throw rippled('invalidLgrRange');
    }
    const e = this.entries.find(
      (x) => x.hash === req.transaction && (lo === undefined || x.ledger >= lo) && (hi === undefined || x.ledger <= hi),
    );
    if (!e || e.ledger > this.V + 1) throw rippled('txnNotFound', { searched_all: false });
    const tx = xrpl.decode(e.blob) as Record<string, unknown>;
    return {
      tx_json: { ...tx, date: 800_000_000 + e.ledger, ledger_index: e.ledger },
      meta: {
        TransactionResult: e.result,
        ...(e.result === 'tesSUCCESS' ? { delivered_amount: tx.Amount } : {}),
      },
      hash: e.hash,
      ledger_index: e.ledger,
      validated: e.ledger <= this.V,
    };
  }
}

export const hashOf = (n: number) => n.toString(16).toUpperCase().padStart(64, '0');

/** A signed Payment blob. Signing is local: no ledger is needed. */
export function payment(
  wallet: InstanceType<typeof xrpl.Wallet>,
  f: { Sequence: number; LastLedgerSequence?: number; TicketSequence?: number; Amount?: string },
): { blob: string; hash: string } {
  const s = wallet.sign({
    TransactionType: 'Payment',
    Account: wallet.classicAddress,
    Destination: DEST,
    Amount: f.Amount ?? '1000',
    Fee: '12',
    ...f,
  } as never);
  return { blob: s.tx_blob, hash: s.hash };
}

/** The same transaction with another signature: a new hash, the same account and sequence (malleability). */
export function variant(blob: string): { blob: string; hash: string } {
  const tx = xrpl.decode(blob) as Record<string, unknown>;
  const sig = tx.TxnSignature as string;
  tx.TxnSignature = `${sig.slice(0, -2)}${sig.endsWith('00') ? '01' : '00'}`;
  const b = xrpl.encode(tx as never);
  return { blob: b, hash: xrpl.hashes.hashSignedTx(b) };
}
