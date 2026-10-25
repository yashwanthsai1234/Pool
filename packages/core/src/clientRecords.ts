// Client records view (DESIGN 8.10): each record shows three checks, its signature, its chain position (`seq` and
// `prev_hash`) and its ledger link. Records stay stored envelope bytes; nothing is re-serialized.
import { type ChainEntry, type EnvelopeCheck, entryLink, ZERO } from './evidence.ts';

export interface RecordChecks {
  seq: number;
  leafHash: string;
  signature: boolean;
  chain: boolean;
  ledger: 'linked' | 'none' | 'mismatch';
}
export interface ClientRecordsOptions {
  /** Where the list starts: the `seq` and the previous leaf hash it must link to. Defaults to a whole chain. */
  start?: { seq: number; prevHash: string };
  /** The validated ledger index of a transaction hash, or undefined when the ledger does not know it. */
  ledgerIndexOf: (txHash: string) => number | undefined;
}

// One result per record, in order. A bad record does not hide the next one: each record is checked against the
// leaf hash of the record before it, so a dropped record fails only the record after the gap.
export function verifyClientRecords(
  records: ChainEntry[],
  check: EnvelopeCheck,
  opts: ClientRecordsOptions,
): RecordChecks[] {
  let seq = opts.start?.seq ?? 0;
  let prev = opts.start?.prevHash ?? ZERO;
  return records.map((r) => {
    const link = entryLink(r);
    const chain = link !== undefined && link.seq === seq && link.prevHash === prev;
    const out: RecordChecks = {
      seq: typeof link?.seq === 'number' ? link.seq : -1,
      leafHash: r.leafHash,
      signature: link !== undefined && check(link.env),
      chain,
      ledger: link ? ledgerLink(link.predicate.ledger, opts.ledgerIndexOf) : 'none',
    };
    seq = out.seq >= 0 ? out.seq + 1 : seq + 1;
    prev = r.leafHash;
    return out;
  });
}

function ledgerLink(ledger: unknown, ledgerIndexOf: (h: string) => number | undefined): RecordChecks['ledger'] {
  if (ledger === undefined) return 'none';
  const { tx_hash, ledger_index } = (ledger ?? {}) as { tx_hash?: unknown; ledger_index?: unknown };
  return typeof tx_hash === 'string' && ledgerIndexOf(tx_hash) === ledger_index ? 'linked' : 'mismatch';
}
