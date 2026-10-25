// The renewal job (DESIGN 8.4): on its schedule, re-time-stamp the evidence head. The WORM store is the only state:
// records live at `renewals/<seq>`, so a rewritten Postgres cannot hide, drop or reorder a renewal, and the next
// sequence number is the first key that does not exist. Steps, in order: read the head, sign, time-stamp, write once.
//   - The authority is down: the handler throws, pg-boss retries with backoff; nothing was written.
//   - A crash before the write: the retry starts over. A crash after the write: the retry sees a record for this period
//     and does nothing, so no renewal is lost and none is doubled.
//   - Two workers at once: both aim at the same key; the store's write-once rule (`conflict`) lets one win.
// Source: https://www.rfc-editor.org/rfc/rfc4998#section-5 ; https://timgit.github.io/pg-boss/ (retryLimit, retryBackoff,
//   schedule with cron) ; https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html (the WORM store)
import type { ObjectStorePort, SignerPort, TsaPort } from '@legx/contracts/ports';
import type { Hex32 } from '@legx/contracts/values';
import type { Jobs } from '@legx/evidence/jobs';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  decodeRecord,
  encodeRecord,
  RENEWAL_CONTEXT,
  type RenewalRecord,
  renewalKey,
  renewalMsg,
  renewalStatement,
  timestampDigest,
} from './record.ts';

export const QUEUE_RENEWAL = 'legx.renewal';
export const RENEWAL_CRON = '0 3 * * *'; // daily at 03:00 UTC: the default; the period below decides what counts as "once"

/** Authority outages last hours or days: retry for a month, with backoff. */
export const RENEWAL_QUEUE_OPTIONS = {
  policy: 'short',
  retryLimit: 40,
  retryDelay: 30,
  retryBackoff: true,
  retryDelayMax: 3600,
  retentionSeconds: 30 * 86_400,
} as const;

export interface RenewalDeps {
  readonly objects: ObjectStorePort;
  readonly retainDays: number;
  /** The service's hybrid signer (the keyring's signer, so a rotated key is used from then on). */
  readonly signer: SignerPort;
  readonly tsa: Pick<TsaPort, 'timestamp'>;
  /** The evidence head: the latest checkpoint note (both lines), or `undefined` before the first checkpoint. */
  readonly head: () => Promise<string | undefined>;
}

export type RenewalOutcome =
  | { readonly status: 'renewed'; readonly seq: number; readonly statementHash: string }
  | { readonly status: 'already'; readonly seq: number }
  | { readonly status: 'raced' }
  | { readonly status: 'no_head' };

const ZERO_HEX = '0'.repeat(64);

export function createRenewal(deps: RenewalDeps) {
  const { objects } = deps;

  /** All records in order. The first missing key ends the chain (writes are in order, and each needs its predecessor). */
  async function load(): Promise<Uint8Array[]> {
    const out: Uint8Array[] = [];
    for (;;) {
      const bytes = await objects.get(renewalKey(out.length));
      if (!bytes) return out;
      out.push(bytes);
    }
  }

  return {
    load,

    /** One renewal for `period` (an opaque label, e.g. the UTC date): at most one record per period, ever. */
    async run(period: string): Promise<RenewalOutcome> {
      const note = await deps.head();
      if (note === undefined) return { status: 'no_head' };
      const stored = await load();
      const last = stored.length > 0 ? decodeRecord(stored[stored.length - 1] as Uint8Array) : undefined;
      if (last?.period === period) return { status: 'already', seq: last.seq };

      const prevHash = last ? Uint8Array.from(Buffer.from(last.statement_hash, 'hex')) : new Uint8Array(32);
      const prevToken = last ? new Uint8Array(Buffer.from(last.tsa.token, 'base64')) : undefined;
      const signed = await deps.signer.signHybrid(renewalMsg(prevHash, note), RENEWAL_CONTEXT);
      const statement = renewalStatement(prevHash, note, signed.mlDsa65);
      const stamp = await deps.tsa.timestamp(bytesToHex(timestampDigest(statement.hash, prevToken)) as Hex32);

      const record: RenewalRecord = {
        v: 1,
        seq: stored.length,
        period,
        prev_hash: last ? last.statement_hash : ZERO_HEX,
        checkpoint: note,
        statement_hash: bytesToHex(statement.hash),
        keys: { ed25519: signed.keyIds.ed25519, ml_dsa_65: signed.keyIds.mlDsa65 },
        sig: {
          ed25519: Buffer.from(signed.ed25519).toString('base64'),
          ml_dsa_65: Buffer.from(signed.mlDsa65).toString('base64'),
        },
        tsa: { authority: stamp.authority, token: Buffer.from(stamp.token).toString('base64') },
      };
      const put = await objects.put(renewalKey(record.seq), encodeRecord(record), deps.retainDays);
      // `conflict`: another worker wrote this sequence number first. Its record stands; ours is dropped.
      return put.status === 'conflict'
        ? { status: 'raced' }
        : { status: 'renewed', seq: record.seq, statementHash: record.statement_hash };
    },
  };
}

/** UTC calendar date: the default period for a daily schedule. */
export const dailyPeriod = (now: Date = new Date()): string => now.toISOString().slice(0, 10);

/** Registers the worker and the schedule. `periodOf` decides what "once" means (default: once per UTC day). */
export async function registerRenewalJob(
  jobs: Jobs,
  renewal: Pick<ReturnType<typeof createRenewal>, 'run'>,
  options: { readonly cron?: string; readonly periodOf?: () => string } = {},
): Promise<void> {
  const periodOf = options.periodOf ?? dailyPeriod;
  await jobs.work(QUEUE_RENEWAL, async () => {
    await renewal.run(periodOf());
  });
  await jobs.schedule(QUEUE_RENEWAL, options.cron ?? RENEWAL_CRON, {});
}
