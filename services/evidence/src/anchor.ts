// Module `anchor` (DESIGN 8.3, 8.4): publish a checkpoint on the ledger as a flagless `AccountSet` memo, and get
// RFC 3161 tokens for it from two independent authorities.
//   anchorNow       every 10 minutes (cron job) and at once on legal milestones (contract signed, lawyer approval,
//                   dispute opened): checkpoint, queue the time-stamp jobs, submit the memo, record the ledger index
//   handleTsa       one authority, one checkpoint; throws when the authority is down, so pg-boss retries it later
//   status          what the dashboard shows, including "time stamp pending"
// The ledger anchor never waits for an authority, and an authority never blocks the anchor.
// Source: https://xrpl.org/docs/references/protocol/transactions/types/accountset (flagless AccountSet with Memos)
// Source: https://www.rfc-editor.org/rfc/rfc3161 (the token covers SHA-256 of the signed checkpoint note)
import type { LedgerPort, ObjectStorePort, XrplJson } from '@legx/contracts/ports';
import type { Hex32, XrplHash } from '@legx/contracts/values';
import type { Database } from '@legx/db';
import { type BuildNetwork, buildAnchor } from '@legx/xrpl';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { type Jobs, QUEUE_ANCHOR, QUEUE_TSA } from './jobs.ts';
import { checkpointKey, type createLogService, putWorm } from './log.ts';
import { serial } from './serial.ts';
import type { Authority } from './tsa.ts';

const utf8 = new TextEncoder();
const MEMO_TYPE = bytesToHex(utf8.encode('legx/ckpt/v1')).toUpperCase();

/** The events after which a checkpoint is anchored at once (DESIGN 8.3). */
export const MILESTONE_KINDS: ReadonlySet<string> = new Set([
  'contract.lawyer_signed',
  'lawyer.approved',
  'dispute.opened',
]);
export const ANCHOR_CRON = '*/10 * * * *';
const MAX_SUBMIT_ATTEMPTS = 3;

export const tsaKey = (treeSize: number, root: string, authority: string) =>
  `tsa/${String(treeSize).padStart(16, '0')}-${root}/${authority}`;

export interface TsaSource {
  readonly authority: Authority;
  timestamp(sha256: Hex32): Promise<{ authority: string; token: Uint8Array }>;
}

export interface AnchorDeps {
  readonly db: Database;
  readonly logSvc: Pick<ReturnType<typeof createLogService>, 'checkpoint'>;
  readonly ledger: LedgerPort;
  /** Signs an autofilled transaction with the anchor account's key and returns the blob. The key is never ours to hold. */
  readonly signTx: (tx: XrplJson) => Promise<string>;
  readonly anchorAccount: string;
  readonly network: BuildNetwork;
  readonly baseFeeDrops?: number;
  readonly origin: string;
  readonly objects: ObjectStorePort;
  readonly retainDays: number;
  readonly jobs: Jobs;
  readonly tsa: readonly TsaSource[];
}

export interface AnchorResult {
  readonly status: 'anchored' | 'unchanged';
  readonly treeSize: number;
  readonly root: Hex32;
  readonly txHash: string;
  readonly ledgerIndex: number;
}

export interface AnchorStatus {
  readonly treeSize: number;
  readonly anchored: boolean;
  readonly anchorTxHash?: string;
  readonly anchorLedger?: number;
  /** "pending" is what the dashboard shows until the first authority has answered. */
  readonly timestamp: 'pending' | 'stamped';
  readonly stampedBy: readonly string[];
}

/** The 72-byte memo: SHA-256(origin) || tree size (8, big-endian) || root. Source: DESIGN 8.3 */
export function parseAnchorMemo(tx: XrplJson): { originHash: string; treeSize: number; root: string } | undefined {
  const memo = (tx.Memos as { Memo?: { MemoType?: string; MemoData?: string } }[] | undefined)?.[0]?.Memo;
  if (tx.TransactionType !== 'AccountSet' || memo?.MemoType !== MEMO_TYPE || memo.MemoData?.length !== 144)
    return undefined;
  const data = hexToBytes(memo.MemoData.toLowerCase());
  const size = new DataView(data.buffer, data.byteOffset + 32, 8).getBigUint64(0);
  return {
    originHash: bytesToHex(data.subarray(0, 32)),
    treeSize: Number(size),
    root: bytesToHex(data.subarray(40, 72)),
  };
}

export function createAnchorService(deps: AnchorDeps) {
  const { db, ledger, objects, jobs } = deps;
  const originHash = sha256(utf8.encode(deps.origin));

  async function submit(treeSize: number, root: Hex32): Promise<{ txHash: string; ledgerIndex: number }> {
    for (let attempt = 0; attempt < MAX_SUBMIT_ATTEMPTS; attempt++) {
      const tx = buildAnchor(
        { anchorAccount: deps.anchorAccount, originHash, treeSize: BigInt(treeSize), root: hexToBytes(root) },
        { network: deps.network, ...(deps.baseFeeDrops === undefined ? {} : { baseFeeDrops: deps.baseFeeDrops }) },
      );
      const blob = await deps.signTx(await ledger.autofill(tx as unknown as XrplJson, 0));
      const res = await ledger.submitReliable(blob);
      if (res.status === 'validated' && res.result === 'tesSUCCESS')
        return { txHash: res.hash, ledgerIndex: res.ledgerIndex };
      if (res.status === 'validated') throw new Error(`anchor transaction validated with ${res.result}`);
      if (res.status === 'rejected') throw new Error(`anchor transaction rejected: ${res.result}`);
      // expired: the sequence was not used; build, autofill and sign again
    }
    throw new Error('anchor transaction expired three times');
  }

  // One anchor at a time: two concurrent submits from the anchor account would fight over its sequence number.
  const exclusive = serial();
  const anchorNow = (): Promise<AnchorResult> => exclusive(anchorOnce);

  async function anchorOnce(): Promise<AnchorResult> {
    const { checkpoint } = await deps.logSvc.checkpoint();
    const latest = await db.repos.checkpointAnchors.latest();
    if (latest?.tree_size === checkpoint.treeSize && latest.anchor_tx_hash && latest.anchor_ledger !== null) {
      return {
        status: 'unchanged',
        treeSize: checkpoint.treeSize,
        root: checkpoint.rootHash,
        txHash: latest.anchor_tx_hash,
        ledgerIndex: latest.anchor_ledger,
      };
    }
    // Time stamps first: they take their own time and must not wait for, or fail with, the ledger.
    for (const t of deps.tsa) {
      await jobs.send(QUEUE_TSA, {
        treeSize: checkpoint.treeSize,
        root: checkpoint.rootHash,
        authority: t.authority.name,
      });
    }
    const { txHash, ledgerIndex } = await submit(checkpoint.treeSize, checkpoint.rootHash);
    await db.repos.checkpointAnchors.setAnchor(checkpoint.treeSize, {
      anchor_tx_hash: txHash,
      anchor_ledger: ledgerIndex,
    });
    return { status: 'anchored', treeSize: checkpoint.treeSize, root: checkpoint.rootHash, txHash, ledgerIndex };
  }

  async function handleTsa(job: { treeSize: number; root: Hex32; authority: string }): Promise<void> {
    const source = deps.tsa.find((t) => t.authority.name === job.authority);
    if (!source) throw new Error(`unknown time-stamp authority ${job.authority}`);
    const key = tsaKey(job.treeSize, job.root, job.authority);
    let token = await objects.get(key);
    if (!token) {
      // Tokens differ on every request (genTime, serial), so a second delivery must not ask again and then conflict.
      const note = await objects.get(checkpointKey(job.treeSize, job.root));
      if (!note) throw new Error('the checkpoint is not in the WORM store');
      token = (await source.timestamp(bytesToHex(sha256(note)) as Hex32)).token;
      await putWorm(objects, key, token, deps.retainDays);
    }
    // The first token to arrive is the one in `checkpoint_anchor`; whoever creates the `primary` marker owns it (a
    // conflict means another authority got there first). The marker is read back, so a crash between the marker and
    // the column is repaired by the retry.
    const marker = tsaKey(job.treeSize, job.root, 'primary');
    await objects.put(marker, utf8.encode(job.authority), deps.retainDays);
    const first = new TextDecoder().decode(await objects.get(marker));
    if (first === job.authority) await db.repos.checkpointAnchors.setAnchor(job.treeSize, { rfc3161_token: token });
  }

  return {
    anchorNow,
    handleTsa,

    /** Queue an immediate anchor when `kind` is a legal milestone. */
    async onEvent(kind: string): Promise<boolean> {
      if (!MILESTONE_KINDS.has(kind)) return false;
      await jobs.send(QUEUE_ANCHOR, { reason: kind });
      return true;
    },

    /** Wires the handlers and the 10-minute schedule into the job runner. */
    async start(): Promise<void> {
      await jobs.work<{ reason: string }>(QUEUE_ANCHOR, () => anchorNow().then(() => undefined));
      await jobs.work<{ treeSize: number; root: Hex32; authority: string }>(QUEUE_TSA, handleTsa);
      await jobs.schedule(QUEUE_ANCHOR, ANCHOR_CRON, { reason: 'schedule' });
    },

    async status(): Promise<AnchorStatus | undefined> {
      const row = await db.repos.checkpointAnchors.latest();
      if (!row) return undefined;
      const stampedBy: string[] = [];
      for (const t of deps.tsa) {
        if (await objects.get(tsaKey(row.tree_size, row.root, t.authority.name))) stampedBy.push(t.authority.name);
      }
      return {
        treeSize: row.tree_size,
        anchored: row.anchor_tx_hash !== null,
        ...(row.anchor_tx_hash ? { anchorTxHash: row.anchor_tx_hash } : {}),
        ...(row.anchor_ledger === null ? {} : { anchorLedger: row.anchor_ledger }),
        timestamp: stampedBy.length > 0 ? 'stamped' : 'pending',
        stampedBy,
      };
    },

    /** Reads the anchor transaction back from the ledger and compares its memo with the checkpoint we published. */
    async verifyAnchor(): Promise<'ok' | 'NOT_ANCHORED' | 'TX_MISSING' | 'MEMO_MISMATCH' | 'WRONG_ACCOUNT'> {
      const row = await db.repos.checkpointAnchors.latest();
      if (!row?.anchor_tx_hash) return 'NOT_ANCHORED';
      const found = await ledger.tx(row.anchor_tx_hash as XrplHash);
      if (!found) return 'TX_MISSING';
      if (found.tx.Account !== deps.anchorAccount) return 'WRONG_ACCOUNT';
      const memo = parseAnchorMemo(found.tx);
      const ok =
        memo && memo.originHash === bytesToHex(originHash) && memo.treeSize === row.tree_size && memo.root === row.root;
      return ok ? 'ok' : 'MEMO_MISMATCH';
    },
  };
}
