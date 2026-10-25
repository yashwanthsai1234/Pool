// Firm and service enrollment keys (DESIGN 6.3): a signed list at a well-known address, anchored on the ledger by a memo
// from the firm's operations account (which holds the LEGX_ATTORNEY credential). Clients check every key they are shown
// against the anchor.
import { createServer, type Server } from 'node:http';
import type { LedgerPort, SignerPort } from '@legx/contracts/ports';
import { XrplAddress, XrplHash } from '@legx/contracts/values';
import type { BarTrust } from '@legx/core/bar';
import type { Envelope } from '@legx/core/evidence';
import { type BuildCtx, hexOfText, hexUp, memo } from '@legx/xrpl/builders/common';
import { sha256 } from '@noble/hashes/sha2.js';
import type { AccountSet } from 'xrpl';
import { z } from 'zod';
import type { AccountSigner } from './service.ts';
import { signAttestation } from './signing.ts';

export const ENROLLMENT_LIST_TYPE = 'legx/enrollment-list/v1';
export const ENROLLMENT_LIST_PATH = '/.well-known/legx/enrollment-keys.json';

const Key = z.strictObject({
  key_id: z.string().min(1).max(128),
  alg: z.enum(['ed25519', 'ml-dsa-65']),
  public_key: z.string().regex(/^[0-9a-f]+$/),
  valid_from: z.int().min(0),
});
export const EnrollmentList = z.strictObject({
  type: z.literal(ENROLLMENT_LIST_TYPE),
  issuer_account: XrplAddress,
  seq: z.int().min(1),
  keys: z.array(Key).min(1).max(256),
  sig_algs: z.tuple([z.literal('ed25519'), z.literal('ml-dsa-65')]),
});
export type EnrollmentListRecord = z.infer<typeof EnrollmentList>;

/** The anchor: an AccountSet from the firm's account whose memo carries SHA-256 of the signed list bytes. */
export function buildEnrollmentAnchor(i: { account: string; listSha256: Uint8Array }, ctx: BuildCtx): AccountSet {
  if (i.listSha256.length !== 32) throw new Error('listSha256 must be 32 bytes');
  return {
    TransactionType: 'AccountSet',
    Account: i.account,
    Memos: [memo(ENROLLMENT_LIST_TYPE, hexUp(i.listSha256))],
    Fee: String(ctx.baseFeeDrops ?? 10),
  };
}

/** Signs the list (the firm's hybrid keys) and anchors its hash from the firm's operations account. */
export async function publishEnrollmentList(i: {
  readonly list: Omit<z.input<typeof EnrollmentList>, 'type' | 'sig_algs'>;
  readonly signer: SignerPort;
  readonly ledger: LedgerPort;
  readonly account: AccountSigner;
}): Promise<{ readonly bytes: Uint8Array; readonly anchorTxHash: string }> {
  const payload = EnrollmentList.parse({ ...i.list, type: ENROLLMENT_LIST_TYPE, sig_algs: ['ed25519', 'ml-dsa-65'] });
  const signed = await signAttestation(i.signer, payload);
  const fees = await i.ledger.fees();
  const tx = buildEnrollmentAnchor(
    { account: payload.issuer_account, listSha256: sha256(signed.bytes) },
    { network: i.ledger.network as never, baseFeeDrops: Number(fees.baseFee) },
  );
  const r = await i.ledger.submitReliable(await i.account.sign(await i.ledger.autofill(tx as never, 0)));
  if (r.status !== 'validated' || r.result !== 'tesSUCCESS')
    throw new Error(`enrollment anchor: ${r.status === 'validated' ? r.result : r.status}`);
  return { bytes: signed.bytes, anchorTxHash: r.hash };
}

export type ListCheck =
  | { readonly ok: true; readonly list: EnrollmentListRecord }
  | {
      readonly ok: false;
      readonly code: 'BAD_SIGNATURE' | 'MALFORMED' | 'ANCHOR_MISSING' | 'ANCHOR_MISMATCH' | 'WRONG_ACCOUNT';
    };

/** What a client does with a list it downloaded: signature, then the ledger memo from the same account. */
export async function checkEnrollmentList(i: {
  readonly bytes: Uint8Array;
  readonly trust: BarTrust;
  readonly ledger: LedgerPort;
  readonly anchorTxHash: string;
}): Promise<ListCheck> {
  let env: Envelope;
  try {
    env = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(i.bytes));
  } catch {
    return { ok: false, code: 'MALFORMED' };
  }
  const v = i.trust.verify(env);
  if (!v.ok) return { ok: false, code: 'BAD_SIGNATURE' };
  let list: EnrollmentListRecord;
  try {
    list = EnrollmentList.parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(v.payload)));
  } catch {
    return { ok: false, code: 'MALFORMED' };
  }
  const tx = await i.ledger.tx(XrplHash.parse(i.anchorTxHash));
  if (!tx) return { ok: false, code: 'ANCHOR_MISSING' };
  if (tx.tx.Account !== list.issuer_account) return { ok: false, code: 'WRONG_ACCOUNT' };
  const memos = (tx.tx.Memos ?? []) as readonly { Memo?: { MemoType?: string; MemoData?: string } }[];
  const want = hexUp(sha256(i.bytes));
  const ok = memos.some((m) => m.Memo?.MemoType === hexOfText(ENROLLMENT_LIST_TYPE) && m.Memo?.MemoData === want);
  return ok ? { ok: true, list } : { ok: false, code: 'ANCHOR_MISMATCH' };
}

/** Serves the signed list at the well-known path. HTTPS is terminated in front of it. */
export function serveEnrollmentList(getBytes: () => Uint8Array, port: number): Promise<Server> {
  const server = createServer((req, res) => {
    if (req.method !== 'GET' || req.url !== ENROLLMENT_LIST_PATH) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(getBytes());
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve(server)));
}
