// Signature collection and exit submission (DESIGN 7.5). One request is one unsigned transaction; each of the four
// roles posts its own single-signer blob. Writes are keyed by (request, role): a retry returns the first result.
// The same four blobs always combine to the same transaction, so a crash at any point is repaired by running the
// last step again (`recoverDeal`): the ledger sees one transaction, and the evidence log one `exit.signed`.
// Source: https://xrpl.org/docs/concepts/accounts/multi-signing
// Source: https://xrpl.org/docs/concepts/transactions/reliable-transaction-submission
import type { SignatureRequest } from '@legx/contracts/api';
import type { LedgerPort } from '@legx/contracts/ports';
import type { Role } from '@legx/contracts/values';
import { type Deal, type Event as MachineEvent, QUORUM, transition } from '@legx/core/machine';
import { verifyMultisigned } from '@legx/core/verify';
import type { Repos } from '@legx/db';
import type { DealRow } from '@legx/db/repos/deals';
import type { SignatureRequestRow } from '@legx/db/repos/ops';
import { deliveredAmount } from '@legx/xrpl/read';
import { decode, encode, hashes, multisign } from 'xrpl';

const hashSignedTx = hashes.hashSignedTx;

import type { z } from 'zod';
import { loadConfig, requireDeal } from './deal.ts';
import type { CoordinatorDeps } from './deps.ts';
import { ApiError, conflict, forbidden, notFound, unprocessable } from './errors.ts';
import { lastOf, loadLog } from './log.ts';
import { derivePublicData } from './publicData.ts';
import { advanceSlot, buildUnsigned, COLLECTION_WINDOW, ExitNotSupported, isExit } from './slot.ts';
import { appendCoordinatorEvent, enqueueSignatureRequest } from './statements.ts';

export type SignatureRequestView = z.infer<typeof SignatureRequest>;
const ROLES: readonly Role[] = ['alice', 'lawyerA', 'bob', 'lawyerB'];

// One submit at a time per deal inside this process. Across processes the identical combined blob is the guard
// (Known gaps in 3.2.md: a row-level claim in the repository would close it for good).
const chains = new Map<string, Promise<unknown>>();
function serial<T>(dealId: string, fn: () => Promise<T>): Promise<T> {
  const run = (chains.get(dealId) ?? Promise.resolve()).then(fn, fn);
  chains.set(
    dealId,
    run.catch(() => undefined),
  );
  return run;
}

async function view(repos: Repos, r: SignatureRequestRow): Promise<SignatureRequestView> {
  const sigs = await repos.signatures.list(r.request_id);
  return {
    requestId: r.request_id,
    dealId: r.deal_id,
    purpose: r.purpose,
    unsignedTx: r.unsigned_tx as Record<string, unknown>,
    lastLedger: r.last_ledger,
    status: r.status,
    signedRoles: sigs.map((s) => s.role),
  } as SignatureRequestView;
}

/** Marks every open request whose LastLedgerSequence has passed (DESIGN 7.5 step 2). Returns the validated index. */
async function expireOld(deps: CoordinatorDeps, dealId: string): Promise<number> {
  const { ledgerIndex } = await deps.ledger.validatedLedger();
  for (const r of await deps.db.repos.signatureRequests.listOpen(dealId))
    if (ledgerIndex > r.last_ledger && (await deps.db.repos.signatures.list(r.request_id)).length < 4)
      await deps.db.repos.signatureRequests.setStatus(r.request_id, 'expired');
  return ledgerIndex;
}

export async function createRequest(
  deps: CoordinatorDeps,
  dealId: string,
  purpose: string,
): Promise<SignatureRequestView> {
  await recoverDeal(deps, dealId);
  const validated = await expireOld(deps, dealId);
  const repos = deps.db.repos;
  const deal = await requireDeal(repos, dealId);
  // A retry returns the open request of the same purpose.
  const open = (await repos.signatureRequests.listOpen(dealId)).find((r) => r.purpose === purpose);
  if (open) return await view(repos, open);
  let unsigned: Record<string, unknown>;
  try {
    unsigned = await buildUnsigned(deps, deal, purpose);
  } catch (e) {
    if (e instanceof ExitNotSupported) throw new ApiError(501, 'not_implemented', e.message);
    throw e;
  }
  const lastLedger = validated + COLLECTION_WINDOW;
  const filled = await deps.ledger.autofill({ ...unsigned, LastLedgerSequence: lastLedger }, 4);
  // The request and its feed row are stored together (I-W-5).
  const row = await deps.db.transaction(async (tx) => {
    const created = await tx.signatureRequests.insert({
      deal_id: dealId,
      purpose,
      unsigned_tx: { ...filled, LastLedgerSequence: lastLedger },
      last_ledger: lastLedger,
    });
    await enqueueSignatureRequest(tx, {
      dealId,
      requestId: created.request_id,
      purpose,
      lastLedger,
      status: created.status,
    });
    return created;
  });
  return await view(repos, row);
}

export async function listRequests(deps: CoordinatorDeps, dealId: string): Promise<SignatureRequestView[]> {
  await requireDeal(deps.db.repos, dealId);
  await recoverDeal(deps, dealId);
  await expireOld(deps, dealId);
  // Open requests only: the repository cannot list closed ones yet (Request to 3.1 in 3.2.md).
  const all = await deps.db.repos.signatureRequests.listOpen(dealId);
  return await Promise.all(all.map((r) => view(deps.db.repos, r)));
}

/** The decoded blob without its Signers, for comparison with the request's unsigned transaction. */
function bodyOf(tx: Record<string, unknown>): string {
  const { Signers: _s, ...rest } = tx;
  return JSON.stringify(sortKeys({ ...rest, SigningPubKey: '' }));
}
const sortKeys = (v: unknown): unknown =>
  Array.isArray(v)
    ? v.map(sortKeys)
    : v !== null && typeof v === 'object'
      ? Object.fromEntries(
          Object.entries(v as object)
            .sort(([a], [b]) => (a < b ? -1 : 1))
            .map(([k, x]) => [k, sortKeys(x)]),
        )
      : v;

export interface SubmitOutcome {
  status: 'accepted' | 'duplicate';
  signedRoles: Role[];
  submitted: boolean;
}

export async function submitSignature(
  deps: CoordinatorDeps,
  caller: Role,
  input: { dealId: string; requestId: string; role: Role; signerBlob: string },
): Promise<SubmitOutcome> {
  if (input.role !== caller) throw forbidden('role_mismatch', 'a role signs only for itself');
  return await serial(input.dealId, async () => {
    const repos = deps.db.repos;
    const req = await repos.signatureRequests.get(input.requestId);
    if (!req || req.deal_id !== input.dealId) throw notFound('no such signature request');
    const existing = await repos.signatures.list(req.request_id);
    if (existing.some((s) => s.role === input.role)) {
      // A retry may be what finishes a request whose process was killed after the fourth blob was stored.
      const submitted = existing.length === 4 && req.status === 'open' ? await completeIfReady(deps, req) : false;
      return { status: 'duplicate', signedRoles: existing.map((s) => s.role) as Role[], submitted };
    }
    await expireOld(deps, input.dealId);
    const fresh = (await repos.signatureRequests.get(req.request_id)) as SignatureRequestRow;
    if (fresh.status === 'expired') throw conflict('request_expired', 'this request expired; ask for a new one');
    if (fresh.status !== 'open') throw conflict('request_closed', `this request is ${fresh.status}`);

    const account = await signerAccount(deps, input.dealId, input.role);
    let decoded: Record<string, unknown>;
    try {
      decoded = decode(input.signerBlob) as Record<string, unknown>;
    } catch {
      throw unprocessable('bad_signer_blob', 'the blob does not decode');
    }
    // A blob that signs a different transaction (changed amount, destination, fee...) is refused; the others stay valid.
    if (bodyOf(decoded) !== bodyOf(decode(encode(req.unsigned_tx as never)) as Record<string, unknown>))
      throw unprocessable('blob_differs', 'the blob signs a different transaction');
    if (!verifyMultisigned(input.signerBlob, [account]).ok)
      throw unprocessable('bad_signer_blob', `the blob is not a valid signature by ${account}`);

    await repos.signatures.insert({ request_id: req.request_id, role: input.role, signer_blob: input.signerBlob });
    await deps.crash?.('sig.afterInsert');
    const signed = (await repos.signatures.list(req.request_id)).map((s) => s.role) as Role[];
    const submitted = signed.length === 4 ? await completeIfReady(deps, req) : false;
    return { status: 'accepted', signedRoles: signed, submitted };
  });
}

async function signerAccount(deps: CoordinatorDeps, dealId: string, role: Role): Promise<string> {
  const deal = await requireDeal(deps.db.repos, dealId);
  const pd = await derivePublicData(deps.db.repos, deal, (await loadConfig(deps.db.repos, dealId)).identity_policy);
  const accounts = await signerAccounts(deps, dealId, deal, pd);
  return accounts[role];
}

type Pd = Awaited<ReturnType<typeof derivePublicData>>;
async function signerAccounts(
  _deps: CoordinatorDeps,
  _dealId: string,
  _deal: DealRow,
  pd: Pd,
): Promise<Record<Role, string>> {
  if (pd.status !== 'complete') throw unprocessable('public_data_incomplete', 'the deal public data is not complete');
  const [alice, lawyerA, bob, lawyerB] = pd.publicData.signerAccounts as unknown as string[];
  return { alice: alice as string, lawyerA: lawyerA as string, bob: bob as string, lawyerB: lawyerB as string };
}

/** Four blobs are in: combine, record `exit.signed` once, submit, finish. Safe to run again after a crash. */
async function completeIfReady(deps: CoordinatorDeps, req: SignatureRequestRow): Promise<boolean> {
  const repos = deps.db.repos;
  const sigs = await repos.signatures.list(req.request_id);
  if (sigs.length < 4) return false;
  const deal = await requireDeal(repos, req.deal_id);
  const pd = await derivePublicData(repos, deal, (await loadConfig(repos, req.deal_id)).identity_policy);
  const accounts = await signerAccounts(deps, req.deal_id, deal, pd);
  const blob = multisign(sigs.map((s) => s.signer_blob));
  if (
    !verifyMultisigned(
      blob,
      ROLES.map((r) => accounts[r]),
    ).ok
  )
    throw unprocessable('bad_combined', 'the combined transaction does not verify against the four signer accounts');

  const header = await deps.ledger.validatedLedger();
  if (isExit(req.purpose)) {
    const log = await loadLog(repos, req.deal_id);
    if (!lastOf(log, 'exit.signed', (d) => d.request_id === req.request_id))
      await deps.db.transaction((tx) =>
        appendCoordinatorEvent(tx, deps.signer, {
          dealId: req.deal_id,
          kind: 'exit.signed',
          data: {
            purpose: req.purpose,
            request_id: req.request_id,
            exit_slot: deal.exit_slot,
            destination: req.purpose === 'pay_bob' ? deal.payout_b : deal.payout_a,
          },
          contractRoot: deal.contract_root,
          closeTime: header.closeTime,
          beforeAppend: async () => deal.state,
        }),
      );
  }
  // After a crash the combined blob may already be validated: read its result instead of sending it again.
  const known = await deps.ledger.tx(hashSignedTx(blob) as never);
  let result: Result;
  if (known) {
    result = {
      status: 'validated',
      result: String(known.meta.TransactionResult),
      hash: known.hash,
      ledgerIndex: known.ledgerIndex,
      meta: known.meta,
    };
  } else {
    await deps.crash?.('submit.before');
    result = await deps.ledger.submitReliable(blob);
    await deps.crash?.('submit.after');
  }
  await finalize(deps, req, result);
  return true;
}

type Result = Awaited<ReturnType<LedgerPort['submitReliable']>>;

async function finalize(deps: CoordinatorDeps, req: SignatureRequestRow, result: Result) {
  const header = await deps.ledger.validatedLedger();
  await deps.db.transaction(async (tx) => {
    const current = (await tx.signatureRequests.get(req.request_id)) as SignatureRequestRow;
    if (current.status !== 'open') return; // finished before the crash
    const deal = await requireDeal(tx, req.deal_id);
    if (result.status === 'expired') return await tx.signatureRequests.setStatus(req.request_id, 'expired');
    if (result.status === 'rejected') return await tx.signatureRequests.setStatus(req.request_id, 'void');
    await tx.ledgerObservations.insert({
      tx_hash: result.hash,
      ledger_index: result.ledgerIndex,
      tx_index: Number(result.meta.TransactionIndex ?? 0),
      account: deal.shell_address as string,
      tx_type: isExit(req.purpose) ? 'Payment' : 'AccountDelete',
      result: result.result,
      meta: result.meta,
    });
    if (result.result !== 'tesSUCCESS') {
      // A tec used the sequence without moving money: both candidates void, S+1 recorded (DESIGN 7.5, P3.2-08).
      await tx.signatureRequests.setStatus(req.request_id, 'void');
      if (isExit(req.purpose)) await advanceSlot(tx, deal);
      return;
    }
    const sigs = QUORUM; // all four signed: verifyMultisigned checked the combined blob against the four accounts
    const destination = req.purpose === 'pay_bob' ? deal.payout_b : deal.payout_a;
    let event: MachineEvent;
    let kind: 'exit.validated' | 'wallet.closed';
    let data: Record<string, unknown>;
    if (isExit(req.purpose)) {
      const delivered = deliveredAmount(result.meta);
      if (delivered !== deal.amount_drops)
        throw unprocessable('delivered_mismatch', 'delivered_amount differs from the agreed amount');
      kind = 'exit.validated';
      data = { purpose: req.purpose, tx_hash: result.hash, destination, delivered_drops: delivered };
      event =
        deal.state === 'DISPUTED'
          ? { t: 'AWARD', to: req.purpose === 'pay_bob' ? 'BOB' : 'ALICE', sigs }
          : req.purpose === 'pay_bob'
            ? { t: 'PAY_BOB', sigs }
            : { t: 'REFUND_ALICE', sigs };
    } else {
      kind = 'wallet.closed';
      data = { tx_hash: result.hash, destination: deal.payout_a.split(':')[0] };
      event = { t: 'CLOSE', sigs };
    }
    const t = transition({ state: deal.state, wasLocked: deal.was_locked } as Deal, event);
    if (!t.ok) throw unprocessable(`refused_${t.refusal}`, t.message);
    await appendCoordinatorEvent(tx, deps.signer, {
      dealId: req.deal_id,
      kind,
      data,
      contractRoot: deal.contract_root,
      closeTime: header.closeTime,
      ledger: { tx_hash: result.hash, ledger_index: result.ledgerIndex },
      beforeAppend: async () => {
        await tx.deals.update(req.deal_id, { state: t.deal.state, was_locked: t.deal.wasLocked });
        await deps.crash?.('finalize.afterState');
        return t.deal.state;
      },
    });
    await tx.signatureRequests.setStatus(req.request_id, 'complete');
    // The other candidate lost the race for slot S: it can never apply (tefPAST_SEQ).
    if (isExit(req.purpose))
      for (const r of await tx.signatureRequests.listOpen(req.deal_id))
        if (isExit(r.purpose)) await tx.signatureRequests.setStatus(r.request_id, 'void');
  });
}

/** Finishes any request that has all four signatures but no recorded result: the repair after a kill (P3.2-10). */
export async function recoverDeal(deps: CoordinatorDeps, dealId: string): Promise<void> {
  await serial(dealId, async () => {
    for (const r of await deps.db.repos.signatureRequests.listOpen(dealId)) await completeIfReady(deps, r);
  });
}
