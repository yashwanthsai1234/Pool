// events.append: a party posts a hybrid-signed evidence event. The coordinator verifies it, checks what the ledger
// can confirm, applies the state transition through the pure machine, and stores state, evidence event and outbox row
// in ONE transaction (P3.2-03). A retry with the same bytes returns the first result (idempotent by leaf hash).
// The lock check and the release gate are run here, by the coordinator, before it stores or relays anything
// (P3.2-11, DESIGN 10.2).
import { type EventPredicate, LegxEvent } from '@legx/contracts/events';
import type { LedgerPort, ValidatedTx } from '@legx/contracts/ports';
import { HybridEnvelope } from '@legx/contracts/records';
import type { Role } from '@legx/contracts/values';
import { bytesToHex, hexToBytes, sha256 } from '@legx/core/dealcore';
import { verifyHybrid } from '@legx/core/hybridEnvelope';
import { allOk, blocking, checkLock } from '@legx/core/lockcheck';
import { type Deal, type Event as MachineEvent, type State, transition } from '@legx/core/machine';
import { fromBase64Strict } from '@legx/core/pq';
import { SHIP_LEDGER_MAX_AGE, verifyReceipt, verifyShipment } from '@legx/core/shipment';
import type { EvidenceEventRow, Repos } from '@legx/db';
import type { DealRow } from '@legx/db/repos/deals';
import type { z } from 'zod';
import { isPrimaryHolder } from './auth.ts';
import { loadConfig, requireDeal } from './deal.ts';
import type { CoordinatorDeps, ReleaseGateRecord } from './deps.ts';
import { badRequest, conflict, forbidden, unprocessable } from './errors.ts';
import { pairIdOf, ROLE_OF_SLOT, registryOf } from './keys.ts';
import { type LoggedEvent, lastOf, loadLog } from './log.ts';
import { derivePublicData, type PublicDataResult } from './publicData.ts';
import { enqueueStored } from './statements.ts';

export type AppendResult =
  | { status: 'stored'; seq: number; leafHash: string; state: State }
  | { status: 'seq_taken'; head: { nextSeq: number; prevHash: string } };

const ZERO = '00'.repeat(32);
const ALL: Role[] = ['alice', 'lawyerA', 'bob', 'lawyerB'];
const SLOT_ROLES = (slot: unknown): Role[] =>
  typeof slot === 'string' && slot in ROLE_OF_SLOT ? [ROLE_OF_SLOT[slot as keyof typeof ROLE_OF_SLOT]] : [];
const SIDE_LAWYER = (side: unknown): Role[] => (side === 'A' ? ['lawyerA'] : side === 'B' ? ['lawyerB'] : []);

/**
 * Who may post each kind, from DESIGN 8.1. Kinds that only another service or the coordinator itself writes are
 * absent: a party that posts one is refused (403), so no party can forge a verifier, watcher or coordinator record.
 */
const ACTORS: Readonly<Record<string, (data: Record<string, unknown>) => Role[]>> = {
  'contract.lawyer_signed': (d) => SLOT_ROLES(d.role),
  'nft.minted': () => ['lawyerA'],
  'shell.opened': () => ['alice'],
  'escrow.created': () => ['alice'],
  'key.bound': (d) => SLOT_ROLES(d.slot),
  'ops.bound': (d) => SLOT_ROLES(d.role),
  'wallet.locked': () => ['alice'],
  'lock.verified': () => ['lawyerB'],
  'lawyer.approved': (d) => SLOT_ROLES(d.role),
  'passport.verified': (d) => SIDE_LAWYER(d.side),
  // OD-37: Bob signs the shipment (slot B), Alice the receipt (slot A); only a primary holder posts them (I-S-A1).
  'shipment.signed': () => ['bob'],
  'receipt.signed': () => ['alice'],
  'release.gate.passed': () => ['lawyerB'],
  'release.performed': () => ['lawyerB'],
  'frost.dkg.completed': (d) => SLOT_ROLES(d.slot),
  'frost.signed': (d) => SLOT_ROLES(d.slot),
  'frost.refreshed': (d) => SLOT_ROLES(d.slot),
  'identity.onboarded': (d) => SIDE_LAWYER(d.side),
  'pq.bound': (d) => SLOT_ROLES((d.binding as { slot?: unknown } | undefined)?.slot),
  // OD-28: the old lawyer B hands the release code over; the X-Wing box stays an attachment, only its hash is logged.
  'release_code.handed_over': () => ['lawyerB'],
  'dispute.opened': () => ALL,
  'award.recorded': () => ALL,
  'escrow.cancelled': () => ALL,
  'wallet.closed': () => ALL,
};

/** Reads the newest chain position of a deal. Request to 3.1 in 3.2.md: a `head` call on the repository. */
export async function headOf(repos: Repos, dealId: string): Promise<{ nextSeq: number; prevHash: string }> {
  let last: EvidenceEventRow | undefined;
  for (let after = -1; ; ) {
    const page = await repos.evidenceEvents.listAfter(dealId, after, 1000);
    if (page.length === 0) break;
    last = page.at(-1);
    after = (last as EvidenceEventRow).seq;
  }
  return last ? { nextSeq: last.seq + 1, prevHash: last.leaf_hash } : { nextSeq: 0, prevHash: ZERO };
}

class SeqMismatch extends Error {}

/** A validated, successful transaction of the expected type, or a 422. Source: DESIGN 7.5 step 5 (only validated ledgers count). */
export async function requireTx(ledger: LedgerPort, hash: string, type?: string): Promise<ValidatedTx> {
  const t = await ledger.tx(hash as never);
  if (!t) throw unprocessable('ledger_tx_not_validated', `transaction ${hash} is not in a validated ledger`);
  if (type !== undefined && t.tx.TransactionType !== type)
    throw unprocessable('ledger_tx_wrong_type', `transaction ${hash} is not ${type}`);
  if (t.meta.TransactionResult !== 'tesSUCCESS')
    throw unprocessable('ledger_tx_failed', `transaction ${hash} result is ${String(t.meta.TransactionResult)}`);
  return t;
}

/** Setup events feed the deal seal, so they are accepted only before it is fixed (DESIGN 5.1, 6.6; I-S-M4). */
const SETUP_STATES = ['DRAFT', 'CONTRACT_SIGNED', 'SHELL_OPEN', 'QUARANTINED'] as const;
const SETUP_KINDS: ReadonlySet<string> = new Set([
  'key.bound',
  'identity.onboarded',
  'ops.bound',
  'frost.dkg.completed',
]);

/**
 * The validated transaction names THIS deal's escrow: Owner and OfferSequence identify an escrow (I-S-M1, I-S-M3).
 * Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowfinish
 */
function requireOurEscrow(t: ValidatedTx, deal: DealRow): void {
  if (
    deal.escrow_owner === null ||
    deal.escrow_sequence === null ||
    t.tx.Owner !== deal.escrow_owner ||
    t.tx.OfferSequence !== deal.escrow_sequence
  )
    throw unprocessable('escrow_mismatch', 'the transaction names another escrow');
}

/** What one kind needs from outside the database, read before the transaction so no lock is held during network calls. */
interface Plan {
  /** Extra state to write, and the machine event to apply, decided inside the lock from the locked deal row. */
  machine?: (deal: DealRow, log: readonly LoggedEvent[], pd: PublicDataResult | undefined) => MachineEvent | undefined;
  patch?: (deal: DealRow) => Partial<DealRow>;
  /** Writes beyond the deal row, in the same transaction. */
  after?: (repos: Repos, row: EvidenceEventRow) => Promise<void>;
  /** Allowed deal states, checked in the lock. */
  states?: readonly string[];
  needsPublicData?: boolean;
}

async function lockCheck(
  deps: CoordinatorDeps,
  deal: DealRow,
  pd: Extract<PublicDataResult, { status: 'complete' }>,
  d: Record<string, unknown>,
) {
  const anchor = d.ledger as { ledger_index: number; ledger_hash: string };
  const shell = deal.shell_address as string;
  const snap = await deps.ledger.snapshot([shell as never], anchor.ledger_index);
  if (snap.ledger.ledgerHash !== anchor.ledger_hash)
    throw unprocessable('ledger_mismatch', 'ledger hash differs from the anchor');
  const acct = snap.accounts[shell];
  if (
    !acct ||
    deal.escrow_owner === null ||
    deal.escrow_sequence === null ||
    deal.condition_hex === null ||
    deal.cancel_after === null
  )
    throw unprocessable('lock_check_failed', 'the wallet or the escrow is not recorded');
  const [alice, , bob] = pd.publicData.signerAccounts as unknown as [string, string, string, string];
  const findings = checkLock(acct.accountData as never, [...acct.objects] as never, {
    deal: pd.publicData,
    releaserAccount: pd.publicData.releaserAccount,
    credentialSubjects: [alice, bob],
    escrow: {
      owner: deal.escrow_owner,
      sequence: deal.escrow_sequence,
      amountDrops: deal.amount_drops,
      conditionHex: deal.condition_hex,
      minCancelAfter: snap.ledger.closeTime + 86_400,
    },
  });
  if (!allOk(findings))
    throw unprocessable(
      'lock_check_failed',
      `blocking findings: ${blocking(findings)
        .map((f) => f.code)
        .join(', ')}`,
    );
}

/** The deal, its seal and one sealed slot key, for the shipment and receipt verifiers (OD-37). */
function dealContext(dealId: string, p: PublicDataResult | undefined, slot: 'A' | 'B', atLedger: number) {
  if (p?.status !== 'complete') throw unprocessable('public_data_incomplete', 'the deal seal cannot be computed yet');
  return {
    dealId,
    dealSeal: hexToBytes(p.dealSeal),
    slotPub: hexToBytes(slot === 'A' ? p.publicData.xPubA : p.publicData.xPubB),
    atLedger,
  };
}

async function planFor(
  deps: CoordinatorDeps,
  kind: string,
  d: Record<string, unknown>,
  deal: DealRow,
  pd: PublicDataResult,
  leafHash: string,
): Promise<Plan> {
  const complete = pd.status === 'complete' ? pd : undefined;
  const needPd = (): Extract<PublicDataResult, { status: 'complete' }> => {
    if (!complete) throw unprocessable('public_data_incomplete', 'the deal public data is not complete yet');
    return complete;
  };
  switch (kind) {
    case 'contract.lawyer_signed':
      if (d.contract_root !== deal.contract_root || d.wallet_address !== deal.shell_address)
        throw unprocessable('contract_mismatch', 'contract root or wallet address differ from the deal');
      return { states: ['DRAFT'] };
    case 'nft.minted': {
      const t = await requireTx(deps.ledger, d.mint_tx_hash as string, 'NFTokenMint');
      if (t.tx.Account !== deal.lawyer_ops_a || d.minter !== deal.lawyer_ops_a)
        throw unprocessable('mint_wrong_account', 'the NFT must be minted by operations account A');
      return {
        states: ['DRAFT'],
        machine: (_, log) =>
          lastOf(log, 'contract.lawyer_signed', (x) => x.role === 'LA') &&
          lastOf(log, 'contract.lawyer_signed', (x) => x.role === 'LB')
            ? { t: 'SIGN_CONTRACT' }
            : undefined,
        patch: () => ({
          nft_token_id: d.nftoken_id as string,
          mint_tx_hash: d.mint_tx_hash as string,
          signed_contract_seal: d.signed_contract_seal as string,
        }),
      };
    }
    case 'shell.opened': {
      await requireTx(deps.ledger, d.funding_tx_hash as string, 'Payment');
      if (d.wallet_address !== deal.shell_address)
        throw unprocessable('wallet_mismatch', 'wallet address differs from the deal');
      return { machine: () => ({ t: 'OPEN_SHELL' }) };
    }
    case 'escrow.created': {
      const e = d.escrow as {
        owner: string;
        offer_sequence: number;
        amount_drops: string;
        condition: string;
        cancel_after: number;
      };
      const t = await requireTx(deps.ledger, d.tx_hash as string, 'EscrowCreate');
      // Every recorded field comes from the validated transaction, never from the claim alone (I-S-M2).
      // Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowcreate (a ticketed create has
      // Sequence 0; the escrow's OfferSequence is then its TicketSequence)
      const seq = t.tx.Sequence === 0 ? t.tx.TicketSequence : t.tx.Sequence;
      if (
        t.tx.Account !== e.owner ||
        t.tx.Destination !== deal.shell_address ||
        t.tx.Amount !== deal.amount_drops ||
        e.amount_drops !== deal.amount_drops ||
        String(t.tx.Condition ?? '').toUpperCase() !== e.condition ||
        t.tx.CancelAfter !== e.cancel_after ||
        seq !== e.offer_sequence
      )
        throw unprocessable('escrow_mismatch', 'the escrow does not match the deal or its validated transaction');
      return {
        machine: () => ({ t: 'FUND_QUARANTINE' }),
        patch: () => ({
          escrow_owner: e.owner,
          escrow_sequence: e.offer_sequence,
          condition_hex: e.condition,
          cancel_after: e.cancel_after,
        }),
      };
    }
    case 'pq.bound':
      return {
        needsPublicData: true,
        machine: (_, log, p) => {
          if (p?.status !== 'complete')
            throw unprocessable('public_data_incomplete', 'the deal seal cannot be computed yet');
          const binding = d.binding as { deal_seal: string };
          if (binding.deal_seal !== p.dealSeal)
            throw unprocessable('seal_mismatch', 'the binding names a different deal seal');
          const bound = new Set(
            log.filter((e) => e.kind === 'pq.bound').map((e) => (e.data.binding as { slot: string }).slot),
          );
          bound.add((d.binding as { slot: string }).slot);
          return bound.size === 4 ? { t: 'KEYS_MADE' } : undefined;
        },
        patch: () => (complete ? { deal_seal: complete.dealSeal } : {}),
      };
    case 'wallet.locked': {
      const pdc = needPd();
      if (d.domain !== pdc.domain) throw unprocessable('domain_mismatch', 'Domain differs from 01 + root + seal');
      for (const h of d.tx_hashes as string[]) await requireTx(deps.ledger, h);
      return { machine: () => ({ t: 'LOCK_WALLET' }) };
    }
    case 'lock.verified': {
      await lockCheck(deps, deal, needPd(), d);
      return { machine: () => ({ t: 'VERIFY_OK' }) };
    }
    case 'shipment.signed': {
      const latest = (await deps.ledger.validatedLedger()).ledgerIndex;
      return {
        states: ['VERIFIED'],
        needsPublicData: true,
        machine: (_, __, p) => {
          const ctx = dealContext(deal.deal_id, p, 'B', latest);
          // Source: build/SHIP_RECEIPT.md 2 (the ledger index is at most 20 ledgers old)
          const r = verifyShipment(d, { ...ctx, maxAge: SHIP_LEDGER_MAX_AGE });
          if (!r.ok) throw unprocessable(`shipment_${r.code.toLowerCase()}`, `shipment refused: ${r.code}`);
          return { t: 'SHIP_SIGNED' };
        },
      };
    }
    case 'receipt.signed': {
      const latest = (await deps.ledger.validatedLedger()).ledgerIndex;
      return {
        states: ['SHIPPED'],
        needsPublicData: true,
        machine: (_, log, p) => {
          const shipped = lastOf(log, 'shipment.signed');
          const sctx = dealContext(deal.deal_id, p, 'B', latest);
          const s = shipped && verifyShipment(shipped.data, sctx);
          if (!s?.ok) throw unprocessable('shipment_missing', 'no valid shipment is logged for this deal');
          const r = verifyReceipt(d, { ...dealContext(deal.deal_id, p, 'A', latest), shipment: s });
          if (!r.ok) throw unprocessable(`receipt_${r.code.toLowerCase()}`, `receipt refused: ${r.code}`);
          return { t: 'RECEIPT_SIGNED', condition: r.condition };
        },
      };
    }
    case 'release.gate.passed': {
      const claim = d.gate as ReleaseGateRecord;
      const r = await deps.gate.run({
        dealId: deal.deal_id,
        publicData: needPd().publicData,
        claim,
        ledger: deps.ledger,
      });
      if (!r.ok) throw unprocessable('GATE_FAILED', `release gate failed: ${r.failed.join(', ')}`);
      if (claim.deal_seal !== needPd().dealSeal)
        throw unprocessable('seal_mismatch', 'the gate record names a different deal seal');
      return {
        states: ['RECEIVED'],
        after: async (repos, row) => {
          await repos.releaseGates.insert({
            deal_id: deal.deal_id,
            leaf_hash: leafHash,
            envelope: row.envelope,
            ledger_index: claim.ledger.ledger_index,
          });
        },
      };
    }
    case 'release.performed': {
      const t = await requireTx(deps.ledger, d.finish_tx_hash as string, 'EscrowFinish');
      requireOurEscrow(t, deal);
      if (t.ledgerIndex !== d.ledger_index)
        throw unprocessable('ledger_mismatch', 'ledger index differs from the transaction');
      const shell = deal.shell_address as string;
      const snap = await deps.ledger.snapshot([shell as never]);
      const slotS = Number(snap.accounts[shell]?.accountData.Sequence);
      return {
        states: ['RECEIVED'],
        // Slot S: the wallet's next Sequence at funding (DESIGN 7.5, D9).
        patch: () => ({ exit_slot: slotS }),
        machine: (dl, log) => ({
          t: 'RELEASE_ESCROW',
          gatePassed: log.some((e) => e.kind === 'release.gate.passed' && e.leafHash === d.gate_leaf_hash),
          submitter: String(t.tx.Account),
          releaser: dl.releaser_account ?? '',
        }),
      };
    }
    case 'dispute.opened':
      return { machine: () => ({ t: 'OPEN_DISPUTE' }) };
    case 'escrow.cancelled': {
      const t = await requireTx(deps.ledger, d.tx_hash as string, 'EscrowCancel');
      requireOurEscrow(t, deal);
      if (deal.cancel_after === null || t.closeTime <= deal.cancel_after)
        throw unprocessable('cancel_too_early', 'CancelAfter has not passed on the validated ledger');
      return { machine: () => ({ t: 'CANCEL_AFTER_PASSED' }) };
    }
    case 'wallet.closed': {
      const t = await requireTx(deps.ledger, d.tx_hash as string, 'AccountDelete');
      if (t.tx.Account !== deal.shell_address)
        throw unprocessable('wrong_account', 'not an AccountDelete of the deal wallet');
      const sigs = Array.isArray(t.tx.Signers) ? t.tx.Signers.length : 1;
      return {
        machine: (dl) =>
          dl.state === 'CONTRACT_SIGNED' || dl.state === 'SHELL_OPEN' ? { t: 'ABANDON' } : { t: 'CLOSE', sigs },
      };
    }
    default:
      return {};
  }
}

/** Setup kinds: only in the setup states, and never once a post-quantum binding has signed the seal (I-S-M4). */
function setupGuard(kind: string, plan: Plan): Plan {
  if (!SETUP_KINDS.has(kind)) return plan;
  return {
    ...plan,
    states: SETUP_STATES,
    machine: (deal, log, pd) => {
      if (log.some((e) => e.kind === 'pq.bound'))
        throw unprocessable('seal_fixed', `${kind} would change the sealed deal`);
      return plan.machine?.(deal, log, pd);
    },
  };
}

/** Applies one party event. `principal` is the authenticated caller; the signature on the event is checked as well. */
export async function appendEvent(
  deps: CoordinatorDeps,
  principal: { dealId: string; role: Role },
  dealId: string,
  envelopeB64: string,
): Promise<AppendResult> {
  const bytes = fromBase64Strict(envelopeB64);
  if (!bytes)
    throw badRequest('envelope is not canonical base64', [{ path: 'envelope', message: 'not canonical base64' }]);
  let envJson: unknown;
  try {
    envJson = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw badRequest('envelope is not JSON', [{ path: 'envelope', message: 'not JSON' }]);
  }
  const env = HybridEnvelope.safeParse(envJson);
  if (!env.success)
    throw badRequest(
      'malformed envelope',
      env.error.issues.map((i) => ({ path: ['envelope', ...i.path].join('.'), message: i.message })),
    );
  const leafHash = bytesToHex(sha256(bytes));

  const repos = deps.db.repos;
  const deal = await requireDeal(repos, dealId);
  const keys = await repos.enrollmentKeys.listForDeal(dealId);
  const header = await deps.ledger.validatedLedger();
  const verified = verifyHybrid(env.data, registryOf(keys), header.closeTime);
  if (!verified.ok) throw unprocessable('bad_event_signature', `event signature refused: ${verified.code}`);

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(verified.payload));
  } catch {
    throw badRequest('event payload is not JSON');
  }
  const ev = LegxEvent.safeParse(parsedJson);
  if (!ev.success)
    throw badRequest(
      'malformed event',
      ev.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    );
  const p = ev.data.predicate as z.infer<typeof EventPredicate>;
  if (p.deal_id !== dealId)
    throw badRequest('event is for another deal', [{ path: 'predicate.deal_id', message: 'differs from the path' }]);
  if (deal.contract_root !== ZERO && ev.data.subject[0].digest.sha256 !== deal.contract_root)
    throw badRequest('event names another contract root', [
      { path: 'subject.0.digest.sha256', message: 'differs from the deal' },
    ]);

  // The signer, the claimed actor and the authenticated caller must be one and the same role.
  // Only a primary holder signs as the party or the lawyer (I-S-A1, OD-17).
  const signerPair = pairIdOf(verified.keyIds.ed25519, 'ed25519');
  const signer = keys.find((k) => k.key_id === signerPair);
  if (!signer || !isPrimaryHolder(signer.holder_role))
    throw forbidden('actor_mismatch', 'the event is not signed by a primary holder of the slot');
  const signerRole = ROLE_OF_SLOT[signer.slot as keyof typeof ROLE_OF_SLOT];
  if (p.actor.role !== principal.role || signerRole !== principal.role)
    throw forbidden('actor_mismatch', 'the event actor, its signer and the caller must be the same role');
  const allowed = ACTORS[p.kind]?.(p.data as Record<string, unknown>);
  if (!allowed) throw forbidden('kind_not_allowed', `${p.kind} is not written by a party`);
  if (!allowed.includes(principal.role))
    throw forbidden('role_not_allowed', `role ${principal.role} may not post ${p.kind}`);

  // A retry of an event we already hold returns the first result.
  const held = await repos.evidenceEvents.getBySeq(dealId, p.seq);
  if (held) {
    if (held.leaf_hash === leafHash) return { status: 'stored', seq: held.seq, leafHash, state: deal.state };
    return { status: 'seq_taken', head: await headOf(repos, dealId) };
  }

  const data = p.data as Record<string, unknown>;
  const config = await loadConfig(repos, dealId);
  const pdBefore = await derivePublicData(repos, deal, config.identity_policy);
  const plan = setupGuard(p.kind, await planFor(deps, p.kind, data, deal, pdBefore, leafHash));

  try {
    return await deps.db.transaction(async (tx): Promise<AppendResult> => {
      let state: State = 'DRAFT';
      const row = await tx.evidenceEvents.appendNext(dealId, async (head) => {
        if (head.nextSeq !== p.seq || head.prevHash !== p.prev_hash) throw new SeqMismatch();
        const locked = await requireDeal(tx, dealId);
        if (plan.states && !plan.states.includes(locked.state))
          throw unprocessable('wrong_state', `${p.kind} is not accepted in ${locked.state}`);
        const log = await loadLog(tx, dealId);
        const pd = plan.needsPublicData ? await derivePublicData(tx, locked, config.identity_policy) : undefined;
        const m = plan.machine?.(locked, log, pd);
        const patch: Partial<DealRow> = { ...(plan.patch?.(locked) ?? {}) };
        if (m) {
          const t = transition({ state: locked.state, wasLocked: locked.was_locked } as Deal, m);
          if (!t.ok) throw unprocessable(`refused_${t.refusal}`, t.message);
          patch.state = t.deal.state;
          patch.was_locked = t.deal.wasLocked;
        } else if (p.kind === 'nft.minted') {
          throw unprocessable('contract_unsigned', 'both lawyers must sign the contract before the NFT is recorded');
        }
        state = patch.state ?? locked.state;
        if (Object.keys(patch).length > 0) await tx.deals.update(dealId, patch);
        await deps.crash?.('deal.afterStateWrite');
        return { envelope: bytes, leaf_hash: leafHash };
      });
      await plan.after?.(tx, row);
      await enqueueStored(tx, dealId, row, {
        kind: p.kind,
        state,
        ...(p.ledger ? { ledger: { tx_hash: p.ledger.tx_hash, ledger_index: p.ledger.ledger_index } } : {}),
      });
      return { status: 'stored', seq: row.seq, leafHash, state };
    });
  } catch (e) {
    if (e instanceof SeqMismatch) return { status: 'seq_taken', head: await headOf(repos, dealId) };
    throw e;
  }
}

export { conflict };
