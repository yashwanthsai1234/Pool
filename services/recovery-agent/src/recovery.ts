// Client and lawyer recovery (DESIGN 6.4 "Recovery rules"): a start that is authenticated, the 72-hour delay, notices
// to the old device and both lawyers, a cancel by the old device, and one logged event per step. The rules are task
// 1.15's pure functions (`recoveryStart`, `recoveryCancel`, `recoveryAuthorize`); this module adds persistence, the
// clock, the notices and the log. The clock is injected so a test can stand at hour 71.
import type { ZkVerification } from '@legx/contracts/records';
import { kyselyOf } from '@legx/coordinator/frost/store';
import type { SlotName } from '@legx/core/frost';
import {
  RECOVERY_DELAY_MS,
  type RecoveryState,
  recoveryAuthorize,
  recoveryCancel,
  recoveryStart,
} from '@legx/core/frostRules';
import type { Database } from '@legx/db';
import { KeyNotRecorded } from '@legx/db';
import { type Kysely, sql } from 'kysely';
import type { EvidencePort } from './events.ts';
import type { DealInfoPort, NoticePort, RecoveryProofPort } from './ports.ts';

export interface RecoveryDeps {
  readonly db: Database;
  readonly evidence: EvidencePort;
  readonly notices: NoticePort;
  readonly proofs: RecoveryProofPort;
  readonly deal: DealInfoPort;
  /** Milliseconds; the same clock for the start, the delay and the cancel. */
  readonly now: () => number;
}

export type RecoveryViewState = 'waiting' | 'ready' | 'cancelled' | 'done';
export interface RecoveryView {
  readonly recoveryId: string;
  readonly dealId: string;
  readonly slot: SlotName;
  readonly newKeyId: string;
  readonly state: RecoveryViewState;
  readonly readyAt: number;
}

interface Row {
  recovery_id: string;
  deal_id: string;
  slot: string;
  new_key_id: string;
  state: RecoveryState;
}

/** A refusal the rules of task 1.15 do not cover: the request is well formed but names something this service has not got. */
export class Refusal extends Error {
  readonly code:
    | 'NEW_KEY_NOT_PINNED'
    | 'RECOVERY_IN_PROGRESS'
    | 'RECOVERY_UNKNOWN'
    | 'CANCEL_KEY_NOT_PINNED'
    | 'NO_RECOVERY'
    | 'PROOF_NOT_VERIFIED'
    | 'PROOF_NOT_BOUND';
  constructor(code: Refusal['code']) {
    super(code);
    this.name = 'Refusal';
    this.code = code;
  }
}

const CLIENT_ROLES = ['phone', 'second-authenticator', 'passkey-same-device'];
const LAWYER_ROLES = ['console', 'firm-hsm', 'partner'];
/** The device roles a slot's recovery can enroll or cancel: a client slot has client devices, a lawyer slot the firm's. */
const rolesOf = (slot: string): string[] => (slot === 'LA' || slot === 'LB' ? LAWYER_ROLES : CLIENT_ROLES);

export class RecoveryService {
  readonly #d: RecoveryDeps;
  readonly #k: Kysely<unknown>;
  constructor(deps: RecoveryDeps) {
    this.#d = deps;
    this.#k = kyselyOf(deps.db);
  }

  async #newKey(dealId: string, slot: SlotName, newKeyId: string): Promise<void> {
    try {
      const row = await this.#d.db.repos.enrollmentKeys.getUsable(newKeyId);
      if (row.deal_id !== dealId || row.slot !== slot || !rolesOf(slot).includes(row.holder_role))
        throw new Refusal('NEW_KEY_NOT_PINNED');
    } catch (e) {
      if (e instanceof KeyNotRecorded) throw new Refusal('NEW_KEY_NOT_PINNED');
      throw e;
    }
  }

  async #open(dealId: string, slot: SlotName, newKeyId: string, state: RecoveryState): Promise<RecoveryView> {
    const { recoveryId } = state; // UUIDv7 from core; the cancel statement names it (I-S-F2)
    try {
      await sql`insert into recovery_agent_recovery (recovery_id, deal_id, slot, new_key_id, state)
        values (${recoveryId}, ${dealId}, ${slot}, ${newKeyId}, ${JSON.stringify(state)}::jsonb)`.execute(this.#k);
    } catch {
      throw new Refusal('RECOVERY_IN_PROGRESS');
    }
    await this.#d.evidence.append(dealId, 'frost.recovery.requested', {
      recovery_id: recoveryId,
      slot,
      new_key_id: newKeyId,
      ready_at: state.startedAt + RECOVERY_DELAY_MS,
    });
    const readyAt = state.startedAt + RECOVERY_DELAY_MS;
    for (const to of ['old-device', 'lawyerA', 'lawyerB'] as const)
      await this.#d.notices.notify({ dealId, recoveryId, to, kind: 'recovery.requested', readyAt });
    return this.#view({ recovery_id: recoveryId, deal_id: dealId, slot, new_key_id: newKeyId, state });
  }

  /** Client recovery: a fresh proof with the onboarding identifier, plus a face match (shares 2 + 3, or 1 + 3). */
  async startClient(input: {
    dealId: string;
    slot: 'A' | 'B';
    newKeyId: string;
    proof: ZkVerification;
  }): Promise<RecoveryView> {
    await this.#newKey(input.dealId, input.slot, input.newKeyId);
    const checked = await this.#d.proofs.check(input);
    const { state } = recoveryStart({
      kind: 'client',
      slot: input.slot,
      at: this.#d.now(),
      proof: { identifier: checked.identifier, provedAt: checked.provedAt },
      onboardingIdentifier: await this.#d.deal.onboardingIdentifier(input.dealId, input.slot),
      faceMatch: checked.faceMatch,
    });
    return await this.#open(input.dealId, input.slot, input.newKeyId, state);
  }

  /** Lawyer recovery: a request signed by the firm's operations account (shares 2 + 3 of a lawyer slot). */
  async startLawyer(input: {
    dealId: string;
    slot: 'LA' | 'LB';
    newKeyId: string;
    /** The ledger index inside the signed message; the route checks it is fresh. */
    ledgerIndex: number;
    opsPub: Uint8Array;
    sig: Uint8Array;
  }): Promise<RecoveryView> {
    await this.#newKey(input.dealId, input.slot, input.newKeyId);
    const { state } = recoveryStart({
      kind: 'lawyer',
      slot: input.slot,
      at: this.#d.now(),
      dealId: input.dealId,
      newKeyId: input.newKeyId,
      ledgerIndex: input.ledgerIndex,
      sig: input.sig,
      opsPub: input.opsPub,
      opsAccount: await this.#d.deal.opsAccount(input.dealId, input.slot),
    });
    return await this.#open(input.dealId, input.slot, input.newKeyId, state);
  }

  async #row(recoveryId: string): Promise<Row> {
    const r = await sql<Row>`select * from recovery_agent_recovery where recovery_id = ${recoveryId}`.execute(this.#k);
    if (!r.rows[0]) throw new Refusal('RECOVERY_UNKNOWN');
    return r.rows[0];
  }

  async #save(row: Row, state: RecoveryState): Promise<void> {
    await sql`update recovery_agent_recovery set state = ${JSON.stringify(state)}::jsonb where recovery_id = ${row.recovery_id}`.execute(
      this.#k,
    );
  }

  /** The old device cancels during the delay with a statement signed by one of its pinned enrollment keys. */
  async cancel(input: { recoveryId: string; sig: Uint8Array; oldDevicePub: Uint8Array }): Promise<RecoveryView> {
    const row = await this.#row(input.recoveryId);
    const pinned = (await this.#d.db.repos.enrollmentKeys.listForDeal(row.deal_id)).filter(
      (k) => k.slot === row.slot && k.key_id !== row.new_key_id && rolesOf(row.slot).includes(k.holder_role),
    );
    const allowed = pinned.some((k) => k.ed25519_pub === Buffer.from(input.oldDevicePub.slice(1)).toString('hex'));
    if (!allowed || input.oldDevicePub.length !== 33) throw new Refusal('CANCEL_KEY_NOT_PINNED');
    const state = recoveryCancel(row.state, this.#d.now(), { sig: input.sig, oldDevicePub: input.oldDevicePub });
    await this.#save(row, state);
    await this.#d.evidence.append(row.deal_id, 'frost.recovery.cancelled', {
      recovery_id: row.recovery_id,
      slot: row.slot,
    });
    const readyAt = row.state.startedAt + RECOVERY_DELAY_MS;
    for (const to of ['lawyerA', 'lawyerB', 'new-device'] as const)
      await this.#d.notices.notify({
        dealId: row.deal_id,
        recoveryId: row.recovery_id,
        to,
        kind: 'recovery.cancelled',
        readyAt,
      });
    return this.#view({ ...row, state });
  }

  /**
   * Called before the agent releases a share: the slot must have a recovery whose delay has passed and which nobody
   * cancelled. Hour 71 gives RECOVERY_DELAY. The first success writes the `authorized` step.
   */
  async authorize(dealId: string, slot: SlotName): Promise<RecoveryView> {
    const r = await sql<Row>`select * from recovery_agent_recovery where deal_id = ${dealId} and slot = ${slot}
      order by (state->>'startedAt')::bigint desc limit 1`.execute(this.#k);
    const row = r.rows[0];
    if (!row) throw new Refusal('NO_RECOVERY');
    const state = recoveryAuthorize(row.state, this.#d.now());
    if (row.state.status !== 'authorized') {
      await this.#save(row, state);
      await this.#d.evidence.append(dealId, 'frost.recovery.authorized', { recovery_id: row.recovery_id, slot });
      const readyAt = row.state.startedAt + RECOVERY_DELAY_MS;
      for (const to of ['old-device', 'lawyerA', 'lawyerB'] as const)
        await this.#d.notices.notify({ dealId, recoveryId: row.recovery_id, to, kind: 'recovery.ready', readyAt });
    }
    return this.#view({ ...row, state });
  }

  /** The key that may sign for the slot during an authorized recovery besides the slot's other pinned holders. */
  async get(recoveryId: string): Promise<RecoveryView> {
    return this.#view(await this.#row(recoveryId));
  }

  #view(row: Row): RecoveryView {
    const readyAt = row.state.startedAt + RECOVERY_DELAY_MS;
    const state: RecoveryViewState =
      row.state.status === 'cancelled'
        ? 'cancelled'
        : row.state.status === 'authorized'
          ? 'ready'
          : this.#d.now() >= readyAt
            ? 'ready'
            : 'waiting';
    return {
      recoveryId: row.recovery_id,
      dealId: row.deal_id,
      slot: row.slot as SlotName,
      newKeyId: row.new_key_id,
      state,
      readyAt,
    };
  }
}
