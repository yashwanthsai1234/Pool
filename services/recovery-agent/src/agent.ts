// The recovery agent (DESIGN 6.4, 10.1): an independent holder of share 3 of each CLIENT slot, run by a party other than
// the client and the coordinator. Collusion is the risk: the agent plus one client share is enough to sign. So the agent
//   - signs only when the slot has a recovery whose 72-hour delay has passed and which nobody cancelled,
//   - signs only a request from a pinned client holder of that same slot, never for a lawyer slot or lawyer role,
//   - signs only an XRPL exit that the allow-list matches against the sealed deal (task 1.15 `cosign`),
//   - marks the commitment used in one atomic database step before it releases a share,
//   - writes a `frost.signed` event for every signature and a `frost.refused` event for every refusal,
//   - helps a repair only toward the new device of an authorized recovery.
// It holds one share per slot, encrypted at rest, and trusts the relay with nothing.
// Source: DESIGN 6.4 (signing, recovery, refresh and repair rules), 10.1 (collusion)
import type { FrostRelayPort } from '@legx/contracts/ports';
import { bytesToHex, sha256 } from '@legx/core/dealcore';
import type { SlotName, SlotPublic } from '@legx/core/frost';
import { type DkgContext, type DkgKey, testSignCheck, testSignMessage } from '@legx/core/frostDkg';
import { commitmentId, releaseShare } from '@legx/core/frostRules';
import type { Database } from '@legx/db';
import { xwingShareCipher } from './cipher.ts';
import { type EvidencePort, recoverySignedData, refreshedData, signedData } from './events.ts';
import { FrostHolder, type HolderConfig, type SignCheck } from './holder.ts';
import { PgNonceLedger } from './nonces.ts';
import { cosignCheck } from './policy.ts';
import type { DealInfoPort } from './ports.ts';
import type { RecoveryService } from './recovery.ts';
import { type RefreshRow, RefreshTable } from './refreshTable.ts';
import { AGENT_INDEX, type ShareVault, VaultError } from './vault.ts';
import type { HolderInfo, HolderKeys } from './wire.ts';

export type RefusalCode =
  | 'LAWYER_SLOT'
  | 'LAWYER_ROLE'
  | 'NOT_A_CLIENT_HOLDER'
  | 'DEAL_STATE'
  | 'NO_RECOVERY'
  | 'RECOVERY_DELAY'
  | 'CANCELLED'
  | 'NO_SHARE'
  | 'NOT_THE_NEW_DEVICE'
  | 'WRONG_PAIR';

/** A refusal: nothing was signed or sent, and the reason was logged. */
export class AgentRefusal extends Error {
  readonly code: RefusalCode;
  constructor(code: RefusalCode, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'AgentRefusal';
    this.code = code;
  }
}

const CLIENT_ROLES = new Set(['phone', 'second-authenticator', 'passkey-same-device']);

export interface AgentDeps {
  readonly db: Database;
  /** The agent's own enrollment keys (one pair for the service). */
  readonly keys: HolderKeys;
  readonly vault: ShareVault;
  readonly recoveries: RecoveryService;
  readonly evidence: EvidencePort;
  readonly deal: DealInfoPort;
  readonly relay: FrostRelayPort;
  /** The three holders of a slot, the agent last, as THE AGENT pinned them. The coordinator does not choose them. */
  readonly directory: (dealId: string, slot: SlotName) => Promise<readonly HolderInfo[]>;
  readonly pinned: HolderConfig['pinned'];
  readonly pollMs?: number;
  readonly timeoutMs?: number;
  readonly complaintWindowMs?: number;
}

interface Pending {
  readonly key: DkgKey;
  readonly ctx: DkgContext;
  readonly done: Set<string>;
}

export class RecoveryAgent {
  readonly #d: AgentDeps;
  readonly #pending = new Map<string, Pending>();
  readonly #refreshes: RefreshTable;

  constructor(deps: AgentDeps) {
    this.#d = deps;
    this.#refreshes = new RefreshTable(deps.db);
  }

  async #holder(dealId: string, slot: SlotName, over: Partial<HolderConfig> = {}): Promise<FrostHolder> {
    const holders = await this.#d.directory(dealId, slot);
    if (holders.length !== 3 || (holders[AGENT_INDEX - 1] as HolderInfo).keyId !== this.#d.keys.keyId)
      throw new AgentRefusal('NOT_A_CLIENT_HOLDER', 'the agent is not holder 3 of this slot');
    return new FrostHolder({
      index: AGENT_INDEX,
      keys: this.#d.keys,
      dealId,
      slot,
      holders,
      relay: this.#d.relay,
      cipher: xwingShareCipher,
      pinned: this.#d.pinned,
      ...(this.#d.pollMs ? { pollMs: this.#d.pollMs } : {}),
      ...(this.#d.timeoutMs ? { timeoutMs: this.#d.timeoutMs } : {}),
      ...(this.#d.complaintWindowMs ? { complaintWindowMs: this.#d.complaintWindowMs } : {}),
      ...over,
    });
  }

  /** Logs the refusal as an event and rethrows: a refused request leaves a trace and no signature. */
  async #logged<T>(dealId: string, slot: string, work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (e) {
      const code = e instanceof Error && 'code' in e ? String(e.code) : 'ERROR';
      await this.#d.evidence.append(dealId, 'frost.refused', { slot, reason: code });
      throw e;
    }
  }

  // ---------- key generation ----------

  /** Joins a DKG as holder 3. The share is kept in memory until both test signatures are done (DESIGN 6.4 rule 4). */
  async dkg(dealId: string, slot: SlotName, sessionId: string): Promise<{ groupPub: Uint8Array }> {
    return await this.#logged(dealId, slot, async () => {
      if (slot !== 'A' && slot !== 'B') throw new AgentRefusal('LAWYER_SLOT');
      if (await this.#d.vault.get(dealId, slot)) throw new VaultError('SLOT_TAKEN');
      const run = await (await this.#holder(dealId, slot)).dkg(sessionId);
      this.#pending.set(`${dealId}|${slot}`, { key: run.key, ctx: run.ctx, done: new Set() });
      return { groupPub: run.key.public.commitments[0] as Uint8Array };
    });
  }

  /** Test-signs one of the agent's two pairs; after both, the share is stored. */
  async testSign(
    dealId: string,
    slot: SlotName,
    sessionId: string,
    pair: readonly [number, number],
  ): Promise<Uint8Array> {
    const p = this.#pending.get(`${dealId}|${slot}`);
    if (!p || !pair.includes(AGENT_INDEX)) throw new AgentRefusal('WRONG_PAIR');
    const pub = p.key.public;
    const sig = await (await this.#holder(dealId, slot)).sign(sessionId, {
      msg: testSignMessage(p.ctx, pub, pair as [number, number]),
      kind: 'tagged',
      share: p.key.secret,
      pub,
      pair,
      check: (m, l) => testSignCheck(p.ctx, pub, AGENT_INDEX)(m, l),
    });
    p.done.add(pair.join(','));
    if (p.done.size === 2) {
      await this.#d.vault.insert(dealId, slot, { share: p.key.secret, pub, epoch: 0 });
      this.#pending.delete(`${dealId}|${slot}`);
    }
    return sig;
  }

  // ---------- signing ----------

  /** The policy that precedes every signature share (see the module comment). Throws `AgentRefusal`. */
  async #authorizeSigning(dealId: string, slot: SlotName, from: HolderInfo): Promise<string> {
    if (slot !== 'A' && slot !== 'B') throw new AgentRefusal('LAWYER_SLOT');
    if (!CLIENT_ROLES.has(from.role))
      throw new AgentRefusal(from.role === 'recovery-agent' ? 'NOT_A_CLIENT_HOLDER' : 'LAWYER_ROLE', from.role);
    const holders = await this.#d.directory(dealId, slot);
    if (!holders.some((x) => x.keyId === from.keyId)) throw new AgentRefusal('NOT_A_CLIENT_HOLDER', from.keyId);
    if (!(await this.#d.deal.allowsSigning(dealId, slot))) throw new AgentRefusal('DEAL_STATE');
    return (await this.#authorizedRecovery(dealId, slot)).recoveryId;
  }

  async #authorizedRecovery(dealId: string, slot: SlotName) {
    try {
      return await this.#d.recoveries.authorize(dealId, slot);
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === 'RECOVERY_DELAY' || code === 'CANCELLED' || code === 'NO_RECOVERY') throw new AgentRefusal(code);
      throw e;
    }
  }

  /**
   * Serves one signing session as holder 3. `pair` names the two holders asked to sign. The agent signs only an
   * authorized recovery's exit transaction; everything else is refused before a nonce is used.
   */
  async sign(dealId: string, slot: SlotName, sessionId: string, pair: readonly [number, number]): Promise<Uint8Array> {
    return await this.#logged(dealId, slot, async () => {
      if (slot !== 'A' && slot !== 'B') throw new AgentRefusal('LAWYER_SLOT');
      if (!pair.includes(AGENT_INDEX)) throw new AgentRefusal('WRONG_PAIR');
      const stored = await this.#d.vault.get(dealId, slot);
      if (!stored) throw new AgentRefusal('NO_SHARE');
      const holder = await this.#holder(dealId, slot);
      const holders = await this.#d.directory(dealId, slot);
      let recoveryId = '';
      let check: SignCheck = () => ({ ok: false, reason: 'no request yet' });
      return await holder.sign(sessionId, {
        kind: 'xrpl-multisign',
        share: stored.share,
        pub: stored.pub,
        pair,
        check: (m, l, c) => check(m, l, c),
        onBegin: async (_begin, from) => {
          recoveryId = await this.#authorizeSigning(dealId, slot, from);
          check = cosignCheck(await this.#d.deal.sealed(dealId), slot, 'recovery-agent', { exitsOnly: true });
        },
        release: (c, produce, msg) =>
          releaseShare(
            new PgNonceLedger(this.#d.db, {
              keyId: this.#d.keys.keyId,
              dealId,
              messageHash: bytesToHex(sha256(msg)),
            }),
            commitmentId(c),
            produce,
          ),
        onSigned: async ({ signature, shares, msg }) => {
          const signers = shares.map((id) => holders.find((x) => x.identifier === id) as HolderInfo);
          await this.#d.evidence.append(
            dealId,
            'frost.signed',
            signedData({ slot, messageHash: sha256(msg), signers: signers as [HolderInfo, HolderInfo], signature }),
          );
          await this.#d.evidence.append(
            dealId,
            'frost.recovery.signed',
            recoverySignedData(recoveryId, slot, signers as [HolderInfo, HolderInfo]),
          );
        },
      });
    });
  }

  // ---------- repair and refresh ----------

  /**
   * Helps a new device rebuild its share without the old one (DESIGN 6.4). The agent helps only the device that the
   * slot's authorized recovery names: otherwise a stranger who enrolls a key could be given a share.
   */
  async repairHelp(
    dealId: string,
    slot: SlotName,
    sessionId: string,
    o: { newIndex: number; helpers: readonly number[] },
  ) {
    await this.#logged(dealId, slot, async () => {
      if (slot !== 'A' && slot !== 'B') throw new AgentRefusal('LAWYER_SLOT');
      const stored = await this.#d.vault.get(dealId, slot);
      if (!stored) throw new AgentRefusal('NO_SHARE');
      const recovery = await this.#authorizedRecovery(dealId, slot);
      const holders = await this.#d.directory(dealId, slot);
      if ((holders[o.newIndex - 1] as HolderInfo).keyId !== recovery.newKeyId)
        throw new AgentRefusal('NOT_THE_NEW_DEVICE');
      await (await this.#holder(dealId, slot)).repairHelp(sessionId, { share: stored.share, pub: stored.pub, ...o });
    });
  }

  /**
   * Joins a refresh of all three holders. The new share replaces the old in the vault, then the agent signs its
   * deletion statement. The refresh is not complete, and the old epoch not retired, until every holder's statement
   * is in (`refreshProgress`).
   */
  async refresh(dealId: string, slot: SlotName, sessionId: string, epoch: number): Promise<RefreshRow> {
    return await this.#logged(dealId, slot, async () => {
      if (slot !== 'A' && slot !== 'B') throw new AgentRefusal('LAWYER_SLOT');
      const stored = await this.#d.vault.get(dealId, slot);
      if (!stored) throw new AgentRefusal('NO_SHARE');
      const holder = await this.#holder(dealId, slot);
      const done = await holder.refresh(sessionId, {
        share: stored.share,
        pub: stored.pub,
        participants: [1, 2, 3],
        epoch,
      });
      await this.#d.vault.replace(dealId, slot, { share: done.share, pub: done.pub, epoch });
      await holder.signDeletion(sessionId, done.ctx, done.pub, epoch);
      this.#refreshCtx.set(`${dealId}|${slot}|${epoch}`, { ctx: done.ctx, pub: done.pub, sessionId, holder });
      return await this.refreshProgress(dealId, slot, epoch);
    });
  }

  readonly #refreshCtx = new Map<
    string,
    { ctx: Parameters<FrostHolder['refreshStatus']>[1]; pub: SlotPublic; sessionId: string; holder: FrostHolder }
  >();

  /** Reads the deletion statements that have arrived; writes `frost.refreshed` and the bookkeeping row. */
  async refreshProgress(dealId: string, slot: SlotName, epoch: number): Promise<RefreshRow> {
    const r = this.#refreshCtx.get(`${dealId}|${slot}|${epoch}`);
    if (!r) throw new AgentRefusal('NO_SHARE', 'no refresh in progress');
    const ev = await r.holder.refreshStatus(r.sessionId, r.ctx, r.pub);
    const holders = await this.#d.directory(dealId, slot);
    const before = await this.#refreshes.get(dealId, slot, epoch);
    const row = await this.#refreshes.set(dealId, slot, epoch, ev.missing);
    if (!before || before.status !== row.status || before.missing.join() !== row.missing.join())
      await this.#d.evidence.append(
        dealId,
        'frost.refreshed',
        refreshedData(ev, slot, epoch, r.pub.commitments[0] as Uint8Array, holders),
      );
    return row;
  }
}
