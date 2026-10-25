// The firm HSM co-signer (DESIGN 6.4): holder 2 of a LAWYER slot (console, firm HSM, partner). A checker first and a
// signer second. Before it signs a share it
//   - accepts the request only from the firm's own operations account (a signature over the exact request),
//   - decodes the message itself and compares it with the sealed deal (task 1.15 allow-list, through the recovery
//     agent's `cosignCheck`); it never trusts the coordinator's description of the transaction,
//   - requires a user-verified WebAuthn approval by the lawyer over the same message hash (`LawyerApprovals`),
//   - for a recovery pair (HSM + partner, no console) requires a recovery that waited out its 72 hours and was not
//     cancelled (the recovery agent's `RecoveryService`, started by a request signed by the operations account),
//   - marks the nonce commitment used in one atomic step before the share is released (`releaseShare`),
// and it writes one audit row for every decision, signed or refused.
// Source: DESIGN 6.4 "Signing rules" and "Recovery rules"; https://www.rfc-editor.org/rfc/rfc9591#section-7.7
import type { FrostRelayPort } from '@legx/contracts/ports';
import { bytesToHex, sha256, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import type { SlotName } from '@legx/core/frost';
import { type DkgContext, type DkgKey, testSignCheck, testSignMessage } from '@legx/core/frostDkg';
import { commitmentId, releaseShare, type SealedDeal } from '@legx/core/frostRules';
import { verifyXrplKeySig } from '@legx/core/verify';
import type { Database } from '@legx/db';
import { xwingShareCipher } from '@legx/recovery-agent/cipher';
import { FrostHolder, type HolderConfig, type SignBegin, type SignCheck } from '@legx/recovery-agent/holder';
import { PgNonceLedger } from '@legx/recovery-agent/nonces';
import { cosignCheck } from '@legx/recovery-agent/policy';
import type { DealInfoPort } from '@legx/recovery-agent/ports';
import type { RecoveryService } from '@legx/recovery-agent/recovery';
import type { HolderInfo, HolderKeys } from '@legx/recovery-agent/wire';
import { deriveAddress } from 'xrpl';
import type { ApprovalCode, LawyerApprovals, WireApproval } from './approval.ts';
import type { AuditLog } from './audit.ts';
import { type FirmShareVault, HSM_INDEX } from './vault.ts';

export type RefusalCode =
  | ApprovalCode
  | 'NOT_A_LAWYER_SLOT'
  | 'OPERATOR_UNAUTHORIZED'
  | 'NOT_THIS_HOLDER'
  | 'NO_SHARE'
  | 'WRONG_PAIR'
  | 'DEAL_STATE'
  | 'SEAL_MISMATCH'
  | 'NOT_ALLOWED'
  | 'UNKNOWN_SIGNER'
  | 'NO_RECOVERY'
  | 'RECOVERY_DELAY'
  | 'CANCELLED';

/** A refusal: nothing was signed and the reason was logged. */
export class CosignerRefusal extends Error {
  readonly code: RefusalCode;
  constructor(code: RefusalCode, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'CosignerRefusal';
    this.code = code;
  }
}

/** What the operations account signs to ask the HSM to join one signing session. */
export const operatorRequestMessage = (r: {
  dealId: string;
  slot: string;
  sessionId: string;
  seal: string;
  pair: readonly [number, number];
}): Uint8Array =>
  tupleHash('legx/firm-cosign-request/v1', [r.dealId, r.slot, r.sessionId, r.seal, r.pair.join(',')].map(utf8ToBytes));

export interface SignRequest {
  readonly dealId: string;
  readonly slot: SlotName;
  readonly sessionId: string;
  readonly pair: readonly [number, number];
  /** The deal seal (hex) the operator signed for; it must be the one stored for the deal. */
  readonly seal: string;
  readonly operator: { readonly opsPub: Uint8Array; readonly sig: Uint8Array };
  /** Needed only when the HSM aggregates (pair [2, 3]); otherwise the message arrives in the aggregator's `sign.begin`. */
  readonly message?: {
    readonly msg: Uint8Array;
    readonly kind: 'xrpl-multisign' | 'tagged';
    readonly tagged?: { tag: string; parts: readonly Uint8Array[] };
    readonly approval?: WireApproval;
  };
}

export interface FirmDeps {
  readonly db: Database;
  /** The HSM's own enrollment keys. */
  readonly keys: HolderKeys;
  readonly vault: FirmShareVault;
  readonly recoveries: RecoveryService;
  readonly approvals: LawyerApprovals;
  readonly audit: AuditLog;
  readonly deal: DealInfoPort;
  readonly relay: FrostRelayPort;
  /** The three holders of a lawyer slot as THE HSM pinned them (console, HSM, partner). */
  readonly directory: (dealId: string, slot: SlotName) => Promise<readonly HolderInfo[]>;
  readonly pinned: HolderConfig['pinned'];
  readonly pollMs?: number;
  readonly timeoutMs?: number;
  readonly complaintWindowMs?: number;
}

/** What a decision is logged with while it is being made. */
interface Trail {
  messageHash: string;
  seal: string;
  detail: Record<string, unknown>;
}

const hex = bytesToHex;

export class FirmCosigner {
  readonly #d: FirmDeps;
  readonly #pending = new Map<string, { key: DkgKey; ctx: DkgContext; done: Set<string> }>();

  constructor(deps: FirmDeps) {
    this.#d = deps;
  }

  async #holder(dealId: string, slot: SlotName): Promise<FrostHolder> {
    const holders = await this.#d.directory(dealId, slot);
    if (holders.length !== 3 || (holders[HSM_INDEX - 1] as HolderInfo).keyId !== this.#d.keys.keyId)
      throw new CosignerRefusal('NOT_THIS_HOLDER', 'the HSM is not holder 2 of this slot');
    return new FrostHolder({
      index: HSM_INDEX,
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
    });
  }

  // ---------- key generation ----------

  /** Joins a DKG as holder 2 of a lawyer slot. The share is kept in memory until both test signatures are done. */
  async dkg(dealId: string, slot: SlotName, sessionId: string): Promise<{ groupPub: Uint8Array }> {
    if (slot !== 'LA' && slot !== 'LB') throw new CosignerRefusal('NOT_A_LAWYER_SLOT');
    const run = await (await this.#holder(dealId, slot)).dkg(sessionId);
    this.#pending.set(`${dealId}|${slot}`, { key: run.key, ctx: run.ctx, done: new Set() });
    return { groupPub: run.key.public.commitments[0] as Uint8Array };
  }

  /** Test-signs one of the HSM's two pairs; after both, the share is stored (DESIGN 6.4 key generation rule 4). */
  async testSign(dealId: string, slot: SlotName, sessionId: string, pair: readonly [number, number]) {
    const p = this.#pending.get(`${dealId}|${slot}`);
    if (!p || !pair.includes(HSM_INDEX)) throw new CosignerRefusal('WRONG_PAIR');
    const pub = p.key.public;
    const sig = await (await this.#holder(dealId, slot)).sign(sessionId, {
      msg: testSignMessage(p.ctx, pub, pair as [number, number]),
      kind: 'tagged',
      share: p.key.secret,
      pub,
      pair,
      check: (m, l) => testSignCheck(p.ctx, pub, HSM_INDEX)(m, l),
    });
    p.done.add(pair.join(','));
    if (p.done.size === 2) {
      await this.#d.vault.insert(dealId, slot, { share: p.key.secret, pub, epoch: 0 });
      this.#pending.delete(`${dealId}|${slot}`);
    }
    return sig;
  }

  // ---------- signing ----------

  /** Only the firm's operations account may ask (P3.10-08). */
  async #operator(r: SignRequest): Promise<void> {
    const pubHex = hex(r.operator.opsPub).toUpperCase();
    const ops = await this.#d.deal.opsAccount(r.dealId, r.slot as 'LA' | 'LB');
    const account = r.operator.opsPub.length === 33 ? deriveAddress(pubHex) : '';
    if (account !== ops || !verifyXrplKeySig(pubHex, operatorRequestMessage(r), hex(r.operator.sig)))
      throw new CosignerRefusal('OPERATOR_UNAUTHORIZED');
  }

  async #authorizedRecovery(dealId: string, slot: SlotName): Promise<void> {
    try {
      await this.#d.recoveries.authorize(dealId, slot);
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === 'RECOVERY_DELAY' || code === 'CANCELLED' || code === 'NO_RECOVERY') throw new CosignerRefusal(code);
      throw e;
    }
  }

  /**
   * Joins one signing session as holder 2. Every refusal comes before a nonce is used and leaves an audit row; every
   * released share leaves one too.
   */
  async sign(r: SignRequest): Promise<Uint8Array> {
    const trail: Trail = { messageHash: '', seal: '', detail: {} };
    try {
      return await this.#sign(r, trail);
    } catch (e) {
      const code = e instanceof Error && 'code' in e ? String(e.code) : 'ERROR';
      await this.#d.audit.append({
        dealId: r.dealId,
        slot: r.slot,
        decision: 'refused',
        reason: code,
        ...trail,
      });
      throw e;
    }
  }

  async #sign(r: SignRequest, trail: Trail): Promise<Uint8Array> {
    if (r.slot !== 'LA' && r.slot !== 'LB') throw new CosignerRefusal('NOT_A_LAWYER_SLOT');
    await this.#operator(r);
    if (!r.pair.includes(HSM_INDEX) || r.pair[0] === r.pair[1]) throw new CosignerRefusal('WRONG_PAIR');
    const stored = await this.#d.vault.get(r.dealId, r.slot);
    if (!stored) throw new CosignerRefusal('NO_SHARE');
    const sealed: SealedDeal = await this.#d.deal.sealed(r.dealId);
    trail.seal = sealed.dealSeal ? hex(sealed.dealSeal) : '';
    if (trail.seal !== '' && r.seal.toLowerCase() !== trail.seal) throw new CosignerRefusal('SEAL_MISMATCH');
    if (!(await this.#d.deal.allowsSigning(r.dealId, r.slot))) throw new CosignerRefusal('DEAL_STATE');
    // shares 2 + 3 (no console) are the recovery pair: only after an authorized recovery
    if (!r.pair.includes(1)) await this.#authorizedRecovery(r.dealId, r.slot);

    const holders = await this.#d.directory(r.dealId, r.slot);
    const holder = await this.#holder(r.dealId, r.slot);
    let approved: string | undefined;
    let allow: SignCheck = () => ({ ok: false, reason: 'no request yet' });

    /** The whole decision on the exact message, before any nonce is used. */
    const decide = async (
      msg: Uint8Array,
      b: Pick<SignBegin, 'message_kind' | 'tagged' | 'approval'>,
      from?: HolderInfo,
    ): Promise<void> => {
      trail.messageHash = hex(sha256(msg));
      if (from && (!['console', 'partner'].includes(from.role) || !holders.some((h) => h.keyId === from.keyId)))
        throw new CosignerRefusal('UNKNOWN_SIGNER', from.keyId);
      // The allow-list only: `cosignCheck` with a role that needs no approval. The approval is checked below with
      // @simplewebauthn/server, which is async and holds state (counters, used assertions).
      const check = cosignCheck(sealed, r.slot, 'console');
      const allowed = check(msg, [], { request: undefined, begin: b as SignBegin });
      if (!allowed.ok) throw new CosignerRefusal('NOT_ALLOWED', allowed.reason);
      if (b.message_kind === 'xrpl-multisign' && !sealed.dealSeal)
        throw new CosignerRefusal('SEAL_MISMATCH', 'no seal');
      trail.detail = { kind: b.message_kind, ...(b.tagged ? { tag: b.tagged.tag } : {}) };
      const credential = await this.#d.approvals.verify(r.dealId, r.slot, sha256(msg), b.approval);
      trail.detail = { ...trail.detail, credential };
      approved = trail.messageHash;
      allow = check;
    };

    if (r.pair[0] === HSM_INDEX) {
      if (!r.message) throw new CosignerRefusal('NOT_ALLOWED', 'no message');
      const m = r.message;
      await decide(m.msg, {
        message_kind: m.kind,
        ...(m.tagged ? { tagged: { tag: m.tagged.tag, parts: m.tagged.parts.map(hex) } } : {}),
        ...(m.approval ? { approval: m.approval } : {}),
      } as SignBegin);
    }

    return await holder.sign(r.sessionId, {
      kind: r.message?.kind ?? 'xrpl-multisign',
      share: stored.share,
      pub: stored.pub,
      pair: r.pair,
      ...(r.message ? { msg: r.message.msg } : {}),
      ...(r.message?.tagged ? { tagged: r.message.tagged } : {}),
      ...(r.message?.approval ? { approval: r.message.approval } : {}),
      check: (m, l, c) =>
        hex(sha256(m)) === approved ? allow(m, l, c) : { ok: false, reason: 'no approval for this message' },
      onBegin: async (begin, from) => decide(Buffer.from(begin.message, 'hex'), begin, from),
      release: async (c, produce, msg) => {
        const share = await releaseShare(
          new PgNonceLedger(this.#d.db, {
            keyId: this.#d.keys.keyId,
            dealId: r.dealId,
            messageHash: hex(sha256(msg)),
          }),
          commitmentId(c),
          produce,
        );
        await this.#d.audit.append({
          dealId: r.dealId,
          slot: r.slot,
          decision: 'share_released',
          reason: 'signed',
          ...trail,
          detail: { ...trail.detail, commitment_id: commitmentId(c) },
        });
        return share;
      },
    });
  }
}
