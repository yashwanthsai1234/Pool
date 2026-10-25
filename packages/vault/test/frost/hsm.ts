// A stand-in for task 3.10's firm HSM co-signer (not built yet): it holds share 2 of a lawyer slot, checks the request
// against its own copy of the seal and the lawyer's user-verified WebAuthn approval (core's `cosign`), marks the
// commitment used before it releases a share, and speaks 3.9's signing kinds on the relay through `serveRelayCoSign`.
// Also a P-256 approver that makes real WebAuthn-shaped assertions (for WebKit, which has no virtual authenticator).
import { type Commitment, type KeyShare, SigningSession, type SlotPublic } from '@legx/core/frost';
import {
  commitmentId,
  cosign,
  MemoryNonceLedger,
  releaseShare,
  type SealedDeal,
  type SignRequest,
} from '@legx/core/frostRules';
import { toBase64 } from '@legx/core/pq';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { type ApprovalWire, approvalBytes, type RequestApproval } from '../../src/frost/approval.ts';
import { type RemoteSigner, serveRelayCoSign } from '../../src/frost/cosign.ts';
import type { FrostHolder } from '../../src/frost/holder.ts';
import { hex } from '../../src/frost/wire.ts';
import { messageFor } from '../../src/vault.ts';

export const RP_ID = location.hostname;
const b64url = (b: Uint8Array) => toBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** A lawyer's ES256 credential that signs like an authenticator; `uv: false` clears the user-verified flag. */
export function fakeApprover(opts: { uv?: boolean } = {}) {
  const secret = p256.utils.randomSecretKey();
  const calls: Uint8Array[] = [];
  const approve: RequestApproval = async (msgHash) => {
    calls.push(msgHash);
    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({ type: 'webauthn.get', challenge: b64url(msgHash), origin: location.origin }),
    );
    const flags = 0x01 | (opts.uv === false ? 0 : 0x04);
    const authenticatorData = new Uint8Array([...sha256(new TextEncoder().encode(RP_ID)), flags, 0, 0, 0, 1]);
    const sig = p256.sign(new Uint8Array([...authenticatorData, ...sha256(clientDataJSON)]), secret, {
      format: 'der',
      lowS: false,
    });
    return {
      credential_id: toBase64(new Uint8Array(16)),
      authenticator_data: toBase64(authenticatorData),
      client_data_json: toBase64(clientDataJSON),
      signature: toBase64(sig),
      message_hash: hex(msgHash),
    } as ApprovalWire;
  };
  return { approve, approver: { p256Pub: p256.getPublicKey(secret), rpId: RP_ID }, calls };
}

/** The mock HSM. `start` is what the console's `relayCoSigner` calls (over HTTP in the app, directly here). */
export function mockHsm(o: {
  holder: FrostHolder;
  share: KeyShare;
  pub: SlotPublic;
  deal: () => SealedDeal;
  dealId: string;
  approver: { p256Pub: Uint8Array; rpId: string };
}) {
  const ledger = new MemoryNonceLedger();
  const sessions = new Map<string, { s: SigningSession; msg: Uint8Array; check: () => ReturnType<typeof cosign> }>();
  const decisions: { ok: boolean; reason?: string }[] = [];
  const signer = (request: SignRequest): RemoteSigner => ({
    async commit({ approval }) {
      const msg = messageFor(o.pub, request);
      const check = () =>
        cosign({
          request,
          msg,
          deal: o.deal(),
          slot: 'LA',
          role: 'firm-hsm',
          ...(approval ? { approval: approvalBytes(approval) } : {}),
          approver: o.approver,
        });
      const verdict = check();
      decisions.push(verdict);
      if (!verdict.ok) throw new Error(verdict.reason);
      const s = SigningSession.open(o.share, o.pub, msg);
      const id = crypto.randomUUID();
      sessions.set(id, { s, msg, check });
      return { session: id, commitment: s.commitment };
    },
    async sign(id, list: Commitment[]) {
      const p = sessions.get(id);
      sessions.delete(id);
      if (!p) throw new Error('NOT_FOUND');
      const mine = list.find((c) => c.identifier === o.share.identifier) as Commitment;
      return releaseShare(ledger, commitmentId(mine), () => p.s.signShare(p.msg, list, p.check));
    },
  });
  return {
    decisions,
    start: async ({
      sessionId,
      request,
      approval,
    }: {
      sessionId: string;
      request: SignRequest;
      approval?: ApprovalWire;
    }) => {
      const run = await serveRelayCoSign({
        holder: o.holder,
        signer: signer(request),
        dealId: o.dealId,
        slot: 'LA',
        sessionId,
        request,
        msg: messageFor(o.pub, request),
        ...(approval ? { approval } : {}),
      });
      run.finished.catch(() => undefined);
    },
  };
}
