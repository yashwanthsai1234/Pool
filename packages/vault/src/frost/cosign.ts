// Two-share signing with a remote share 2 over the relay (DESIGN 6.4): the client's second device, or the firm HSM
// for a lawyer slot (task 3.10). The vault's `signRemote` (task 4.2) opens share 1 only after the remote holder has
// committed, so here the remote holder speaks first: it sends `sign.begin` with the exact message and its own
// commitment, the primary device answers `sign.commit`, the remote sends `sign.request` with the list and then its
// `sign.share`. The primary device aggregates and verifies inside the vault. Message kinds and order are 3.9's.
//  - The remote decodes the request itself, checks it against its own seal and asks its human first (the second
//    device's `approve`, or the lawyer's WebAuthn approval that the firm HSM checks).
//  - The primary device refuses a `sign.begin` for any bytes other than the ones it derived itself (P4.7-08).
// Source: https://www.rfc-editor.org/rfc/rfc9591#section-5 (round 1 commitments, round 2 shares)
import type { Commitment } from '@legx/core/frost';
import type { SignRequest } from '@legx/core/frostRules';
import { sha256 } from '@noble/hashes/sha2.js';
import { VaultError } from '../errors.ts';
import type { CoSignerPort } from '../vault.ts';
import type { ApprovalWire, RequestApproval } from './approval.ts';
import type { FrostHolder } from './holder.ts';
import type { RelayPort } from './transport.ts';
import { commitmentsDigest, type HolderInfo, hex, type OfKind, type RelayMessage, unhex } from './wire.ts';

const wireC = (c: Commitment) => ({ identifier: c.identifier, hiding: hex(c.hiding), binding: hex(c.binding) });
const coreC = (c: { identifier: string; hiding: string; binding: string }): Commitment => ({
  identifier: c.identifier,
  hiding: unhex(c.hiding),
  binding: unhex(c.binding),
});
const header = (h: FrostHolder, sessionId: string, dealId: string, slot: string) => ({
  session_id: sessionId,
  deal_id: dealId,
  slot,
  from: h.identifier,
});
const kindOf = (r: SignRequest) => (r.kind === 'xrpl-multisign' ? 'xrpl-multisign' : 'tagged');

/** Starts the remote holder on a session: the second device's request channel, or the HSM's HTTP call (3.10). */
export type StartRemote = (input: {
  sessionId: string;
  request: SignRequest;
  approval?: ApprovalWire;
}) => Promise<void>;

/**
 * The primary device's `CoSignerPort` (pass it as the vault's `cosigner`). `messageOf` derives the bytes the vault
 * will sign (`messageFor`), `approve` is the lawyer's approval for a firm-HSM slot, and `onRefused` gets the reason
 * the remote gave, for the screen (the vault itself reports only `APPROVAL_REFUSED`).
 */
export function relayCoSigner(o: {
  holder: FrostHolder;
  relay: RelayPort;
  holders: readonly HolderInfo[];
  dealId: string;
  slot: string;
  remote: number;
  messageOf: (request: SignRequest) => Uint8Array;
  start: StartRemote;
  approve?: RequestApproval;
  onRefused?: (reason: string) => void;
}): CoSignerPort {
  const sessions = new Map<string, Uint8Array>();
  const refuse = (reason: string): never => {
    o.onRefused?.(reason);
    throw new VaultError('APPROVAL_REFUSED');
  };
  return {
    async commit({ request }) {
      const msg = o.messageOf(request);
      const approval = o.approve ? await o.approve(sha256(msg)).catch(() => refuse('APPROVAL_MISSING')) : undefined;
      const pair = [o.holders[o.remote - 1]?.identifier, o.holder.identifier] as [string, string];
      const sessionId = await o.relay.openSession({ purpose: 'sign', holders: o.holders, pair });
      await o
        .start({ sessionId, request, ...(approval ? { approval } : {}) })
        .catch((e: unknown) => refuse(e instanceof Error ? e.message : 'refused'));
      const begin = (await o.holder.collect(sessionId, 'sign.begin', 1))[0]?.message as OfKind<'sign.begin'>;
      if (begin.message !== hex(msg)) refuse('MESSAGE_REFUSED: the remote holder sent other bytes');
      sessions.set(sessionId, msg);
      return { session: sessionId, commitment: coreC(begin.commitment) };
    },
    async sign(sessionId, list) {
      const msg = sessions.get(sessionId);
      sessions.delete(sessionId); // one try per session
      const mine = list.find((c) => c.identifier === o.holder.identifier);
      if (!msg || !mine) throw new VaultError('NOT_FOUND');
      await o.holder.send({
        ...header(o.holder, sessionId, o.dealId, o.slot),
        kind: 'sign.commit',
        message_hash: hex(sha256(msg)),
        commitment: wireC(mine),
      } as RelayMessage);
      const req = (await o.holder.collect(sessionId, 'sign.request', 1))[0]?.message as OfKind<'sign.request'>;
      const same = (a: readonly Commitment[], b: readonly Commitment[]) =>
        JSON.stringify(a.map(wireC).sort((x, y) => x.identifier.localeCompare(y.identifier))) ===
        JSON.stringify(b.map(wireC).sort((x, y) => x.identifier.localeCompare(y.identifier)));
      if (req.message !== hex(msg) || !same(req.commitments.map(coreC), list))
        throw new VaultError('SIGNATURE_INVALID');
      const share = (await o.holder.collect(sessionId, 'sign.share', 1))[0]?.message as OfKind<'sign.share'>;
      return unhex(share.share);
    },
  };
}

/** The remote holder's side: a vault co-signer (second device) or an HSM share, speaking 3.9's kinds on the relay. */
export interface RemoteSigner {
  commit(input: {
    request: SignRequest;
    approval?: ApprovalWire;
  }): Promise<{ session: string; commitment: Commitment }>;
  sign(session: string, list: Commitment[]): Promise<Uint8Array>;
}

/**
 * Runs one remote co-signature on `sessionId`. Resolves once `sign.begin` is out (a refusal throws before anything is
 * sent); `finished` settles when the share is out.
 */
export async function serveRelayCoSign(o: {
  holder: FrostHolder;
  signer: RemoteSigner;
  dealId: string;
  slot: string;
  sessionId: string;
  request: SignRequest;
  msg: Uint8Array;
  approval?: ApprovalWire;
}): Promise<{ finished: Promise<void> }> {
  const h = header(o.holder, o.sessionId, o.dealId, o.slot);
  const withApproval = o.approval ? { approval: o.approval } : {};
  const c = await o.signer.commit({ request: o.request, ...withApproval });
  await o.holder.send({
    ...h,
    kind: 'sign.begin',
    message: hex(o.msg),
    message_kind: kindOf(o.request),
    commitment: wireC(c.commitment),
    ...withApproval,
  } as RelayMessage);
  const finished = (async () => {
    const other = (await o.holder.collect(o.sessionId, 'sign.commit', 1))[0]?.message as OfKind<'sign.commit'>;
    const list = [c.commitment, coreC(other.commitment)];
    await o.holder.send({
      ...h,
      kind: 'sign.request',
      message: hex(o.msg),
      message_kind: kindOf(o.request),
      commitments: list.map(wireC),
      ...withApproval,
    } as unknown as RelayMessage);
    const share = await o.signer.sign(c.session, list);
    await o.holder.send({
      ...h,
      kind: 'sign.share',
      message_hash: hex(sha256(o.msg)),
      commitments_hash: commitmentsDigest(list),
      share: hex(share),
    } as RelayMessage);
  })();
  return { finished };
}

/** Where the console asks the firm HSM (task 3.10) to begin; not in the contracts yet (request in build/status/4.7.md). */
export const FIRM_HSM_SIGN_PATH = '/firm-hsm/sign';

/** The JSON form of a sign request (bytes as lowercase hex). */
export const requestToJson = (r: SignRequest): unknown =>
  r.kind === 'tagged'
    ? { kind: 'tagged', tag: r.tag, parts: r.parts.map(hex) }
    : r.kind === 'gate-record'
      ? { kind: 'gate-record', envelope: hex(r.envelope) }
      : r;
export const requestFromJson = (j: {
  kind: string;
  tag?: string;
  parts?: string[];
  envelope?: string;
  tx?: Record<string, unknown>;
}): SignRequest =>
  j.kind === 'tagged'
    ? { kind: 'tagged', tag: String(j.tag), parts: (j.parts ?? []).map(unhex) }
    : j.kind === 'gate-record'
      ? { kind: 'gate-record', envelope: unhex(String(j.envelope)) }
      : { kind: 'xrpl-multisign', tx: j.tx ?? {} };

/** `StartRemote` over HTTP to the firm HSM service: a refusal comes back as `{ reason }` and is thrown with it. */
export function httpStart(url: string, dealId: string, doFetch: typeof fetch = (i, o) => fetch(i, o)): StartRemote {
  return async ({ sessionId, request, approval }) => {
    const res = await doFetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ dealId, sessionId, request: requestToJson(request), ...(approval ? { approval } : {}) }),
    });
    if (!res.ok)
      throw new Error(((await res.json().catch(() => ({}))) as { reason?: string }).reason ?? `HTTP ${res.status}`);
  };
}
