// The fixed message schema of the vault frame (DESIGN 6.4 "Code integrity"): the app reaches the vault only through
// `postMessage` on a MessagePort, and only with these messages. No message carries a share, a salt, a PRF output,
// a recovery code or a key: shares enter the frame only from the DKG and repair code that runs inside it (task 4.7),
// and the recovery code is typed into the frame's own UI. Task 4.10 hands the port to the cross-origin iframe
// (checking `event.origin`) and serves the frame; this module is the schema and both ends.
// The same RPC carries the second-device co-signing messages (commitments and signature shares are public).
// Source: https://html.spec.whatwg.org/multipage/web-messaging.html#message-channels
// Source: https://zod.dev/api (strict objects)

import type { ApiAuth } from '@legx/contracts/api';
import { WebAuthnApproval } from '@legx/contracts/frost';
import type { HybridPublicKeys, HybridSignature } from '@legx/contracts/ports';
import type { FrostRefreshed } from '@legx/core/frostRefresh';
import type { SignRequest } from '@legx/core/frostRules';
import type { SealedPackage } from '@legx/core/pq';
import { z } from 'zod';
import {
  type CeremonyIo,
  ceremonyClient,
  ceremonyServer,
  DkgArgs,
  type DkgRequest,
  type FrameDkgResult,
  isCeremonyMessage,
  RefreshArgs,
  type RefreshRequest,
  RepairArgs,
  type RepairRequest,
  SlotSignBase,
  type SlotSignRequest,
} from './ceremony.ts';
import { type VaultCode, VaultError } from './errors.ts';
import type { EnrollResult, FrameHost, SignApiInput } from './frame-host.ts';
import type { ShellInfo } from './shell.ts';
import type { CoSignerPort, Vault } from './vault.ts';

type ApiAuthValue = z.infer<typeof ApiAuth>;
const bytes = z.instanceof(Uint8Array);
const uuid = z.uuid({ version: 'v7' });
const SignRequestSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('xrpl-multisign'), tx: z.record(z.string(), z.union([z.string(), z.number()])) }),
  z.strictObject({ kind: z.literal('xrpl-single'), tx: z.record(z.string(), z.unknown()) }),
  z.strictObject({ kind: z.literal('tagged'), tag: z.string().max(64), parts: z.array(bytes).max(8) }),
  z.strictObject({ kind: z.literal('gate-record'), envelope: bytes }),
]);
const CommitmentSchema = z.strictObject({
  identifier: z.string().regex(/^[0-9a-f]{64}$/),
  hiding: bytes,
  binding: bytes,
});

/** Vault requests (app to frame). */
const VaultOps = {
  list: z.strictObject({}),
  location: z.strictObject({}),
  sign: z.strictObject({ dealId: uuid, request: SignRequestSchema }),
  signMultisig: z.strictObject({ dealId: uuid, tx: z.record(z.string(), z.union([z.string(), z.number()])) }),
  signSingle: z.strictObject({ dealId: uuid, tx: z.record(z.string(), z.unknown()) }),
  backup: z.strictObject({ dealId: uuid }),
  restore: z.strictObject({ file: bytes }),
  signSlot: SlotSignBase.extend({ request: SignRequestSchema, approval: WebAuthnApproval }),
  dkg: DkgArgs,
  refresh: RefreshArgs,
  repair: RepairArgs,
  enroll: z.strictObject({ dealId: uuid, pairId: z.string().max(200).optional() }),
  deals: z.strictObject({}),
  shellKey: z.strictObject({ dealId: uuid }),
  signShell: z.strictObject({ dealId: uuid, tx: z.record(z.string(), z.unknown()) }),
  signHybrid: z.strictObject({ dealId: uuid, msg: bytes }),
  signerKeys: z.strictObject({ dealId: uuid }),
  pinSeal: z.strictObject({ dealId: uuid, seal: z.string().max(64) }),
  loadDeal: z.strictObject({ dealId: uuid, data: z.unknown(), exitAmountDrops: z.string().max(20) }),
  openBox: z.strictObject({
    dealId: uuid,
    kind: z.enum(['zk-salt', 'zk-disclosure']),
    side: z.enum(['A', 'B']),
    pkg: z.strictObject({ suite: z.string().max(40), enc: bytes, ct: bytes }),
  }),
  signApi: z.strictObject({
    dealId: uuid,
    pairId: z.string().max(200).optional(),
    method: z.string().max(10),
    path: z.string().max(2048),
    body: bytes,
    ledgerIndex: z.int().nonnegative().max(0xffffffff),
  }),
} as const;
/** Co-signer requests (phone to second device). */
const CoSignOps = {
  commit: z.strictObject({ dealId: uuid, request: SignRequestSchema }),
  sign: z.strictObject({ session: z.string().regex(/^[0-9a-f]{32}$/), list: z.array(CommitmentSchema).length(2) }),
} as const;

type Ops = Record<string, z.ZodType>;
const requestOf = <O extends Ops>(ops: O) =>
  z.strictObject({
    legxVault: z.literal(1),
    id: z.int().nonnegative(),
    op: z.enum(Object.keys(ops) as [string, ...string[]]),
    args: z.unknown(),
  });
const Response = z.union([
  z.strictObject({ legxVault: z.literal(1), id: z.int(), ok: z.literal(true), result: z.unknown() }),
  z.strictObject({ legxVault: z.literal(1), id: z.int(), ok: z.literal(false), code: z.string().max(40) }),
]);

/** True when `data` is a message of the vault schema (requests of either op set, or a response). */
export const isVaultMessage = (data: unknown): boolean =>
  requestOf(VaultOps).safeParse(data).success ||
  requestOf(CoSignOps).safeParse(data).success ||
  isCeremonyMessage(data) ||
  Response.safeParse(data).success;

function serve<O extends Ops>(
  port: MessagePort,
  ops: O,
  handlers: { [K in keyof O]: (a: z.infer<O[K]>) => Promise<unknown> },
  consume: (data: unknown) => boolean = () => false,
) {
  port.onmessage = async (ev: MessageEvent) => {
    if (consume(ev.data)) return;
    const req = requestOf(ops).safeParse(ev.data);
    if (!req.success) return; // not ours: ignored, never echoed
    const { id, op } = req.data;
    const reply = (m: object) => port.postMessage({ legxVault: 1, id, ...m });
    const args = (ops[op] as z.ZodType).safeParse(req.data.args);
    if (!args.success) return reply({ ok: false, code: 'INPUT_INVALID' });
    try {
      reply({ ok: true, result: await handlers[op as keyof O](args.data as never) });
    } catch (err) {
      reply({ ok: false, code: err instanceof VaultError ? err.code : 'INTERNAL' }); // a code only, never a message
    }
  };
}

function client(port: MessagePort, consume: (data: unknown) => boolean = () => false) {
  let next = 0;
  const waiting = new Map<number, (r: z.infer<typeof Response>) => void>();
  port.onmessage = (ev: MessageEvent) => {
    if (consume(ev.data)) return;
    const r = Response.safeParse(ev.data);
    if (r.success) waiting.get(r.data.id)?.(r.data);
  };
  return <T>(op: string, args: object): Promise<T> =>
    new Promise((resolve, reject) => {
      const id = next++;
      waiting.set(id, (r) => {
        waiting.delete(id);
        if (r.ok) resolve(r.result as T);
        else reject(new VaultError(r.code as VaultCode));
      });
      port.postMessage({ legxVault: 1, id, op, args });
    });
}

/** Frame side: answers the app's requests with `vault`. */
export function serveVault(port: MessagePort, vault: Vault, host?: FrameHost): void {
  const ceremonies = ceremonyServer(port, vault, host);
  serve(
    port,
    VaultOps,
    {
      list: () => vault.list(),
      location: () => vault.location(),
      sign: (a) => vault.signFrost(a.dealId, a.request as SignRequest),
      signMultisig: (a) => vault.signMultisig(a.dealId, a.tx),
      signSingle: (a) => vault.signSingle(a.dealId, a.tx),
      backup: (a) => vault.backupShare2ToFile(a.dealId),
      restore: (a) => vault.restore(a.file),
      signSlot: (a) => ceremonies.signSlot(a as unknown as SlotSignRequest),
      dkg: (a) => ceremonies.dkg(a),
      refresh: (a) => ceremonies.refresh(a),
      repair: (a) => ceremonies.repair(a),
      deals: () => (host ? host.deals() : Promise.reject(new VaultError('NOT_FOUND'))),
      shellKey: (a) => (host ? host.shellKey(a.dealId) : Promise.reject(new VaultError('NOT_FOUND'))),
      signShell: (a) => (host ? host.signShell(a.dealId, a.tx) : Promise.reject(new VaultError('NOT_FOUND'))),
      enroll: (a) => (host ? host.enroll(a.dealId, a.pairId) : Promise.reject(new VaultError('NOT_FOUND'))),
      signHybrid: (a) => (host ? host.signHybrid(a.dealId, a.msg) : Promise.reject(new VaultError('NOT_FOUND'))),
      openBox: (a) =>
        host ? host.openBox(a.dealId, a.kind, a.side, a.pkg) : Promise.reject(new VaultError('NOT_FOUND')),
      pinSeal: (a) => (host ? host.pinSeal(a.dealId, a.seal) : Promise.reject(new VaultError('NOT_FOUND'))),
      loadDeal: (a) =>
        host ? host.loadDeal(a.dealId, a.data, a.exitAmountDrops) : Promise.reject(new VaultError('NOT_FOUND')),
      signerKeys: (a) => (host ? host.signerKeys(a.dealId) : Promise.reject(new VaultError('NOT_FOUND'))),
      signApi: (a) => (host ? host.signApi(a) : Promise.reject(new VaultError('NOT_FOUND'))),
    },
    ceremonies.consume,
  );
}

/** App side: the only way the app talks to the vault. */
export function connectVault(port: MessagePort) {
  const ceremonies = ceremonyClient(port);
  const call = client(port, ceremonies.consume);
  return {
    list: () => call<Awaited<ReturnType<Vault['list']>>>('list', {}),
    location: () => call<Awaited<ReturnType<Vault['location']>>>('location', {}),
    signFrost: (dealId: string, request: SignRequest) => call<Uint8Array>('sign', { dealId, request }),
    signMultisig: (dealId: string, tx: Record<string, string | number>) => call<string>('signMultisig', { dealId, tx }),
    signSingle: (dealId: string, tx: Record<string, unknown>) => call<string>('signSingle', { dealId, tx }),
    backupShare2ToFile: (dealId: string) => call<Uint8Array>('backup', { dealId }),
    restore: (file: Uint8Array) => call<{ needsShare1: boolean }>('restore', { file }),
    /** Runs the slot DKG inside the frame; the frame's relay and session calls are answered by `io`. */
    /** Makes the shell setup key (once) and returns its public key and address. */
    shellKey: (dealId: string) => call<ShellInfo>('shellKey', { dealId }),
    /** Signs one setup transaction of the shell; refuses anything that moves money. */
    signShell: (dealId: string, tx: Record<string, unknown>) => call<string>('signShell', { dealId, tx }),
    /** Makes this device's enrollment keys for the deal (once) and returns the public halves. */
    enroll: (dealId: string, pairId?: string) =>
      call<EnrollResult>('enroll', { dealId, ...(pairId === undefined ? {} : { pairId }) }),
    /** The deals this frame holds enrollment keys for (OD-35). */
    deals: () => call<string[]>('deals', {}),
    /** The `x-legx-auth` value for a request, signed inside the frame. */
    signApi: (input: SignApiInput) => call<ApiAuthValue>('signApi', input),
    /** The lawyer console's evidence signer (I-W-10): DSSE statements of this deal only, both halves together. */
    signHybrid: (dealId: string, msg: Uint8Array) => call<HybridSignature>('signHybrid', { dealId, msg }),
    /** OD-32: opens the salt or disclosure box of this lawyer's own client; the X-Wing key stays in the frame. */
    openBox: (dealId: string, kind: 'zk-salt' | 'zk-disclosure', side: 'A' | 'B', pkg: SealedPackage) =>
      call<Uint8Array>('openBox', { dealId, kind, side, pkg }),
    /** OD-36: pins the seal when the key joins the deal. */
    pinSeal: (dealId: string, seal: string) => call<undefined>('pinSeal', { dealId, seal }),
    /** OD-36: the frame recomputes the seal over this data and keeps it only if it is the pinned one. */
    loadDeal: (dealId: string, data: unknown, exitAmountDrops: string) =>
      call<undefined>('loadDeal', { dealId, data, exitAmountDrops }),
    signerKeys: (dealId: string) => call<HybridPublicKeys>('signerKeys', { dealId }),
    /** A lawyer slot signs in the frame with the firm HSM as holder 2; the lawyer's approval is over the hash of the bytes. */
    signSlot: (args: SlotSignRequest, io: Pick<CeremonyIo, 'relay' | 'start'>) =>
      ceremonies.use({ ...io, sessions: () => Promise.reject(new VaultError('NOT_FOUND')) }, () =>
        call<Uint8Array>('signSlot', args),
      ),
    dkg: (args: DkgRequest, io: CeremonyIo) => ceremonies.use(io, () => call<FrameDkgResult>('dkg', args)),
    /** Refreshes this device's shares inside the frame; resolves with the public `frost.refreshed` record. */
    refresh: (args: RefreshRequest, io: CeremonyIo) => ceremonies.use(io, () => call<FrostRefreshed>('refresh', args)),
    /** Share repair inside the frame: nothing but public messages and a status leave it. */
    repair: (args: RepairRequest, io: CeremonyIo) => ceremonies.use(io, () => call<{ repaired: true }>('repair', args)),
  };
}

/** Second device side: serves its co-signer on a port (the relay transport and its HPKE are task 4.7). */
export function serveCoSigner(port: MessagePort, cosigner: CoSignerPort): void {
  serve(port, CoSignOps, {
    commit: (a) => cosigner.commit(a as { dealId: string; request: SignRequest }),
    sign: (a) => cosigner.sign(a.session, a.list),
  });
}

/** Phone side: a co-signer port over a MessagePort. */
export function connectCoSigner(port: MessagePort): CoSignerPort {
  const call = client(port);
  return { commit: (req) => call('commit', req), sign: (session, list) => call('sign', { session, list }) };
}
