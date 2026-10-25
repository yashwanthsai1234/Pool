// The key vault (DESIGN 6.4, IMPLEMENTATION 4.2). It stores a slot's FROST shares encrypted in IndexedDB, under the
// name `dealId:role:slot`, and only signs inside `signFrost`:
// - share 1 (phone or console) under a fresh non-extractable AES-GCM device key;
// - share 2 under a key from the WebAuthn PRF of a separate authenticator (or, without PRF, a recovery code); or
//   held by a remote holder (the client's second device, the firm HSM) that computes its own signature share;
// - the identity salt (DESIGN 6.2) with share 2.
// A raw share exists only inside one call (store, sign, restore, repair install) and is zeroed before it returns,
// on every path. Nothing is cached between calls. The vault is bound to one party role (P4.2-04).
// Source: https://www.rfc-editor.org/rfc/rfc9591 (sections 5.1 to 5.3, 7.3 nonce rules, 7.7 message validation)
import { DealId } from '@legx/contracts/values';
import { tupleHash } from '@legx/core/dealcore';
import {
  aggregateChecked,
  type CheckResult,
  type Commitment,
  FrostError,
  holderId,
  idScalar,
  type KeyShare,
  mulBase,
  parsePoint,
  parseScalar,
  SigningSession,
  type SlotName,
  type SlotPublic,
  slotAddress,
} from '@legx/core/frost';
import { messageAllowed, type SealedDeal, type SignRequest } from '@legx/core/frostRules';
import { equalBytes } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { encode, encodeForMultiSigning, encodeForSigning, type Transaction } from 'xrpl';
import {
  aad,
  keyFromCode,
  keyFromPrf,
  newDeviceKey,
  open,
  PBKDF2_ITERATIONS,
  type Sealed,
  seal,
  wipe,
} from './aead.ts';
import { type Confirmation, confirmationFor } from './confirmation.ts';
import { VaultError } from './errors.ts';
import { decodeFile, encodeFile, type FileLock } from './file.ts';
import type { PrfCredential, PrfSource } from './prf.ts';
import { codeBytes, newRecoveryCode } from './recoveryCode.ts';
import { checkModeForRole, type PartyRole, type Share2Mode, SINGLE_DEVICE_LABEL, SLOT_OF } from './rules.ts';
import { Store } from './store.ts';

export type StorageContext = 'home-screen' | 'browser-tab';

/** A holder that computes its own signature share: the client's second device or the firm HSM (DESIGN 6.4). */
export interface CoSignerPort {
  /** Round 1. The holder decodes the request, checks it against its own seal and asks its human to approve. */
  commit(req: { dealId: string; request: SignRequest }): Promise<{ session: string; commitment: Commitment }>;
  /** Round 2, once per session. */
  sign(session: string, list: Commitment[]): Promise<Uint8Array>;
}

/**
 * A remote holder chosen for one call (the frame's slot signing, I-W-10): it is built with the function that derives the bytes
 * the vault will sign, and the vault still checks the request against the seal before it asks that holder anything.
 */
export type RemoteVia = (messageOf: (request: SignRequest) => Uint8Array) => CoSignerPort;

export type VaultDeps = {
  role: PartyRole;
  /** The seal this frame verified itself (task 4.3 decode-and-check); every request is checked against it. */
  deals: (dealId: string) => Promise<SealedDeal>;
  /** One IndexedDB per storage partition (default `legx-vault`). */
  dbName?: string;
  prf?: PrfSource;
  /** Frame UI: asks the client to type the recovery code. */
  askRecoveryCode?: () => Promise<string>;
  /** Frame UI: shows a new recovery code once. The code never leaves this callback. */
  showRecoveryCode?: (code: string) => void | Promise<void>;
  /** The remote holder of share 2 for `second-device` and `firm-hsm` modes (tasks 4.7, 3.10). */
  cosigner?: (dealId: string) => CoSignerPort;
  /** Frame UI on the second device: approve this request? (P4.2-14) */
  approve?: (dealId: string, request: SignRequest) => Promise<boolean>;
  /** Frame UI: shows what a shipment or receipt signs and asks the client to confirm (OD-37). Without it those requests are refused. */
  confirm?: (dealId: string, what: Confirmation) => Promise<boolean>;
  context?: () => StorageContext;
};

type Lock =
  | { kind: 'device'; key: CryptoKey }
  | { kind: 'prf'; credential: PrfCredential; prfInput: Uint8Array }
  | { kind: 'code'; kdfSalt: Uint8Array; iterations: number };
type Held = { identifier: string; lock: Lock; share: Sealed; salt?: Sealed };
type Entry = {
  id: string; // dealId:role:slot
  role: PartyRole;
  dealId: string;
  slot: SlotName;
  pub: SlotPublic;
  mode: Share2Mode;
  device: 'primary' | 'second'; // `second`: this is the client's second device, holding share 2 itself
  context: StorageContext;
  local?: Held; // share 1 on the primary device, share 2 on the second device; device lock
  share2?: Held; // PRF or recovery-code lock (primary device only)
  /** The shares before an unfinished refresh (task 4.7): kept until every holder confirmed, or restored on an abort. */
  previous?: { pub: SlotPublic; local?: Held; share2?: Held };
};

export type Share2Input =
  | { mode: 'security-key'; credential: PrfCredential; share: KeyShare }
  | { mode: 'single-device'; credential: PrfCredential; share: KeyShare; acceptedWarning: boolean }
  | { mode: 'recovery-code'; share: KeyShare }
  | { mode: 'second-device' }
  | { mode: 'firm-hsm' };

type LocalShare2 = Extract<Share2Input, { share: KeyShare }>;

export type EntrySummary = {
  dealId: string;
  slot: SlotName;
  mode: Share2Mode;
  device: 'primary' | 'second';
  context: StorageContext;
  hasShare1: boolean;
  label?: string;
};

const detectContext = (): StorageContext =>
  matchMedia('(display-mode: standalone)').matches || (navigator as { standalone?: boolean }).standalone === true
    ? 'home-screen'
    : 'browser-tab';

const CONTEXT_NAME: Record<StorageContext, string> = { 'home-screen': 'home-screen app', 'browser-tab': 'browser tab' };
const OTHER_CONTEXT: Record<StorageContext, StorageContext> = {
  'home-screen': 'browser-tab',
  'browser-tab': 'home-screen',
};

/** The share must be the expected holder's and match its verifying share. */
function checkShare(pub: SlotPublic, s: KeyShare, holder: number): void {
  const vs = pub.verifyingShares[s.identifier];
  try {
    if (s.identifier !== holderId(holder) || !vs || !mulBase(parseScalar(s.signingShare)).equals(parsePoint(vs)))
      throw new VaultError('SHARE_INVALID');
  } catch {
    throw new VaultError('SHARE_INVALID');
  }
}

/** The exact bytes the slot signs for a request; the allow-list (task 1.15) then compares them with the seal. */
export function messageFor(pub: SlotPublic, req: SignRequest): Uint8Array {
  try {
    if (req.kind === 'xrpl-multisign')
      return hexToBytes(encodeForMultiSigning(req.tx as unknown as Transaction, slotAddress(pub)));
    if (req.kind === 'xrpl-single') return hexToBytes(encodeForSigning(req.tx as unknown as Transaction));
    if (req.kind === 'tagged') return tupleHash(req.tag, req.parts);
    return sha256(req.envelope);
  } catch {
    throw new VaultError('MESSAGE_REFUSED');
  }
}

/** Maps a core FROST error to a vault code (the details stay inside the frame). */
const frostCode = (err: unknown, fallback: 'SHARE_INVALID' | 'SIGNATURE_INVALID'): VaultError =>
  err instanceof VaultError
    ? err
    : new VaultError(err instanceof FrostError && err.code === 'MESSAGE_REFUSED' ? 'MESSAGE_REFUSED' : fallback);

export function createVault(deps: VaultDeps) {
  const role = deps.role;
  const slot = SLOT_OF[role];
  const store = new Store(deps.dbName ?? 'legx-vault');
  const context = deps.context ?? detectContext;
  const nameOf = (dealId: string): string => {
    if (!DealId.safeParse(dealId).success) throw new VaultError('INPUT_INVALID');
    return `${dealId}:${role}:${slot}`;
  };

  async function entry(dealId: string): Promise<Entry> {
    const e = await store.get<Entry>('entries', nameOf(dealId));
    if (!e) throw new VaultError('NOT_FOUND');
    return e;
  }

  /** The key that opens a held share: the device key, a PRF tap, or the typed recovery code. */
  async function keyFor(e: Entry, h: Held): Promise<CryptoKey> {
    const lock = h.lock;
    if (lock.kind === 'device') return lock.key;
    if (lock.kind === 'prf') {
      if (!deps.prf) throw new VaultError('PASSKEY_REQUIRED');
      const prf = await deps.prf.evaluate(lock.credential, lock.prfInput).catch(() => {
        throw new VaultError('PASSKEY_REQUIRED');
      });
      try {
        return await keyFromPrf(prf, e.dealId, e.slot);
      } finally {
        prf.fill(0);
      }
    }
    const typed = await deps.askRecoveryCode?.().catch(() => undefined);
    if (typed === undefined) throw new VaultError('PASSKEY_REQUIRED');
    const code = codeBytes(typed);
    try {
      return await keyFromCode(code, lock.kdfSalt, lock.iterations);
    } finally {
      code.fill(0);
    }
  }

  /** Opens one field of a held share; a code lock that fails means a wrong code. */
  async function openHeld(e: Entry, h: Held, key: CryptoKey, field: 'share' | 'salt'): Promise<Uint8Array> {
    const sealed = field === 'share' ? h.share : h.salt;
    if (!sealed) throw new VaultError('NOT_FOUND');
    const which = h === e.local ? 'local' : 'share2';
    return open(key, sealed, aad(e.id, `${which}:${field}`)).catch((err: unknown) => {
      throw h.lock.kind === 'code' ? new VaultError('RECOVERY_CODE_WRONG') : err;
    });
  }

  async function sealHeld(
    id: string,
    which: 'local' | 'share2',
    lock: Lock,
    key: CryptoKey,
    s: KeyShare,
    salt?: Uint8Array,
  ): Promise<Held> {
    const share = await seal(key, s.signingShare, aad(id, `${which}:share`));
    if (!salt) return { identifier: s.identifier, lock, share };
    if (salt.length !== 32) throw new VaultError('INPUT_INVALID');
    return { identifier: s.identifier, lock, share, salt: await seal(key, salt, aad(id, `${which}:salt`)) };
  }

  /** Locks share 2 under the chosen mode: a PRF tap, or a new recovery code shown once. */
  async function lockShare2(e: Entry, input: LocalShare2, salt?: Uint8Array): Promise<Held> {
    if (input.mode === 'recovery-code') {
      if (!deps.showRecoveryCode) throw new VaultError('INPUT_INVALID');
      const typed = newRecoveryCode();
      const lock: Lock = {
        kind: 'code',
        kdfSalt: crypto.getRandomValues(new Uint8Array(16)),
        iterations: PBKDF2_ITERATIONS,
      };
      const code = codeBytes(typed);
      let key: CryptoKey;
      try {
        key = await keyFromCode(code, lock.kdfSalt, lock.iterations);
      } finally {
        code.fill(0);
      }
      const held = await sealHeld(e.id, 'share2', lock, key, input.share, salt);
      await deps.showRecoveryCode(typed);
      return held;
    }
    const lock: Lock = {
      kind: 'prf',
      credential: input.credential,
      prfInput: crypto.getRandomValues(new Uint8Array(32)),
    };
    const held: Held = {
      identifier: input.share.identifier,
      lock,
      share: { iv: new Uint8Array(), ct: new Uint8Array() },
    };
    return sealHeld(e.id, 'share2', lock, await keyFor(e, held), input.share, salt);
  }

  /** Asks the browser not to evict the vault's storage; the caller shows the result (P4.2-09). */
  const persist = (): Promise<boolean> =>
    navigator.storage?.persist ? navigator.storage.persist().catch(() => false) : Promise.resolve(false);

  const newEntry = (dealId: string, pub: SlotPublic, mode: Share2Mode, device: Entry['device']): Entry => ({
    id: nameOf(dealId),
    role,
    dealId,
    slot,
    pub,
    mode,
    device,
    context: context(),
  });

  /** Signs with the local share 1 and a remote holder's share; share 1 is opened only after the holder commits. */
  async function signRemote(e: Entry, local: Held, req: SignRequest, msg: Uint8Array, check: Check, via?: RemoteVia) {
    const port = via ? via((r) => messageFor(e.pub, r)) : deps.cosigner?.(e.dealId);
    if (!port) throw new VaultError('APPROVAL_REFUSED');
    const remote = await port.commit({ dealId: e.dealId, request: req }).catch(() => {
      throw new VaultError('APPROVAL_REFUSED');
    });
    const s1 = await openHeld(e, local, await keyFor(e, local), 'share');
    let list: Commitment[];
    let z1: Uint8Array;
    try {
      const a = SigningSession.open({ identifier: local.identifier, signingShare: s1 }, e.pub, msg);
      list = [a.commitment, remote.commitment];
      z1 = a.signShare(msg, list, check);
    } catch (err) {
      throw frostCode(err, 'SHARE_INVALID');
    } finally {
      s1.fill(0);
    }
    const z2 = await port.sign(remote.session, list).catch(() => {
      throw new VaultError('APPROVAL_REFUSED');
    });
    try {
      return aggregateChecked(e.pub, list, msg, { [local.identifier]: z1, [remote.commitment.identifier]: z2 });
    } catch (err) {
      throw frostCode(err, 'SIGNATURE_INVALID');
    }
  }

  /** Both shares on this device: share 2's key first (the tap), then both shares, both signers, aggregate. */
  async function signLocal(e: Entry, local: Held, share2: Held, msg: Uint8Array, check: Check) {
    const k2 = await keyFor(e, share2); // PASSKEY_REQUIRED here means no share was decrypted (P4.2-07)
    const bufs: Uint8Array[] = [];
    try {
      const s1 = await openHeld(e, local, await keyFor(e, local), 'share');
      bufs.push(s1);
      const s2 = await openHeld(e, share2, k2, 'share');
      bufs.push(s2);
      let a: SigningSession;
      let b: SigningSession;
      try {
        a = SigningSession.open({ identifier: local.identifier, signingShare: s1 }, e.pub, msg);
        b = SigningSession.open({ identifier: share2.identifier, signingShare: s2 }, e.pub, msg);
      } catch (err) {
        throw frostCode(err, 'SHARE_INVALID');
      }
      try {
        const list = [a.commitment, b.commitment]; // nonces stay inside the two sessions, used once
        const shares = {
          [local.identifier]: a.signShare(msg, list, check),
          [share2.identifier]: b.signShare(msg, list, check),
        };
        return aggregateChecked(e.pub, list, msg, shares); // verifyShare each, aggregate, strict verify
      } catch (err) {
        throw frostCode(err, 'SIGNATURE_INVALID');
      }
    } finally {
      wipe(...bufs);
    }
  }

  type Check = (m: Uint8Array) => CheckResult;

  /** The bytes this vault derives from the request, and the check that they are allowed for the sealed deal and this slot. */
  async function derive(e: Entry, dealId: string, request: SignRequest): Promise<{ msg: Uint8Array; check: Check }> {
    const deal = await deps.deals(dealId);
    const msg = messageFor(e.pub, request);
    const check: Check = (m) => messageAllowed(request, m, deal, e.slot);
    if (!check(msg).ok) throw new VaultError('MESSAGE_REFUSED');
    const what = confirmationFor(request);
    if (what && !(await deps.confirm?.(dealId, what).catch(() => false))) throw new VaultError('APPROVAL_REFUSED');
    return { msg, check };
  }

  /** Pending second-device sessions: each holds its share only until round 2 or the timeout, then zeroes it. */
  const pending = new Map<
    string,
    { session: SigningSession; share: Uint8Array; msg: Uint8Array; check: Check; timer: ReturnType<typeof setTimeout> }
  >();
  const COSIGN_TIMEOUT_MS = 120_000;
  const drop = (id: string) => {
    const p = pending.get(id);
    if (!p) return undefined;
    clearTimeout(p.timer);
    pending.delete(id);
    return p;
  };

  const api = {
    /**
     * Stores a slot's shares (P4.2-01). Inputs are zeroed on every path. Returns whether the browser granted
     * persistent storage, which the share screen shows (P4.2-09), and the single-device label when it applies.
     */
    async storeShares(input: {
      dealId: string;
      pub: SlotPublic;
      share1: KeyShare;
      share2: Share2Input;
      identitySalt?: Uint8Array;
    }): Promise<{ persisted: boolean; mode: Share2Mode; label?: string }> {
      const s2: LocalShare2 | undefined = 'share' in input.share2 ? input.share2 : undefined;
      try {
        const mode = input.share2.mode;
        checkModeForRole(role, mode);
        if (input.share2.mode === 'single-device' && input.share2.acceptedWarning !== true)
          throw new VaultError('SINGLE_DEVICE_NOT_ACCEPTED');
        checkShare(input.pub, input.share1, 1);
        if (s2) checkShare(input.pub, s2.share, 2);
        const e = newEntry(input.dealId, input.pub, mode, 'primary');
        // The identity salt stays with share 2; with a remote share 2 the second device keeps it (DESIGN 6.2).
        if (input.identitySalt && !s2) throw new VaultError('INPUT_INVALID');
        if (s2) e.share2 = await lockShare2(e, s2, input.identitySalt);
        const key = await newDeviceKey();
        e.local = await sealHeld(e.id, 'local', { kind: 'device', key }, key, input.share1);
        await store.put('entries', e);
        const persisted = await persist();
        return mode === 'single-device' ? { persisted, mode, label: SINGLE_DEVICE_LABEL } : { persisted, mode };
      } finally {
        wipe(input.share1.signingShare, s2?.share.signingShare, input.identitySalt);
      }
    },

    /** On the client's second device: stores share 2 (and the identity salt) under this device's own key. */
    async storeSecondDeviceShare(input: {
      dealId: string;
      pub: SlotPublic;
      share: KeyShare;
      identitySalt?: Uint8Array;
    }) {
      try {
        checkModeForRole(role, 'second-device');
        checkShare(input.pub, input.share, 2);
        const e = newEntry(input.dealId, input.pub, 'second-device', 'second');
        const key = await newDeviceKey();
        e.local = await sealHeld(e.id, 'local', { kind: 'device', key }, key, input.share, input.identitySalt);
        await store.put('entries', e);
        return { persisted: await persist() };
      } finally {
        wipe(input.share.signingShare, input.identitySalt);
      }
    },

    /**
     * Signs one allow-listed request with shares 1 and 2 (P4.2-02). The bytes are derived here from the request
     * and checked against the seal before any key is touched; the result verifies strictly under the slot key.
     */
    async signFrost(dealId: string, request: SignRequest, via?: RemoteVia): Promise<Uint8Array> {
      const e = await entry(dealId);
      if (e.device !== 'primary') throw new VaultError('INPUT_INVALID');
      if (!e.local) throw new VaultError('NO_SHARE_1');
      const { msg, check } = await derive(e, dealId, request);
      return e.share2 ? signLocal(e, e.local, e.share2, msg, check) : signRemote(e, e.local, request, msg, check, via);
    },

    /** An XRPL multisign signature over `encodeForMultiSigning(tx, slotAddress)`, as uppercase hex. */
    async signMultisig(dealId: string, tx: Record<string, unknown>): Promise<string> {
      return bytesToHex(await api.signFrost(dealId, { kind: 'xrpl-multisign', tx })).toUpperCase();
    },

    /**
     * Step 5f (OD-33): the client's account is the slot account, so the acceptance is single-signed by the FROST pair. Only the
     * sealed `CredentialAccept` passes the allow-list. Returns the signed transaction blob, uppercase hex.
     */
    async signSingle(dealId: string, tx: Record<string, unknown>): Promise<string> {
      const sig = await api.signFrost(dealId, { kind: 'xrpl-single', tx });
      return encode({ ...tx, TxnSignature: bytesToHex(sig).toUpperCase() } as unknown as Transaction);
    },

    /** The second device's side of signing (P4.2-14): share 2 never leaves this device. */
    cosigner(): CoSignerPort {
      return {
        async commit({ dealId, request }) {
          const e = await entry(dealId);
          if (e.device !== 'second' || !e.local) throw new VaultError('INPUT_INVALID');
          const { msg, check } = await derive(e, dealId, request);
          if (!(await deps.approve?.(dealId, request).catch(() => false))) throw new VaultError('APPROVAL_REFUSED');
          const share = await openHeld(e, e.local, await keyFor(e, e.local), 'share');
          let session: SigningSession;
          try {
            session = SigningSession.open({ identifier: e.local.identifier, signingShare: share }, e.pub, msg);
          } catch (err) {
            share.fill(0);
            throw frostCode(err, 'SHARE_INVALID');
          }
          const id = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
          const timer = setTimeout(() => drop(id)?.share.fill(0), COSIGN_TIMEOUT_MS);
          pending.set(id, { session, share, msg, check, timer });
          return { session: id, commitment: session.commitment };
        },
        async sign(id, list) {
          const p = drop(id);
          if (!p) throw new VaultError('NOT_FOUND');
          try {
            return p.session.signShare(p.msg, list, p.check);
          } catch (err) {
            throw frostCode(err, 'SIGNATURE_INVALID');
          } finally {
            p.share.fill(0);
          }
        },
      };
    },

    /** The share-2 ciphertext as a file (PRF or recovery-code lock, with the identity salt). Opens nothing. */
    async backupShare2ToFile(dealId: string): Promise<Uint8Array> {
      const e = await entry(dealId);
      const h = e.share2;
      if (!h || h.lock.kind === 'device') throw new VaultError('NOT_FOUND');
      return encodeFile({
        id: e.id,
        mode: e.mode,
        pub: e.pub,
        identifier: h.identifier,
        lock: h.lock,
        share: h.share,
        salt: h.salt,
      });
    },

    /**
     * Restores share 2 from a file (P4.2-05, P4.2-06, P4.2-13): unlocks it (tap or code), checks it against the
     * slot's verifying share, and stores the same ciphertext. Nothing is written when anything fails.
     */
    async restore(file: Uint8Array): Promise<{ needsShare1: boolean }> {
      const f = decodeFile(file);
      const [dealId] = f.id.split(':');
      if (dealId === undefined || f.id !== nameOf(dealId)) throw new VaultError('ROLE_REFUSED');
      checkModeForRole(role, f.mode);
      const existing = await store.get<Entry>('entries', f.id);
      const e: Entry = existing ?? newEntry(dealId, f.pub, f.mode, 'primary');
      const lock: FileLock = f.lock;
      const held: Held = { identifier: f.identifier, lock, share: f.share, ...(f.salt ? { salt: f.salt } : {}) };
      const key = await keyFor(e, held);
      const bufs: Uint8Array[] = [];
      try {
        e.share2 = held;
        const s = await openHeld(e, held, key, 'share');
        bufs.push(s);
        if (held.salt) bufs.push(await openHeld(e, held, key, 'salt'));
        checkShare(e.pub, { identifier: held.identifier, signingShare: s }, 2);
      } finally {
        wipe(...bufs);
      }
      e.mode = f.mode;
      await store.put('entries', e);
      return { needsShare1: !e.local };
    },

    /** Installs a repaired share 1 (task 4.7 repair) under a fresh device key. The input is zeroed. */
    async installShare1(dealId: string, share1: KeyShare): Promise<void> {
      try {
        const e = await entry(dealId);
        checkShare(e.pub, share1, 1);
        const key = await newDeviceKey();
        e.local = await sealHeld(e.id, 'local', { kind: 'device', key }, key, share1);
        await store.put('entries', e);
      } finally {
        share1.signingShare.fill(0);
      }
    },

    /**
     * Share refresh (task 4.7, DESIGN 6.4): opens this device's shares (share 2 after the tap), lends them to `run`
     * (the refresh protocol in `frost/refresh.ts`), and stores the new shares under the same locks with the new
     * verifying shares. The old ciphertexts stay until `endRefresh` (ZF: delete old shares only once every holder
     * refreshed). Nothing changes when `run` throws or returns shares that do not match. Every buffer is zeroed.
     */
    async refreshShares(
      dealId: string,
      run: (shares: KeyShare[], pub: SlotPublic) => Promise<{ pub: SlotPublic; shares: KeyShare[] }>,
    ): Promise<void> {
      const e = await entry(dealId);
      if (!e.local) throw new VaultError('NO_SHARE_1');
      if (e.previous) throw new VaultError('INPUT_INVALID'); // the last refresh is not finished
      const local = e.local;
      const held = e.share2 ? [local, e.share2] : [local];
      const keys = await Promise.all(held.map((h) => keyFor(e, h)));
      const bufs: Uint8Array[] = [];
      try {
        const old: KeyShare[] = [];
        for (const [i, h] of held.entries()) {
          const s = await openHeld(e, h, keys[i] as CryptoKey, 'share');
          bufs.push(s);
          old.push({ identifier: h.identifier, signingShare: s });
        }
        const out = await run(old, e.pub);
        for (const s of out.shares) bufs.push(s.signingShare);
        if (out.shares.length !== held.length || !out.shares.every((s, i) => s.identifier === held[i]?.identifier))
          throw new VaultError('SHARE_INVALID');
        for (const s of out.shares) checkShare(out.pub, s, Number(idScalar(s.identifier)));
        if (!equalBytes(out.pub.commitments[0] as Uint8Array, e.pub.commitments[0] as Uint8Array))
          throw new VaultError('SHARE_INVALID'); // a refresh never changes the group key
        const next: Entry = {
          ...e,
          pub: out.pub,
          previous: { pub: e.pub, local, ...(e.share2 ? { share2: e.share2 } : {}) },
        };
        const reseal = async (which: 'local' | 'share2', h: Held, key: CryptoKey, s: KeyShare): Promise<Held> => ({
          ...h,
          share: await seal(key, s.signingShare, aad(e.id, `${which}:share`)),
        });
        next.local = await reseal('local', local, keys[0] as CryptoKey, out.shares[0] as KeyShare);
        if (e.share2) next.share2 = await reseal('share2', e.share2, keys[1] as CryptoKey, out.shares[1] as KeyShare);
        await store.put('entries', next);
      } finally {
        wipe(...bufs);
      }
    },

    /**
     * Ends a refresh: `new` when every holder's deletion statement is in (the old ciphertexts are dropped; nobody can
     * prove a deletion, so this is hygiene, not revocation); `old` when another holder aborted (the old shares return).
     */
    async endRefresh(dealId: string, keep: 'new' | 'old'): Promise<void> {
      const e = await entry(dealId);
      const prev = e.previous;
      if (!prev) return;
      const { previous: _dropped, ...rest } = e;
      await store.put('entries', keep === 'new' ? rest : { ...rest, ...prev });
    },

    /**
     * Share repair (task 4.7, DESIGN 6.4): lends this device's share (share 2 on a new phone restored from its file, or
     * the second device's share) to `run` (the helper's side in `frost/repair.ts`). When `run` returns a repaired share
     * 1 for this device, it is checked against its verifying share and installed under a fresh device key.
     */
    async repairShare(
      dealId: string,
      run: (helperShare: KeyShare, pub: SlotPublic) => Promise<KeyShare | undefined>,
    ): Promise<void> {
      const e = await entry(dealId);
      const h = e.device === 'second' ? e.local : e.share2;
      if (!h) throw new VaultError('NOT_FOUND');
      const s = await openHeld(e, h, await keyFor(e, h), 'share');
      let repaired: KeyShare | undefined;
      try {
        repaired = await run({ identifier: h.identifier, signingShare: s }, e.pub);
      } finally {
        s.fill(0);
      }
      if (repaired) await api.installShare1(dealId, repaired);
    },

    /** Lends the identity salt (kept with share 2, DESIGN 6.2) to `use` inside the frame, then zeroes it. */
    async withIdentitySalt<T>(dealId: string, use: (salt: Uint8Array) => Promise<T>): Promise<T> {
      const e = await entry(dealId);
      const h = e.device === 'second' ? e.local : e.share2;
      if (!h?.salt) throw new VaultError('NOT_FOUND');
      const salt = await openHeld(e, h, await keyFor(e, h), 'salt');
      try {
        return await use(salt);
      } finally {
        salt.fill(0);
      }
    },

    /** This role's entries only (P4.2-04), with the single-device label where it applies. */
    async list(): Promise<EntrySummary[]> {
      return (await store.byRole<Entry>('entries', role)).map((e) => ({
        dealId: e.dealId,
        slot: e.slot,
        mode: e.mode,
        device: e.device,
        context: e.context,
        hasShare1: e.device === 'primary' && e.local !== undefined,
        ...(e.mode === 'single-device' ? { label: SINGLE_DEVICE_LABEL } : {}),
      }));
    },

    /** Which storage context holds the shares, in words for the screen (P4.2-13, iOS home-screen apps). */
    async location(): Promise<{ context: StorageContext; entries: number; message: string }> {
      const here = context();
      const entries = (await store.byRole<Entry>('entries', role)).length;
      const other = CONTEXT_NAME[OTHER_CONTEXT[here]];
      const message = entries
        ? `Your shares are saved in this ${CONTEXT_NAME[here]}. The ${other} cannot see them; use a recovery file to move them.`
        : `No shares are saved in this ${CONTEXT_NAME[here]}. If you set up the deal in the ${other}, open it there or restore a recovery file here.`;
      return { context: here, entries, message };
    },

    close: () => store.close(),
  };
  return api;
}

export type Vault = ReturnType<typeof createVault>;
