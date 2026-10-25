// Test helpers: FROST slots from noble's DKG rounds, a fake PRF authenticator (HMAC), a sealed deal, and a
// deep byte search used by the leak tests.
import {
  holderId,
  type KeyShare,
  type SlotName,
  type SlotPublic,
  slotAddress,
  slotPubkey,
  THRESHOLD,
} from '@legx/core/frost';
import type { SealedDeal, SignRequest } from '@legx/core/frostRules';
import { ed25519_FROST } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { vi } from 'vitest';
import { VaultError } from '../src/errors.ts';
import type { PrfSource } from '../src/prf.ts';

/** A 2-of-3 slot from noble's three DKG rounds, without transport (transport is task 1.15 / 4.7). */
export function makeSlot(): { pub: SlotPublic; shares: [KeyShare, KeyShare, KeyShare] } {
  const ids = [1, 2, 3].map(holderId);
  const r1 = ids.map((id) => ed25519_FROST.DKG.round1(id, THRESHOLD));
  const others = <T>(xs: T[], i: number) => xs.filter((_, j) => j !== i);
  const r2 = r1.map((p, i) =>
    ed25519_FROST.DKG.round2(
      p.secret,
      others(r1, i).map((x) => x.public),
    ),
  );
  const keys = ids.map((id, i) =>
    ed25519_FROST.DKG.round3(
      (r1[i] as (typeof r1)[number]).secret,
      others(r1, i).map((x) => x.public),
      others(r2, i).map((m) => m[id] as (typeof m)[string]),
    ),
  );
  const pub = (keys[0] as (typeof keys)[number]).public;
  const [a, b, c] = keys.map((k) => ({ identifier: k.secret.identifier, signingShare: k.secret.signingShare }));
  if (!a || !b || !c) throw new Error('DKG');
  return { pub, shares: [a, b, c] };
}

export const copy = (s: KeyShare): KeyShare => ({ identifier: s.identifier, signingShare: s.signingShare.slice() });

/** A UUIDv7 deal id (the contracts `DealId`). */
export function dealId(): string {
  const b = randomBytes(16);
  const ms = BigInt(Date.now());
  for (let i = 0; i < 6; i++) b[i] = Number((ms >> BigInt(8 * (5 - i))) & 0xffn);
  b[6] = ((b[6] as number) & 0x0f) | 0x70;
  b[8] = ((b[8] as number) & 0x3f) | 0x80;
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** A sealed deal in which `slot` is the given FROST group key; the other slots get unrelated keys. */
export function sealedDeal(pub: SlotPublic, slot: SlotName = 'A'): SealedDeal {
  const other = () => slotPubkey(makeSlot().pub);
  const slotPubs = { A: other(), B: other(), LA: other(), LB: other() };
  slotPubs[slot] = slotPubkey(pub);
  return {
    walletAddress: slotAddress(makeSlot().pub),
    contractRoot: randomBytes(32),
    payoutA: { account: slotAddress(makeSlot().pub) },
    payoutB: { account: slotAddress(makeSlot().pub), tag: 7 },
    exitAmountDrops: '25000000',
    maxFeeDrops: '1000',
    slotPubs,
  };
}

/** The binding statement (DESIGN 6.5), always on the allow-list for its own slot. */
export const binding = (deal: SealedDeal, slot: SlotName, c = randomBytes(32)): SignRequest => ({
  kind: 'tagged',
  tag: 'legx/binding/v1',
  parts: [deal.contractRoot, c, deal.slotPubs[slot], new TextEncoder().encode(slot)],
});

/** The exit payment to Bob, an allowed multisign transaction. */
export const exitPayment = (deal: SealedDeal) => ({
  TransactionType: 'Payment',
  Account: deal.walletAddress,
  Destination: deal.payoutB.account,
  DestinationTag: deal.payoutB.tag,
  Amount: deal.exitAmountDrops,
  Fee: '12',
  Sequence: 5,
  SigningPubKey: '',
});

/** A fake PRF authenticator: HMAC-SHA256 under its own secret. `outputs` are the buffers it handed out. */
export function fakePrf(opts: { fail?: boolean } = {}) {
  const secret = randomBytes(32);
  const outputs: Uint8Array[] = [];
  const copies: Uint8Array[] = []; // what the outputs held, for the leak searches
  const state = { fail: opts.fail ?? false, calls: 0 };
  const source: PrfSource = {
    async register() {
      return { credential: { id: bytesToHex(randomBytes(16)), transports: ['usb'] }, prf: true };
    },
    async evaluate(credential, input) {
      state.calls++;
      if (state.fail) throw new VaultError('PASSKEY_REQUIRED');
      const out = hmac(sha256, secret, new Uint8Array([...new TextEncoder().encode(credential.id), ...input]));
      outputs.push(out);
      copies.push(out.slice());
      return out;
    },
  };
  return { source, outputs, copies, state };
}

/** True when any needle (raw bytes, or its hex) appears anywhere inside `hay` (deep, including typed arrays). */
export function containsSecret(hay: unknown, needles: readonly Uint8Array[], seen = new Set<unknown>()): boolean {
  if (hay === null || hay === undefined || seen.has(hay)) return false;
  if (typeof hay === 'string') return needles.some((n) => hay.toLowerCase().includes(bytesToHex(n)));
  if (typeof hay !== 'object' && typeof hay !== 'function') return false;
  seen.add(hay);
  const bytes =
    hay instanceof ArrayBuffer
      ? new Uint8Array(hay)
      : ArrayBuffer.isView(hay)
        ? new Uint8Array(hay.buffer, hay.byteOffset, hay.byteLength)
        : undefined;
  if (bytes) return needles.some((n) => indexOf(bytes, n) >= 0);
  if (hay instanceof MessagePort || hay instanceof CryptoKey) return false;
  try {
    return (
      Object.values(hay as object).some((v) => containsSecret(v, needles, seen)) ||
      (hay instanceof Map && [...hay.values()].some((v) => containsSecret(v, needles, seen)))
    );
  } catch {
    return false;
  }
}

function indexOf(hay: Uint8Array, n: Uint8Array): number {
  outer: for (let i = 0; i + n.length <= hay.length; i++) {
    for (let j = 0; j < n.length; j++) if (hay[i + j] !== n[j]) continue outer;
    return i;
  }
  return -1;
}

/** Rewrites raw rows of a vault database (tamper tests): `edit` gets every row by id and returns the rows to put. */
export async function tamper(
  dbName: string,
  edit: (rows: Record<string, Record<string, unknown>>) => Record<string, unknown>[],
): Promise<void> {
  const rows = Object.fromEntries(
    ((await rawRows(dbName)) as Record<string, unknown>[]).map((r) => [r.id as string, r]),
  );
  const db = await openDb(dbName);
  await new Promise((resolve) => {
    const t = db.transaction('entries', 'readwrite');
    for (const r of edit(rows)) t.objectStore('entries').put(r);
    t.oncomplete = resolve;
  });
  db.close();
}

const openDb = (dbName: string) =>
  new Promise<IDBDatabase>((res, rej) => {
    const r = indexedDB.open(dbName);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });

/** Every raw row of a vault database, read straight from IndexedDB (for the "only ciphertext" checks). */
export async function rawRows(dbName: string): Promise<unknown[]> {
  const db = await openDb(dbName);
  const rows: unknown[] = [];
  for (const name of Array.from(db.objectStoreNames)) {
    rows.push(
      ...(await new Promise<unknown[]>((res) => {
        const q = db.transaction(name).objectStore(name).getAll();
        q.onsuccess = () => res(q.result);
      })),
    );
  }
  db.close();
  return rows;
}

export const freshDb = (): string => `legx-vault-test-${bytesToHex(randomBytes(6))}`;
export const isZero = (b: Uint8Array): boolean => b.every((x) => x === 0);

/** Records every MessagePort message (and still delivers it). */
export function recordPortMessages(): unknown[] {
  const posted: unknown[] = [];
  const real = MessagePort.prototype.postMessage as (
    this: MessagePort,
    m: unknown,
    o?: StructuredSerializeOptions,
  ) => void;
  vi.spyOn(MessagePort.prototype, 'postMessage').mockImplementation(function (
    this: MessagePort,
    m: unknown,
    o?: StructuredSerializeOptions,
  ) {
    posted.push(m);
    real.call(this, m, o);
  });
  return posted;
}
