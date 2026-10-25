// Task 2.8 helpers: FROST slot signers with an explicit pair of shares, a message check before any nonce is used,
// trusted-dealer slots, refresh and repair runs, and the shared T-I-11 deal flow (standalone and Testnet).
import { ed25519, ed25519_FROST } from '@noble/curves/ed25519.js';
import type { Client, SubmittableTransaction } from 'xrpl';
import xrpl from 'xrpl';
import {
  aggregateChecked,
  type CheckResult,
  type Commitment,
  type KeyShare,
  SigningSession,
  type SlotName,
  type SlotPublic,
  slotAddress,
  slotPubkey,
} from '../../../core/src/frost.ts';
import type { DkgKey } from '../../../core/src/frostDkg.ts';
import { dkgKeys, type Enrolled, slotSetup } from '../../../core/test/helpers/frost.ts';
import { type BuildCtx, build5a, build5b, build5g, build8, build9 } from '../../src/builders/index.ts';
import { advanceLedgers, readFees } from '../../src/ledger.ts';
import { combine, nextSlot } from '../../src/multisig.ts';
import { prepare } from '../../src/prepare.ts';
import { rpcOf } from '../../src/read.ts';
import { submitReliable } from '../../src/submit.ts';
import type { FrostSlot } from '../frostSlots.ts';

export const NAMES = ['A', 'B', 'LA', 'LB'] as const satisfies readonly SlotName[];
/** Holder indexes 1..3 are the roles in canonical order: phone, second authenticator, recovery agent; console, firm HSM, partner. */
export const PAIRS = [
  [1, 2],
  [1, 3],
  [2, 3],
] as const;
export type Pair = readonly [number, number];
export const ROLE_PAIR_NAMES = {
  client: ['phone+passkey', 'phone+recovery-agent', 'passkey+recovery-agent'],
  lawyer: ['console+hsm', 'console+partner', 'hsm+partner'],
} as const;

export type Kit = FrostSlot & { holders: Enrolled[]; pub: SlotPublic; ctx: ReturnType<typeof slotSetup>['ctx'] };

export const pubHex = (k: Pick<Kit, 'pub'>): string => Buffer.from(slotPubkey(k.pub)).toString('hex').toUpperCase();

/** A slot made by the in-process DKG (task 1.15). */
export async function dkgKit(name: SlotName): Promise<Kit> {
  const k = await dkgKeys(name);
  return { name, address: slotAddress(k.pub), keys: k.keys, holders: k.holders, pub: k.pub, ctx: k.ctx };
}

/** A slot made by a trusted dealer (noble `trustedDealer`): the other way to get a group key. */
export function dealerKit(name: SlotName): Kit {
  const { ctx, holders } = slotSetup(name);
  const d = ed25519_FROST.trustedDealer({ min: 2, max: 3 });
  const keys: DkgKey[] = [1, 2, 3].map((i) => ({
    public: d.public,
    secret: d.secretShares[ed25519_FROST.Identifier.fromNumber(i)] as KeyShare,
  }));
  return { name, address: slotAddress(d.public), keys, holders, pub: d.public, ctx };
}

const ok = (): CheckResult => ({ ok: true });
/** The signer's own check: the bytes it is asked to sign must be this transaction's multisigning message. */
export const messageIsTx =
  (tx: Record<string, unknown>, account: string) =>
  (msg: Uint8Array): CheckResult =>
    Buffer.from(msg).toString('hex').toUpperCase() ===
    xrpl.encodeForMultiSigning({ ...tx, SigningPubKey: '' } as never, account)
      ? ok()
      : { ok: false, reason: 'message is not this transaction' };

export const slotMessage = (slot: Kit, tx: Record<string, unknown>): Uint8Array =>
  Buffer.from(xrpl.encodeForMultiSigning({ ...tx, SigningPubKey: '' } as never, slot.address), 'hex');

/** One Signer entry blob, FROST-signed by exactly the two shares in `pair` (1-based holder indexes). */
export function signWithPair(slot: Kit, tx: Record<string, unknown>, pair: Pair): string {
  const shares = pair.map((i) => slot.keys[i - 1]?.secret as KeyShare);
  const msg = slotMessage(slot, tx);
  const sessions = shares.map((s) => SigningSession.open(s, slot.pub, msg));
  const list: Commitment[] = sessions.map((s) => s.commitment);
  const check = messageIsTx(tx, slot.address);
  const sigShares = Object.fromEntries(
    shares.map((s, i) => [s.identifier, (sessions[i] as SigningSession).signShare(msg, list, check)]),
  );
  const sig = aggregateChecked(slot.pub, list, msg, sigShares);
  const unsigned = { ...tx, SigningPubKey: '' };
  return xrpl.encode({
    ...unsigned,
    Signers: [
      {
        Signer: {
          Account: slot.address,
          SigningPubKey: pubHex(slot),
          TxnSignature: Buffer.from(sig).toString('hex').toUpperCase(),
        },
      },
    ],
  } as never);
}

/** Plain Ed25519, strict (zip215: false), straight from noble: the check rippled's key type implies. */
export const strictVerify = (sig: Uint8Array, msg: Uint8Array, key33: Uint8Array): boolean =>
  ed25519.verify(sig, msg, key33.slice(1), { zip215: false });

export const signerOf = (blob: string) =>
  (xrpl.decode(blob).Signers as { Signer: { Account: string; SigningPubKey: string; TxnSignature: string } }[])[0]
    ?.Signer as { Account: string; SigningPubKey: string; TxnSignature: string };

// ---------- refresh and repair (task 1.15 functions, run in process) ----------

export function withKeys(slot: Kit, shares: KeyShare[], pub: SlotPublic): Kit {
  return { ...slot, pub, keys: shares.map((secret) => ({ public: pub, secret })) };
}

// `refreshSlot` and `repairShare` are the shared helpers of core (no second copy).
export { refreshSlot, repairShare } from '../../../core/test/helpers/frost.ts';

// ---------- the deal on a ledger (T-I-11) ----------

export interface Net {
  client: Client;
  ctx: BuildCtx;
  /** Funds a new wallet. */
  fund(xrp: number): Promise<InstanceType<typeof xrpl.Wallet>>;
  /** Standalone: closes `n` ledgers. Testnet: waits until the validated ledger index reaches `index`. */
  waitUntil(index: number): Promise<void>;
  timeoutMs: number;
}

export const settle = (net: Net, blob: string) =>
  submitReliable(rpcOf(net.client), blob, { pollMs: 50, timeoutMs: net.timeoutMs });

/** Prepares `tx`, has each slot sign with its pair, combines (sorted by AccountID) and submits. */
export async function multisend(
  net: Net,
  slots: readonly Kit[],
  tx: SubmittableTransaction,
  pairs: readonly Pair[],
  feeMultiplier = 1,
) {
  const prepared = (await prepare(tx, {
    client: net.client,
    signers: slots.length,
    lastLedgerOffset: 1800,
    feeMultiplier,
  })) as unknown as Record<string, unknown>;
  const blobs = slots.map((s, i) => signWithPair(s, prepared, pairs[i] as Pair));
  const blob = combine(
    blobs,
    slots.map((s) => s.address),
  );
  return { blob, prepared, result: await settle(net, blob) };
}

function success(name: string, r: { status: string; result?: string }): void {
  if (r.status !== 'validated' || r.result !== 'tesSUCCESS') throw new Error(`${name}: ${JSON.stringify(r)}`);
}

export interface DealResult {
  steps: { name: string; hash: string; fee: string }[];
  shell: string;
  groupKeys: string[];
}

/** Lock steps 5a to 5g, the exit and the close; every multisigned step uses a different pair per slot. */
export async function runDeal(net: Net, slots: readonly Kit[]): Promise<DealResult> {
  const rpc = rpcOf(net.client);
  const shell = await net.fund(100);
  const bob = await net.fund(30);
  const steps: DealResult['steps'] = [];
  const pairFor = (t: number): Pair[] => slots.map((_, k) => PAIRS[(t + k) % 3] as Pair);
  const need = async (name: string, r: Awaited<ReturnType<typeof multisend>>) => {
    success(name, r.result);
    steps.push({ name, hash: (r.result as { hash: string }).hash, fee: String(r.prepared.Fee) });
  };
  const addresses = slots.map((s) => s.address);
  // 5a: the shell's own key sets the 4-of-4 list (the only single-signed lock step).
  const a = await settle(
    net,
    shell.sign(await net.client.autofill(build5a({ shell: shell.classicAddress, signers: addresses }, net.ctx)))
      .tx_blob,
  );
  success('5a', a);
  const root = crypto.getRandomValues(new Uint8Array(32));
  const seal = crypto.getRandomValues(new Uint8Array(32));
  await need(
    '5b AccountSet Domain+DepositAuth',
    await multisend(
      net,
      slots,
      build5b({ shell: shell.classicAddress, contractRoot: root, dealSeal: seal }, net.ctx),
      pairFor(0),
      5,
    ),
  );
  // DisableMaster must be signed by the master key itself (tecNEED_MASTER_KEY when multisigned), so 5g is single-signed.
  success(
    '5g',
    await settle(net, shell.sign(await net.client.autofill(build5g({ shell: shell.classicAddress }, net.ctx))).tx_blob),
  );
  await need(
    '5b again, after the lock (master disabled)',
    await multisend(
      net,
      slots,
      build5b({ shell: shell.classicAddress, contractRoot: root, dealSeal: seal }, net.ctx),
      pairFor(1),
      5,
    ),
  );
  const slot = await nextSlot(rpc, shell.classicAddress);
  await need(
    '8 Payment',
    await multisend(
      net,
      slots,
      build8({ shell: shell.classicAddress, payout: bob.classicAddress, amount: '10000000', slot }, net.ctx),
      pairFor(2),
      5,
    ),
  );
  const seq = (await nextSlot(rpc, shell.classicAddress)).sequence;
  await net.waitUntil(seq + 256);
  const fees = await readFees(net.client);
  await need(
    '9 AccountDelete',
    await multisend(
      net,
      slots,
      build9(
        {
          shell: shell.classicAddress,
          destination: bob.classicAddress,
          ownerReserveDrops: String(fees.ownerReserveDrops),
        },
        net.ctx,
      ),
      pairFor(3),
    ),
  );
  return { steps, shell: shell.classicAddress, groupKeys: slots.map(pubHex) };
}

export const advance = (client: Client, n: number) => advanceLedgers(client, n);
