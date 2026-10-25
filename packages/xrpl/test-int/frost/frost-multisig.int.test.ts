// Task 2.8 (T-I-11, P2.8-01 to 10): FROST 2-of-3 slots as the four multisig signers of a deal wallet, on the
// standalone ledger. rippled sees plain Ed25519 keys; the multisig layer (`combine`) is unchanged from task 2.4.
import { ed25519 } from '@noble/curves/ed25519.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'xrpl';
import xrpl from 'xrpl';
import { aggregateChecked, type FrostError, SigningSession, slotPubkey } from '../../../core/src/frost.ts';
import { deletionStatement, refreshedEvent } from '../../../core/src/frostRefresh.ts';
import { repairFinish } from '../../../core/src/frostRepair.ts';
import { type BuildCtx, build5a, build5g, build8 } from '../../src/builders/index.ts';
import { connect } from '../../src/connect.ts';
import { standaloneEnv } from '../../src/env.ts';
import { fundAccount } from '../../src/fund.ts';
import { readFees } from '../../src/ledger.ts';
import { combine, nextSlot } from '../../src/multisig.ts';
import { rpcOf } from '../../src/read.ts';
import { closer } from '../support.ts';
import {
  advance,
  dealerKit,
  dkgKit,
  type Kit,
  messageIsTx,
  multisend,
  NAMES,
  type Net,
  PAIRS,
  type Pair,
  pubHex,
  refreshSlot,
  repairShare,
  runDeal,
  settle,
  signerOf,
  signWithPair,
  slotMessage,
  strictVerify,
  withKeys,
} from './support.ts';

const env = standaloneEnv(process.env.XRPLD_WS ?? 'ws://127.0.0.1:6110');
let client: Client;
let ticker: Client;
let stop: () => Promise<void>;
let net: Net;
let ctx: BuildCtx;
let slots: Kit[];
let dealers: Kit[];

beforeAll(async () => {
  client = await connect(env);
  ticker = await connect(env);
  stop = closer(ticker);
  ctx = { network: 'standalone', baseFeeDrops: (await readFees(client)).baseFeeDrops };
  net = {
    client,
    ctx,
    fund: (xrp) => fundAccount(env, client, xrp),
    waitUntil: async (index) => {
      const r = await client.request({ command: 'ledger', ledger_index: 'validated' });
      await advance(client, Math.max(0, index - r.result.ledger_index));
    },
    timeoutMs: 60_000,
  };
  slots = await Promise.all(NAMES.map(dkgKit));
  dealers = NAMES.map(dealerKit);
});
afterAll(async () => {
  await stop();
  await Promise.all([client.disconnect(), ticker.disconnect()].map((p) => p.catch(() => undefined)));
});

const addresses = (s: readonly Kit[]) => s.map((k) => k.address);
const code = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    return (e as FrostError).code ?? String(e);
  }
  return 'NO_THROW';
};

/** A deal wallet locked as in 5a and 5g (single-signed here; the multisigned lock steps are in T-I-11). */
async function locked(s: readonly Kit[] = slots) {
  const shell = await fundAccount(env, client, 100);
  const a = await settle(
    net,
    shell.sign(await client.autofill(build5a({ shell: shell.classicAddress, signers: addresses(s) }, ctx))).tx_blob,
  );
  const g = await settle(net, shell.sign(await client.autofill(build5g({ shell: shell.classicAddress }, ctx))).tx_blob);
  expect([a, g]).toMatchObject([{ result: 'tesSUCCESS' }, { result: 'tesSUCCESS' }]);
  return shell;
}
const payTx = async (shell: string, to: string) =>
  build8({ shell, payout: to, amount: '1000000', slot: await nextSlot(rpcOf(client), shell) }, ctx);
const txOnLedger = async (hash: string) =>
  (await client.request({ command: 'tx', transaction: hash })).result as unknown as {
    tx_json: { Fee: string; Signers: { Signer: { Account: string; SigningPubKey: string } }[] };
  };
const idHex = (a: string) => Buffer.from(xrpl.decodeAccountID(a)).toString('hex');

describe('T-I-11 the whole deal with FROST slots', () => {
  for (const [label, get] of [
    ['DKG slots', () => slots],
    ['trusted-dealer slots', () => dealers],
  ] as const) {
    it(`${label}: lock steps, exit and close, each signed by four 2-of-3 groups`, async () => {
      const s = get();
      const deal = await runDeal(net, s);
      expect(deal.steps.map((x) => x.name)).toEqual([
        '5b AccountSet Domain+DepositAuth',
        '5b again, after the lock (master disabled)',
        '8 Payment',
        '9 AccountDelete',
      ]);
      // The slot public keys on the ledger are the group keys (checked on every multisigned transaction).
      for (const step of deal.steps) {
        const t = await txOnLedger(step.hash);
        expect(t.tx_json.Signers.map((x) => x.Signer.SigningPubKey).sort()).toEqual([...deal.groupKeys].sort());
        expect(t.tx_json.Signers.map((x) => x.Signer.Account).sort()).toEqual(addresses(s).sort());
      }
    });
  }
});

describe('signing', () => {
  it('P2.8-01 every pair of shares signs the same prepared transaction, for every slot', async () => {
    for (const [k, slot] of slots.entries()) {
      const shell = await locked();
      const bob = await fundAccount(env, client, 25);
      const tx = await (async () => {
        const t = await multisendPrepared(shell.classicAddress, bob.classicAddress);
        return t;
      })();
      const variants = PAIRS.map((pair) =>
        slots.map((s, i) => signWithPair(s, tx, i === k ? pair : (PAIRS[0] as Pair))),
      );
      const sigs = variants.map((v) => signerOf(v[k] as string).TxnSignature);
      expect(new Set(sigs).size).toBe(3); // three valid but different signatures
      const msg = slotMessage(slot, tx);
      for (const sg of sigs) expect(strictVerify(Buffer.from(sg, 'hex'), msg, slotPubkey(slot.pub))).toBe(true);
      const results = [];
      for (const v of variants)
        results.push(await client.submit(combine(v, addresses(slots))).then((r) => r.result.engine_result));
      await advance(client, 1);
      // rippled checks every signature cryptographically on submit; only the first copy can apply.
      expect(results).toEqual(['tesSUCCESS', 'tefPAST_SEQ', 'tefPAST_SEQ']);
      // A negative control: one flipped signature byte is refused by rippled, not just by us.
      const bad = variants[0]?.map((b, i) => (i === k ? flip(b) : b)) as string[];
      await expect(client.submit(xrpl.multisign(bad))).rejects.toThrow(/Invalid signature/);
    }
  });

  it('P2.8-02 one share alone is refused before any nonce is used', () => {
    const slot = slots[0] as Kit;
    const msg = new TextEncoder().encode('one share');
    const session = SigningSession.open(slot.keys[0]?.secret as never, slot.pub, msg);
    const alone = [session.commitment];
    expect(code(() => session.signShare(msg, alone, () => ({ ok: true })))).toBe('BELOW_THRESHOLD');
    // The nonces are still there: the same session now signs with a proper pair.
    const other = SigningSession.open(slot.keys[1]?.secret as never, slot.pub, msg);
    const list = [session.commitment, other.commitment];
    const shares = {
      [slot.keys[0]?.secret.identifier as string]: session.signShare(msg, list, () => ({ ok: true })),
      [slot.keys[1]?.secret.identifier as string]: other.signShare(msg, list, () => ({ ok: true })),
    };
    expect(strictVerify(aggregateChecked(slot.pub, list, msg, shares), msg, slotPubkey(slot.pub))).toBe(true);
    // The aggregator also refuses a single share.
    const solo = SigningSession.open(slot.keys[2]?.secret as never, slot.pub, msg);
    expect(code(() => aggregateChecked(slot.pub, [solo.commitment], msg, { x: new Uint8Array(32) }))).toBe(
      'BELOW_THRESHOLD',
    );
  });

  it('P2.8-02b a signer that refuses the message keeps its nonce unused', () => {
    const slot = slots[1] as Kit;
    const msg = new TextEncoder().encode('wrong');
    const a = SigningSession.open(slot.keys[0]?.secret as never, slot.pub, msg);
    const b = SigningSession.open(slot.keys[1]?.secret as never, slot.pub, msg);
    const list = [a.commitment, b.commitment];
    expect(code(() => a.signShare(msg, list, () => ({ ok: false, reason: 'no' })))).toBe('MESSAGE_REFUSED');
    expect(a.signShare(msg, list, () => ({ ok: true }))).toBeInstanceOf(Uint8Array);
  });

  it('P2.8-03 a pair outside the slot policy is refused before submit; nothing reaches the ledger', async () => {
    const shell = await locked();
    const bob = await fundAccount(env, client, 25);
    const tx = await multisendPrepared(shell.classicAddress, bob.classicAddress);
    const before = (await nextSlot(rpcOf(client), shell.classicAddress)).sequence;
    const a = slots[0] as Kit; // client A
    const la = slots[2] as Kit; // lawyer A
    // 1. Client phone + lawyer HSM share: the signer refuses to open a session (the share is not in this slot).
    const msg = slotMessage(a, tx);
    const hsm = (la.keys[1] as (typeof la.keys)[0]).secret;
    expect(code(() => SigningSession.open(hsm, a.pub, msg))).toBe('SHARE_INVALID');
    // 2. A signature made by the lawyer slot, relabelled as slot A's signer entry: `combine` refuses it.
    const forged = signerOf(signWithPair(la, tx, [1, 2]));
    const relabelled = xrpl.encode({
      ...tx,
      SigningPubKey: '',
      Signers: [{ Signer: { ...forged, Account: a.address, SigningPubKey: pubHex(a) } }],
    } as never);
    const rest = [slots[1], slots[2], slots[3]].map((s, i) => signWithPair(s as Kit, tx, PAIRS[i] as Pair));
    expect(() => combine([relabelled, ...rest], addresses(slots))).toThrow(/signatures do not match/);
    // 3. A holder index that is not in the pair table at all.
    expect(() => signWithPair(a, tx, [1, 4])).toThrow();
    expect((await nextSlot(rpcOf(client), shell.classicAddress)).sequence).toBe(before);
  });

  it('P2.8-04 rippled accepts a FROST Ed25519 signature in Signers, with an ED-prefixed key', async () => {
    const shell = await locked();
    const bob = await fundAccount(env, client, 25);
    const r = await multisend(
      net,
      slots,
      await payTx(shell.classicAddress, bob.classicAddress),
      [
        [1, 2],
        [1, 3],
        [2, 3],
        [1, 2],
      ],
      5,
    );
    expect(r.result).toMatchObject({ status: 'validated', result: 'tesSUCCESS' });
    const t = await txOnLedger((r.result as { hash: string }).hash);
    for (const { Signer } of t.tx_json.Signers) {
      expect(Signer.SigningPubKey).toMatch(/^ED[0-9A-F]{64}$/);
      expect(xrpl.deriveAddress(Signer.SigningPubKey)).toBe(Signer.Account);
    }
  });

  it('P2.8-05 and P2.8-10 fee and Signers order equal the plain-key run; AccountIDs sort differently from slot names', async () => {
    const names = slots.map((s) => idHex(s.address));
    expect(names).not.toEqual([...names].sort()); // the slot order A, B, LA, LB is not the AccountID order
    const shell = await locked();
    const bob = await fundAccount(env, client, 25);
    const f = await multisend(net, slots, await payTx(shell.classicAddress, bob.classicAddress), [
      [2, 3],
      [1, 2],
      [1, 3],
      [2, 3],
    ]);
    const tf = await txOnLedger((f.result as { hash: string }).hash);
    // Plain-key reference run: four Ed25519 wallets, the same builder, xrpl.multisign.
    const wallets = [0, 1, 2, 3].map(() => xrpl.Wallet.generate(xrpl.ECDSA.ed25519));
    const pshell = await fundAccount(env, client, 100);
    for (const t of [
      build5a({ shell: pshell.classicAddress, signers: wallets.map((w) => w.classicAddress) }, ctx),
      build5g({ shell: pshell.classicAddress }, ctx),
    ])
      await settle(net, pshell.sign(await client.autofill(t)).tx_blob);
    const pt = await client.autofill(await payTx(pshell.classicAddress, bob.classicAddress), 4);
    const plain = xrpl.multisign(wallets.map((w) => w.sign(pt, true).tx_blob));
    const pr = await settle(net, plain);
    const tp = await txOnLedger((pr as { hash: string }).hash);
    expect(tf.tx_json.Fee).toBe(String((ctx.baseFeeDrops ?? 10) * 5)); // base fee x (1 + 4)
    expect(tf.tx_json.Fee).toBe(tp.tx_json.Fee);
    for (const t of [tf, tp]) {
      const ids = t.tx_json.Signers.map((x) => idHex(x.Signer.Account));
      expect(ids).toEqual([...ids].sort());
    }
  });

  it('P2.8-06 the group signature verifies with plain strict Ed25519 over the transaction signing bytes', async () => {
    const slot = slots[2] as Kit;
    const shell = await locked();
    const bob = await fundAccount(env, client, 25);
    const tx = await multisendPrepared(shell.classicAddress, bob.classicAddress);
    for (const pair of PAIRS) {
      const e = signerOf(signWithPair(slot, tx, pair));
      const msg = Buffer.from(xrpl.encodeForMultiSigning({ ...tx, SigningPubKey: '' } as never, e.Account), 'hex');
      const key = Buffer.from(e.SigningPubKey, 'hex');
      expect(ed25519.verify(Buffer.from(e.TxnSignature, 'hex'), msg, key.subarray(1), { zip215: false })).toBe(true);
      // And not for a different transaction (the message is bound to this signing hash).
      const other = Buffer.from(
        xrpl.encodeForMultiSigning({ ...tx, Fee: '999', SigningPubKey: '' } as never, e.Account),
        'hex',
      );
      expect(ed25519.verify(Buffer.from(e.TxnSignature, 'hex'), other, key.subarray(1), { zip215: false })).toBe(false);
      // The signer's own check refuses a message that is another transaction's.
      expect(messageIsTx(tx, e.Account)(other).ok).toBe(false);
    }
  });

  it('P2.8-07 a signing nonce used twice throws NONCE_USED and the session keeps no copy', () => {
    const slot = slots[3] as Kit;
    const msg = new TextEncoder().encode('twice');
    const a = SigningSession.open(slot.keys[0]?.secret as never, slot.pub, msg);
    const b = SigningSession.open(slot.keys[2]?.secret as never, slot.pub, msg);
    const list = [a.commitment, b.commitment];
    const first = a.signShare(msg, list, () => ({ ok: true }));
    expect(first).toBeInstanceOf(Uint8Array);
    expect(code(() => a.signShare(msg, list, () => ({ ok: true })))).toBe('NONCE_USED');
    // The same session cannot sign a different message either, and it cannot be serialized or copied.
    expect(code(() => a.signShare(new TextEncoder().encode('other'), list, () => ({ ok: true })))).toBe(
      'SESSION_MISMATCH',
    );
    expect(code(() => JSON.stringify(a))).toBe('NOT_SERIALIZABLE');
    expect(Object.keys(a)).toEqual([]);
    expect(JSON.stringify(Object.getOwnPropertyNames(a))).not.toMatch(/nonce/i);
  });
});

describe('refresh and repair mid-deal', () => {
  it('P2.8-08 a refreshed slot keeps its key and list entry; refreshed pairs sign an exit; old+new does not combine', async () => {
    const shell = await locked();
    const bob = await fundAccount(env, client, 25);
    const { ctx: rctx, results } = await refreshSlot(slots[1] as Kit);
    const newPub = (results[0] as { pub: Kit['pub'] }).pub;
    const st = [1, 2, 3].map((p) =>
      deletionStatement((slots[1] as Kit).holders[p - 1]?.signer as never, rctx, p, newPub),
    );
    expect(refreshedEvent(rctx, newPub, st.slice(0, 2)).status).toBe('INCOMPLETE');
    expect(refreshedEvent(rctx, newPub, st).status).toBe('COMPLETE');
    const refreshed = withKeys(
      slots[1] as Kit,
      results.map((r) => r.share),
      newPub,
    );
    expect(pubHex(refreshed)).toBe(pubHex(slots[1] as Kit));
    expect(refreshed.address).toBe((slots[1] as Kit).address);
    // old share + refreshed share: the signer will not even open a session, and a raw mix gives no valid signature
    expect(code(() => SigningSession.open((slots[1] as Kit).keys[0]?.secret as never, newPub, new Uint8Array(4)))).toBe(
      'SHARE_INVALID',
    );
    const mixed = withKeys(
      refreshed,
      [(slots[1] as Kit).keys[0]?.secret as never, results[1]?.share as never, results[2]?.share as never],
      newPub,
    );
    expect(() => signWithPair(mixed, { TransactionType: 'Payment' }, [1, 2])).toThrow();
    // Every refreshed pair signs the exit, with the other three slots unchanged.
    const set = [slots[0], refreshed, slots[2], slots[3]] as Kit[];
    const r = await multisend(
      net,
      set,
      await payTx(shell.classicAddress, bob.classicAddress),
      [
        [1, 2],
        [2, 3],
        [1, 3],
        [1, 2],
      ],
      5,
    );
    expect(r.result).toMatchObject({ status: 'validated', result: 'tesSUCCESS' });
    const list = await client.request({
      command: 'account_objects',
      account: shell.classicAddress,
      type: 'signer_list',
    });
    const entries = (
      list.result.account_objects[0] as unknown as { SignerEntries: { SignerEntry: { Account: string } }[] }
    ).SignerEntries;
    expect(entries.map((e) => e.SignerEntry.Account).sort()).toEqual(addresses(slots).sort());
    for (const pair of PAIRS) {
      const tx = await multisendPrepared(shell.classicAddress, bob.classicAddress);
      const e = signerOf(signWithPair(refreshed, tx, pair));
      expect(e.SigningPubKey).toBe(pubHex(slots[1] as Kit));
    }
  });

  it('P2.8-09 a share rebuilt by repair signs a ledger transaction under the unchanged group key', async () => {
    const shell = await locked();
    const bob = await fundAccount(env, client, 25);
    const slot = slots[2] as Kit;
    const shares = slot.keys.map((k) => k.secret);
    const rebuilt = repairFinish(slot.pub, 2, repairShare(slot.pub, [1, 3], shares, 2));
    const repaired = withKeys(slot, [shares[0] as never, rebuilt, shares[2] as never], slot.pub);
    const set = [slots[0], slots[1], repaired, slots[3]] as Kit[];
    // The new device (holder 2) signs with holder 1, then with holder 3.
    const r = await multisend(
      net,
      set,
      await payTx(shell.classicAddress, bob.classicAddress),
      [
        [1, 2],
        [1, 2],
        [1, 2],
        [1, 2],
      ],
      5,
    );
    expect(r.result).toMatchObject({ status: 'validated', result: 'tesSUCCESS' });
    const tx = await multisendPrepared(shell.classicAddress, bob.classicAddress);
    expect(signerOf(signWithPair(repaired, tx, [2, 3])).SigningPubKey).toBe(pubHex(slot));
  });
});

/** A prepared (fee, sequence and LastLedgerSequence filled) 4-signer exit that is not submitted. */
async function multisendPrepared(shell: string, to: string): Promise<Record<string, unknown>> {
  const { prepareExit } = await import('../../src/multisig.ts');
  return (await prepareExit(await payTx(shell, to), { client, signers: 4 })) as unknown as Record<string, unknown>;
}
function flip(blob: string): string {
  const t = xrpl.decode(blob) as { Signers: { Signer: { TxnSignature: string } }[] };
  const sig = t.Signers[0]?.Signer.TxnSignature as string;
  (t.Signers[0] as { Signer: { TxnSignature: string } }).Signer.TxnSignature =
    (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  return xrpl.encode(t as never);
}
