// P3.9-28: rotation on the ledger after a stolen share. A new DKG for the slot, a 4-of-4 SignerListSet signed by all four
// current slots (each a 2-of-3 FROST signature made through the relay), a new seal. On a standalone ledger the new
// key is the only valid signer for that slot, and the lock checker accepts the new seal and refuses the old one.
// Needs a standalone rippled: docker run -d --name legx-3.9-xrpld --platform linux/amd64 -p 127.0.0.1:6119:6006
//   -v "$PWD/ci:/etc/xrpld:ro" rippleci/xrpld:3.4.1 --standalone     (override the address with LEGX_39_LEDGER)
import type { PublicDealData } from '@legx/contracts/deal';
import { bytesToHex, dealSeal } from '@legx/core/dealcore';
import { rotationPlan } from '@legx/core/frostRules';
import { checkLock } from '@legx/core/lockcheck';
import { connect } from '@legx/xrpl/connect';
import { standaloneEnv } from '@legx/xrpl/env';
import { fundAccount } from '@legx/xrpl/fund';
import { advanceLedgers } from '@legx/xrpl/ledger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import xrpl, { type Client, deriveAddress, encodeForMultiSigning, type Wallet } from 'xrpl';
import { slotSetup } from '../test/support/setup.ts';
import { makeWorld, type World } from '../test/support/world.ts';

const WS = process.env.LEGX_39_LEDGER ?? process.env.XRPLD_WS ?? 'ws://127.0.0.1:6119';
const SLOTS = ['A', 'LA', 'B', 'LB'] as const;
type Slot = (typeof SLOTS)[number];

let client: Client;
let master: Wallet;
const worlds = {} as Record<Slot, World>;
const sets = {} as Record<Slot, Awaited<ReturnType<typeof slotSetup>>>;
let rotatedA: Awaited<ReturnType<typeof slotSetup>>;

const pubOf = (s: { record: { slotPub: Uint8Array } }) => bytesToHex(s.record.slotPub).toUpperCase();
const addrOf = (s: { record: { slotPub: Uint8Array } }) => deriveAddress(pubOf(s));

beforeAll(async () => {
  const env = standaloneEnv(WS);
  client = await connect(env);
  master = await fundAccount(env, client, 200);
  for (const s of SLOTS) {
    worlds[s] = await makeWorld({ slot: s });
    sets[s] = await slotSetup(worlds[s]);
  }
});
afterAll(async () => {
  await client?.disconnect();
  for (const w of Object.values(worlds)) await w.close();
});

/** One slot's signature over the multisign message, made by two of its three holders through the relay. */
async function slotSignature(w: World, s: Awaited<ReturnType<typeof slotSetup>>, msg: Uint8Array): Promise<string> {
  const ids = [1, 2].map((i) => w.members[i - 1]?.info.identifier) as [string, string];
  const session = await w.relay.openSession({
    dealId: w.dealId,
    slot: w.slot,
    purpose: 'sign',
    participants: w.participants(),
    pair: ids,
  });
  const [sig] = await Promise.all(
    [1, 2].map((i) =>
      w.holder(i).sign(session, {
        msg,
        kind: 'xrpl-multisign',
        share: s.keys[i - 1]?.secret as never,
        pub: s.pub,
        pair: [1, 2],
        check: () => ({ ok: true }),
      }),
    ),
  );
  return Buffer.from(sig as Uint8Array)
    .toString('hex')
    .toUpperCase();
}

/** The four slots sign `tx` (a multisign request); returns the blob with its Signers array. */
async function multisign(
  tx: Record<string, unknown>,
  signers: { slot: Slot; world: World; set: typeof rotatedA }[],
): Promise<string> {
  const entries = [];
  for (const { world, set } of signers) {
    const address = addrOf(set);
    const msg = new Uint8Array(Buffer.from(encodeForMultiSigning(tx as never, address), 'hex'));
    entries.push({
      Signer: { Account: address, SigningPubKey: pubOf(set), TxnSignature: await slotSignature(world, set, msg) },
    });
  }
  entries.sort((a, b) =>
    Buffer.from(xrpl.decodeAccountID(a.Signer.Account)).compare(Buffer.from(xrpl.decodeAccountID(b.Signer.Account))),
  );
  return xrpl.encode({ ...tx, Signers: entries } as never);
}

const close = async () => void (await advanceLedgers(client, 1));
async function submit(blob: string): Promise<string> {
  const r = (await client.request({ command: 'submit', tx_blob: blob } as never)) as unknown as {
    result: { engine_result: string };
  };
  await close();
  return r.result.engine_result;
}
const prepared = async (tx: Record<string, unknown>): Promise<Record<string, unknown>> => ({
  ...((await client.autofill({ ...tx, Account: master.classicAddress } as never, 4)) as unknown as Record<
    string,
    unknown
  >),
  SigningPubKey: '',
});

describe('P3.9-28 rotation after a stolen share', () => {
  const current = () => SLOTS.map((slot) => ({ slot, world: worlds[slot], set: sets[slot] }));

  it("sets the four slot keys as the wallet's only signers, and a 4-of-4 FROST exit is valid", async () => {
    const own = async (tx: Record<string, unknown>) =>
      await submit(
        master.sign((await client.autofill({ Account: master.classicAddress, ...tx } as never)) as never).tx_blob,
      );
    expect(
      await own({
        TransactionType: 'SignerListSet',
        SignerQuorum: 4,
        SignerEntries: SLOTS.map((s) => ({ SignerEntry: { Account: addrOf(sets[s]), SignerWeight: 1 } })),
      }),
    ).toBe('tesSUCCESS');
    expect(await own({ TransactionType: 'AccountSet', SetFlag: xrpl.AccountSetAsfFlags.asfDisableMaster })).toBe(
      'tesSUCCESS',
    );
    const exit = await prepared({
      TransactionType: 'Payment',
      Destination: xrpl.Wallet.generate().classicAddress,
      Amount: '20000000',
    });
    expect(await submit(await multisign(exit, current()))).toBe('tesSUCCESS');
  });

  it('a stolen share: new DKG, 4-of-4 SignerListSet by the old four, a new seal; only the new key signs', async () => {
    expect(rotationPlan('A', 'stolen')).toEqual(['new-dkg', 'signer-list-set-4-of-4', 'new-seal']);
    expect(rotationPlan('LA', 'stolen')).toEqual([
      'new-dkg',
      'signer-list-set-4-of-4',
      'new-seal',
      'new-contract-signatures',
      'new-nft',
    ]);
    expect(rotationPlan('A', 'lost')).toEqual(['repair', 'refresh']); // a lost share is not rotated
    rotatedA = await slotSetup(worlds.A); // a new DKG with fresh randomness, test-signed by all three pairs
    expect(pubOf(rotatedA)).not.toBe(pubOf(sets.A));

    const change = await prepared({
      TransactionType: 'SignerListSet',
      SignerQuorum: 4,
      SignerEntries: [rotatedA, sets.LA, sets.B, sets.LB].map((s) => ({
        SignerEntry: { Account: addrOf(s), SignerWeight: 1 },
      })),
    });
    expect(await submit(await multisign(change, current()))).toBe('tesSUCCESS');

    const exit = await prepared({
      TransactionType: 'Payment',
      Destination: xrpl.Wallet.generate().classicAddress,
      Amount: '20000000',
    });
    const rest = (['LA', 'B', 'LB'] as const).map((slot) => ({ slot, world: worlds[slot], set: sets[slot] }));
    // the old slot key can no longer sign an exit
    const old = await submit(await multisign(exit, current()));
    expect(['tefBAD_SIGNATURE', 'tefBAD_QUORUM']).toContain(old);
    // the new key is the only valid signer
    const fresh = await prepared({
      TransactionType: 'Payment',
      Destination: xrpl.Wallet.generate().classicAddress,
      Amount: '20000000',
    });
    expect(await submit(await multisign(fresh, [{ slot: 'A', world: worlds.A, set: rotatedA }, ...rest]))).toBe(
      'tesSUCCESS',
    );
  });

  it("the new seal passes the lock checker's signer rules; the old seal does not", async () => {
    const objects = (
      await client.request({
        command: 'account_objects',
        account: master.classicAddress,
        type: 'signer_list',
        ledger_index: 'validated',
      })
    ).result.account_objects;
    const info = (
      await client.request({ command: 'account_info', account: master.classicAddress, ledger_index: 'validated' })
    ).result.account_data;
    const dealWith = (a: typeof rotatedA) =>
      ({
        contractRoot: '01'.repeat(32),
        signedContractSeal: '02'.repeat(32),
        walletAddress: master.classicAddress,
        xPubA: pubOf(a),
        xPubB: pubOf(sets.B),
        lawyerPubA: pubOf(sets.LA),
        lawyerPubB: pubOf(sets.LB),
        commitmentA: '05'.repeat(32),
        commitmentB: '06'.repeat(32),
        idMethodA: 'zkpassport',
        idMethodB: 'nfc-chip',
        identityPolicy: 'zk-or-chip',
        lawyerCommitmentA: '09'.repeat(32),
        lawyerCommitmentB: '0a'.repeat(32),
        lawyerOpsA: xrpl.Wallet.generate().classicAddress,
        releaserAccount: '',
        lawyerOpsB: '',
        slotPolicyA: bytesToHex(sets.A.record.slotPolicy),
        slotPolicyLA: bytesToHex(sets.LA.record.slotPolicy),
        slotPolicyB: bytesToHex(sets.B.record.slotPolicy),
        slotPolicyLB: bytesToHex(sets.LB.record.slotPolicy),
        pqKeyHashA: '0f'.repeat(32),
        pqKeyHashLA: '10'.repeat(32),
        pqKeyHashB: '11'.repeat(32),
        pqKeyHashLB: '12'.repeat(32),
        signerAccounts: [a, sets.B, sets.LA, sets.LB].map(addrOf),
        quorum: 4,
        payoutA: `${xrpl.Wallet.generate().classicAddress}:7`,
        payoutB: xrpl.Wallet.generate().classicAddress,
      }) as unknown as PublicDealData;
    const ops = xrpl.Wallet.generate().classicAddress;
    const run = (a: typeof rotatedA) => {
      const deal = { ...dealWith(a), lawyerOpsB: ops, releaserAccount: ops } as PublicDealData;
      return {
        deal,
        findings: checkLock(info as never, objects as never, {
          deal,
          releaserAccount: ops,
          credentialSubjects: [],
          escrow: {
            owner: master.classicAddress,
            sequence: 1,
            amountDrops: '1',
            conditionHex: 'AA',
            minCancelAfter: 0,
          },
        }),
      };
    };
    const signerCodes = ['ONE_SIGNER_LIST', 'SIGNERS_MATCH_KEYS', 'QUORUM_MATCH', 'QUORUM_NEEDS_EVERY_SIGNER'];
    const verdict = (f: ReturnType<typeof run>['findings']) =>
      Object.fromEntries(signerCodes.map((c) => [c, f.find((x) => x.code === c)?.ok]));
    const fresh = run(rotatedA);
    const stale = run(sets.A);
    expect(verdict(fresh.findings)).toEqual(Object.fromEntries(signerCodes.map((c) => [c, true])));
    expect(verdict(stale.findings).SIGNERS_MATCH_KEYS).toBe(false);
    expect(bytesToHex(dealSeal(fresh.deal))).not.toBe(bytesToHex(dealSeal(stale.deal))); // a new seal
  });
});
