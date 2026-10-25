// P3.9-14 and 15: the coordinator cannot choose anyone's enrollment key.

import { pinEnrollmentKey } from '@legx/coordinator/enroll';
import { decodeSigned } from '@legx/coordinator/frost/schema';
import { bytesToHex } from '@legx/core/dealcore';
import { FrostError, type Role } from '@legx/core/frost';
import { EnrollmentRegistry, enrollmentKeyHash, qrPin, verifyQrPin } from '@legx/core/frostSetup';
import { toBase64 } from '@legx/core/pq';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ECDSA, Wallet } from 'xrpl';
import { xwingShareCipher } from '../src/cipher.ts';
import { FrostHolder } from '../src/holder.ts';
import {
  acceptServiceKey,
  anchorMemo,
  buildKeyList,
  KEY_LIST_MEMO_TYPE,
  readAnchor,
  signKeyList,
} from '../src/keylist.ts';
import { hex, type Member, makeMember, makeWorld, type World } from './support/world.ts';

let w: World;
beforeAll(async () => {
  w = await makeWorld();
});
afterAll(async () => {
  await w.close();
});

describe('P3.9-14 the client pins its own devices; the coordinator cannot offer another recovery-agent key', () => {
  it('the app refuses the swapped key and starts nothing', async () => {
    const [phone, second, agent] = w.members as [Member, Member, Member];
    const entry = (m: Member) => ({ holder: m.keys.keyId, role: m.info.role as Role, edPub: m.info.edPub });
    // the phone and the second authenticator pin each other by a QR scan
    const qr = qrPin(entry(phone), entry(second));
    verifyQrPin(qr, entry(phone), entry(second), qr.sas);
    // the agent's key comes from its signed, anchored list
    const client = new EnrollmentRegistry();
    for (const m of [phone, second, agent]) {
      client.pin(entry(m));
      client.markLogged(enrollmentKeyHash(entry(m)));
    }
    // a hacked coordinator pins a key of its own for the agent role and offers it in the session
    const evil = makeMember(3, 'A', 'recovery-agent');
    await pinEnrollmentKey(w.deps, w.dealId, {
      key_id: evil.keys.keyId,
      slot: 'A',
      holder_role: 'recovery-agent',
      ed25519_pub: hex(evil.info.edPub.slice(1)),
      mldsa65_pub: toBase64(evil.info.pqPub),
      valid_from: 0,
    } as never);
    const offered = [phone.info, second.info, evil.info];
    const session = await w.relay.openSession({
      dealId: w.dealId,
      slot: 'A',
      purpose: 'dkg',
      participants: offered.map((h) => ({ identifier: h.identifier, keyId: h.keyId, role: h.role })),
    });
    const app = new FrostHolder({
      index: 1,
      keys: phone.keys,
      dealId: w.dealId,
      slot: 'A',
      holders: offered,
      relay: w.relay,
      cipher: xwingShareCipher,
      pinned: client.check,
      pollMs: 2,
      timeoutMs: 1000,
    });
    await expect(app.dkg(session)).rejects.toMatchObject({ code: 'KEY_NOT_PINNED' });
    const kinds = (await w.relay.transcript(session)).map((m) => decodeSigned(m.message).message.kind);
    expect(kinds.filter((k) => k !== 'abort')).toEqual([]); // the app sent no round-1 message, only an abort
    // the key it pinned is the only one it accepts: a different key for the same holder cannot be pinned over it
    expect(() => client.pin({ ...entry(agent), edPub: evil.info.edPub })).toThrow(FrostError);
    // and the agent's own key works
    const ok = new FrostHolder({
      index: 1,
      keys: phone.keys,
      dealId: w.dealId,
      slot: 'A',
      holders: w.members.map((m) => m.info),
      relay: w.relay,
      cipher: xwingShareCipher,
      pinned: client.check,
      pollMs: 2,
      timeoutMs: 200,
    });
    const s2 = await w.relay.openSession({
      dealId: w.dealId,
      slot: 'A',
      purpose: 'dkg',
      participants: w.participants(),
    });
    await expect(ok.dkg(s2)).rejects.toMatchObject({ code: 'TIMEOUT' }); // it started (the others are not running)
    expect((await w.relay.transcript(s2)).map((m) => decodeSigned(m.message).message.kind)).toContain('dkg.round1');
  });

  it('a wrong QR code or a wrong short code is refused', () => {
    const [phone, second] = w.members as [Member, Member];
    const entry = (m: Member) => ({ holder: m.keys.keyId, role: m.info.role as Role, edPub: m.info.edPub });
    const qr = qrPin(entry(phone), entry(second));
    expect(() => verifyQrPin(qr, entry(phone), entry(second), '000000' === qr.sas ? '000001' : '000000')).toThrow(
      FrostError,
    );
    expect(() => verifyQrPin(qr, entry(second), entry(phone), qr.sas)).toThrow(FrostError);
  });
});

describe("P3.9-15 the agent's signed key list and its ledger anchor", () => {
  const account = Wallet.generate(ECDSA.ed25519);
  const secret = new Uint8Array(Buffer.from(account.privateKey.slice(2), 'hex'));
  const other = Wallet.generate(ECDSA.ed25519);
  const agentKey = () => {
    const m = w.members[2] as Member;
    return { holder: m.keys.keyId, role: 'recovery-agent' as Role, edPub: m.info.edPub };
  };
  const listFor = (keys: Member[]) =>
    signKeyList(
      buildKeyList(
        keys.map((m) => ({
          holder: m.keys.keyId,
          role: 'recovery-agent' as const,
          ed25519: `ED${hex(m.info.edPub.slice(1)).toUpperCase()}`,
          mldsa65: toBase64(m.info.pqPub),
        })),
      ),
      secret,
    );
  const ledgerWith = (txAccount: string, memoOf: Uint8Array | undefined) => ({
    tx: async () => ({
      tx: { Account: txAccount, TransactionType: 'AccountSet', ...(memoOf ? { Memos: [anchorMemo(memoOf)] } : {}) },
      meta: { TransactionResult: 'tesSUCCESS' },
    }),
  });

  it("accepts a key in the list when the list hash equals the anchor from the agent's own account", async () => {
    const list = listFor([w.members[2] as Member]);
    const anchor = await readAnchor(ledgerWith(account.classicAddress, list.bytes) as never, 'AA'.repeat(32));
    expect(acceptServiceKey({ list, anchor, agentAccount: account.classicAddress, key: agentKey() }).holder).toBe(
      agentKey().holder,
    );
    expect(KEY_LIST_MEMO_TYPE).toBe(bytesToHex(new TextEncoder().encode('legx/service-key-list/v1')).toUpperCase());
  });

  it('refuses a swapped list, a list with no anchor, and an anchor from another account', async () => {
    const good = listFor([w.members[2] as Member]);
    const evil = makeMember(3, 'A', 'recovery-agent');
    const swapped = listFor([evil]);
    const anchorOfGood = await readAnchor(ledgerWith(account.classicAddress, good.bytes) as never, 'AA'.repeat(32));
    // the coordinator serves its own list; the anchor on the ledger is the real one
    expect(() =>
      acceptServiceKey({
        list: swapped,
        anchor: anchorOfGood,
        agentAccount: account.classicAddress,
        key: { ...agentKey(), edPub: evil.info.edPub },
      }),
    ).toThrow(/PIN_MISMATCH/);
    // no anchor at all
    const none = await readAnchor(ledgerWith(account.classicAddress, undefined) as never, 'AA'.repeat(32));
    expect(none).toBeUndefined();
    expect(() =>
      acceptServiceKey({ list: good, anchor: none, agentAccount: account.classicAddress, key: agentKey() }),
    ).toThrow(/PIN_MISMATCH/);
    // the coordinator anchors its own list from its own account
    const mine = await readAnchor(ledgerWith(other.classicAddress, swapped.bytes) as never, 'AA'.repeat(32));
    expect(() =>
      acceptServiceKey({
        list: swapped,
        anchor: mine,
        agentAccount: account.classicAddress,
        key: { ...agentKey(), edPub: evil.info.edPub },
      }),
    ).toThrow(/PIN_MISMATCH/);
    // a list signed by another key than the agent's account
    const forged = signKeyList(good.bytes, new Uint8Array(Buffer.from(other.privateKey.slice(2), 'hex')));
    expect(() =>
      acceptServiceKey({ list: forged, anchor: anchorOfGood, agentAccount: account.classicAddress, key: agentKey() }),
    ).toThrow(/LIST_SIGNER_WRONG/);
    // a key that is not in the list
    expect(() =>
      acceptServiceKey({
        list: good,
        anchor: anchorOfGood,
        agentAccount: account.classicAddress,
        key: { ...agentKey(), edPub: evil.info.edPub },
      }),
    ).toThrow(/KEY_NOT_PINNED/);
  });
});
