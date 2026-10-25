// P4.7-03, 06, 07, 08, 10: two-share signing on the phone with the second device over the relay, nonces in memory only.
import {
  aggregateChecked,
  FrostError,
  type KeyShare,
  SigningSession,
  slotAddress,
  slotPubkey,
  verifyEd25519Strict,
} from '@legx/core/frost';
import { verifyMultisigned } from '@legx/core/verify';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { encode, encodeForMultiSigning, type Transaction } from 'xrpl';
import { relayCoSigner, serveRelayCoSign } from '../../src/frost/cosign.ts';
import { createVault, messageFor } from '../../src/vault.ts';
import { binding, containsSecret, exitPayment, fakePrf, freshDb, rawRows } from '../helpers.ts';
import { clientDevices } from './devices.ts';

afterEach(() => vi.restoreAllMocks());

describe('P4.7-03 two-share signing on the phone', () => {
  it('Approve payment asks the second device, then gives a valid FROST signature under the slot key', async () => {
    const d = await clientDevices();
    const tx = exitPayment(d.deal);
    const sig = await d.phoneVault.signMultisig(d.id, tx);
    expect(d.approveState.asked).toBe(1);
    const msg = hexToBytes(encodeForMultiSigning(tx as unknown as Transaction, slotAddress(d.pub)));
    expect(verifyEd25519Strict(hexToBytes(sig), msg, slotPubkey(d.pub))).toBe(true);
    const signer = { Account: slotAddress(d.pub), SigningPubKey: upperHex(slotPubkey(d.pub)), TxnSignature: sig };
    const signed = { ...tx, Signers: [{ Signer: signer }] };
    expect(verifyMultisigned(encode(signed as unknown as Transaction), [slotAddress(d.pub)]).ok).toBe(true);
    await Promise.all(d.finished);
  });

  it('without the second-device approval there is no signature', async () => {
    const d = await clientDevices();
    d.approveState.ok = false;
    const from = d.relay.log.length;
    await expect(d.phoneVault.signFrost(d.id, binding(d.deal, 'A'))).rejects.toThrow('APPROVAL_REFUSED');
    expect(sentAfter(d, from, 'sign.begin')).toHaveLength(0);
    expect(sentAfter(d, from, 'sign.share')).toHaveLength(0);
  });
});

const upperHex = (b: Uint8Array): string => bytesToHex(b).toUpperCase();
/** Relay messages of `kind` sent after the log had `from` entries. */
const sentAfter = (d: { relay: { log: { payload: string }[] } }, from: number, kind: string) =>
  d.relay.log.slice(from).filter((m) => JSON.parse(atob(m.payload)).kind === kind);

describe('P4.7-06 nonces are held in memory only', () => {
  it('a session cannot be serialized or rebuilt, and no nonce, share or commitment secret is in storage', async () => {
    const d = await clientDevices();
    const msg = messageFor(d.pub, binding(d.deal, 'A'));
    const s = SigningSession.open(d.agentShare, d.pub, msg);
    expect(() => JSON.stringify(s)).toThrow('NOT_SERIALIZABLE');
    expect(structuredCloneFails(s)).toBe(true);
    // after a full signature, storage holds only ciphertext: no share, and nothing in localStorage or sessionStorage
    await d.phoneVault.signFrost(d.id, binding(d.deal, 'A'));
    const rows = [...(await rawRows(d.phone.dbName)), ...(await rawRows(d.second.dbName))];
    expect(containsSecret(rows, d.secrets)).toBe(false);
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it('a "reload" between commit and signShare: the pending session is gone and a new session uses new nonces', async () => {
    const d = await clientDevices();
    const port = d.secondVault.cosigner();
    const first = await port.commit({ dealId: d.id, request: binding(d.deal, 'A') });
    d.secondVault.close();
    // the page reloads: a new vault object over the same database knows no pending session
    const { createVault } = await import('../../src/vault.ts');
    const reloaded = createVault({
      role: 'alice',
      dbName: d.second.dbName,
      deals: async () => d.deal,
      approve: async () => true,
    });
    await expect(reloaded.cosigner().sign(first.session, [first.commitment, first.commitment])).rejects.toThrow(
      'NOT_FOUND',
    );
    const again = await reloaded.cosigner().commit({ dealId: d.id, request: binding(d.deal, 'A') });
    expect(again.commitment.hiding).not.toEqual(first.commitment.hiding);
  });
});

function structuredCloneFails(x: unknown): boolean {
  try {
    const c = structuredClone(x) as { commitment?: unknown };
    return c.commitment === undefined; // private fields are not cloned: nothing to rebuild a session from
  } catch {
    return true;
  }
}

describe('P4.7-07 a nonce set used for a second message', () => {
  it('signShare throws NONCE_USED for a second share and SESSION_MISMATCH for another message; the vault opens new sessions', async () => {
    const d = await clientDevices();
    const [s1, , s3] = d.clearShares as [KeyShare, KeyShare, KeyShare];
    const msg = messageFor(d.pub, binding(d.deal, 'A'));
    const a = SigningSession.open(s1, d.pub, msg);
    const b = SigningSession.open(s3, d.pub, msg);
    const list = [a.commitment, b.commitment];
    const ok = () => ({ ok: true }) as const;
    const z1 = a.signShare(msg, list, ok);
    expect(() => a.signShare(msg, list, ok)).toThrow(expect.objectContaining({ code: 'NONCE_USED' }));
    expect(() => a.signShare(randomBytes(32), list, ok)).toThrow(expect.objectContaining({ code: 'SESSION_MISMATCH' }));
    const sig = aggregateChecked(d.pub, list, msg, {
      [s1.identifier]: z1,
      [s3.identifier]: b.signShare(msg, list, ok),
    });
    expect(verifyEd25519Strict(sig, msg, slotPubkey(d.pub))).toBe(true);
    // two signatures in a row through the vault: each with fresh commitments
    await d.phoneVault.signFrost(d.id, binding(d.deal, 'A'));
    await d.phoneVault.signFrost(d.id, binding(d.deal, 'A'));
    const begins = d.relay.log.map((m) => JSON.parse(atob(m.payload))).filter((m) => m.kind === 'sign.begin');
    expect(new Set(begins.map((m) => m.commitment.hiding)).size).toBe(begins.length);
    await Promise.all(d.finished);
  });
});

describe('P4.7-08 a different message than the one the phone decoded', () => {
  it('the second device begins with other bytes: the phone gives no share and says why', async () => {
    const d = await clientDevices();
    const reasons: string[] = [];
    const evil = relayCoSigner({
      holder: d.phoneHolder,
      relay: d.relay,
      holders: d.holders,
      dealId: d.id,
      slot: 'A',
      remote: 2,
      messageOf: (r) => messageFor(d.pub, r),
      onRefused: (r) => reasons.push(r),
      start: async ({ sessionId }) => {
        const other = binding(d.deal, 'A'); // another binding the second device would happily sign
        const run = await serveRelayCoSign({
          holder: d.secondHolder,
          signer: {
            commit: ({ request }) => d.secondVault.cosigner().commit({ dealId: d.id, request }),
            sign: async () => new Uint8Array(32),
          },
          dealId: d.id,
          slot: 'A',
          sessionId,
          request: other,
          msg: messageFor(d.pub, other),
        });
        run.finished.catch(() => undefined); // it waits in vain for the phone's commitment
      },
    });
    const vault = createVault({
      role: 'alice',
      dbName: d.phone.dbName,
      deals: async () => d.deal,
      cosigner: () => evil,
    });
    const from = d.relay.log.length;
    await expect(vault.signFrost(d.id, binding(d.deal, 'A'))).rejects.toThrow('APPROVAL_REFUSED');
    expect(reasons[0]).toMatch(/MESSAGE_REFUSED/);
    expect(sentAfter(d, from, 'sign.commit')).toHaveLength(0);
  });

  it('a follower signs only the bytes it checked itself, and a relay that rewrites a message breaks its signature', async () => {
    const d = await clientDevices();
    const [s1, s2] = d.clearShares as [KeyShare, KeyShare];
    const mine = messageFor(d.pub, binding(d.deal, 'A'));
    const theirs = messageFor(d.pub, binding(d.deal, 'A'));
    const sid = await d.relay.openSession({ purpose: 'sign', holders: d.holders });
    const opts = { kind: 'tagged' as const, pub: d.pub, check: () => ({ ok: true }) as const, pair: [1, 2] as const };
    const [agg, fol] = await Promise.allSettled([
      d.phoneHolder.sign(sid, { ...opts, msg: theirs, share: s1 }),
      d.secondHolder.sign(sid, { ...opts, msg: mine, share: s2 }),
    ]);
    expect((fol as PromiseRejectedResult).reason).toMatchObject({ code: 'MESSAGE_REFUSED' });
    expect(agg.status).toBe('rejected');

    d.relay.deliver = (_to, rows) =>
      rows.map((r) => ({
        ...r,
        message: {
          ...r.message,
          payload: btoa(atob(r.message.payload).replace('"sign.begin"', '"sign.begin" ')) as never,
        },
      }));
    const sid2 = await d.relay.openSession({ purpose: 'sign', holders: d.holders });
    const [, f2] = await Promise.allSettled([
      d.phoneHolder.sign(sid2, { ...opts, msg: mine, share: s1 }),
      d.secondHolder.sign(sid2, { ...opts, msg: mine, share: s2 }),
    ]);
    expect((f2 as PromiseRejectedResult).reason).toMatchObject({ code: 'ENROLLMENT_SIG_INVALID' });
  });
});

describe('P4.7-10 every 2-of-3 pair of a client slot signs; one share alone cannot (T-P-01 in the browser)', () => {
  it('all three pairs verify; one share gives no valid signature', async () => {
    const d = await clientDevices();
    const shares = d.clearShares as KeyShare[];
    const msg = messageFor(d.pub, binding(d.deal, 'A'));
    const ok = () => ({ ok: true }) as const;
    for (const [i, j] of [
      [0, 1],
      [0, 2],
      [1, 2],
    ] as const) {
      const a = SigningSession.open(shares[i] as KeyShare, d.pub, msg);
      const b = SigningSession.open(shares[j] as KeyShare, d.pub, msg);
      const list = [a.commitment, b.commitment];
      const sig = aggregateChecked(d.pub, list, msg, {
        [a.commitment.identifier]: a.signShare(msg, list, ok),
        [b.commitment.identifier]: b.signShare(msg, list, ok),
      });
      expect(verifyEd25519Strict(sig, msg, slotPubkey(d.pub))).toBe(true);
    }
    const alone = SigningSession.open(shares[0] as KeyShare, d.pub, msg);
    expect(() => alone.signShare(msg, [alone.commitment], ok)).toThrow(
      expect.objectContaining({ code: 'BELOW_THRESHOLD' }),
    );
    expect(() =>
      aggregateChecked(d.pub, [alone.commitment], msg, { [alone.commitment.identifier]: randomBytes(32) }),
    ).toThrow(FrostError);
  });
});

describe('P4.7-03 with share 2 on a security key', () => {
  it('signs after the tap; a cancelled tap gives PASSKEY_REQUIRED and no signature', async () => {
    const d = await clientDevices();
    const prf = fakePrf();
    const [s1, s2] = d.clearShares as [KeyShare, KeyShare];
    const vault = createVault({ role: 'alice', dbName: freshDb(), deals: async () => d.deal, prf: prf.source });
    const credential = (await prf.source.register('security-key', { id: new Uint8Array(16), name: 'alice' }))
      .credential;
    await vault.storeShares({
      dealId: d.id,
      pub: d.pub,
      share1: { ...s1, signingShare: s1.signingShare.slice() },
      share2: { mode: 'security-key', credential, share: { ...s2, signingShare: s2.signingShare.slice() } },
    });
    expect(await vault.signFrost(d.id, binding(d.deal, 'A'))).toHaveLength(64);
    prf.state.fail = true; // the user cancels the security-key prompt
    await expect(vault.signFrost(d.id, binding(d.deal, 'A'))).rejects.toThrow('PASSKEY_REQUIRED');
  });
});
