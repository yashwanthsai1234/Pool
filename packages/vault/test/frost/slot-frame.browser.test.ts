// I-W-10 slot port: a lawyer slot signs with the console share plus the firm HSM, and the whole signing round runs inside
// the vault frame. Over a MessageChannel the app sees only relay messages, the HSM start call and the signature. The frame
// checks the request against its own seal before any share is opened, and the lawyer's approval must be over its hash.
import { holderId, type KeyShare, slotPubkey, verifyEd25519Strict } from '@legx/core/frost';
import type { SealedDeal } from '@legx/core/frostRules';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import { vaultFrameHost } from '../../src/frame-host.ts';
import { openerSessions, runSlotDkg } from '../../src/frost/dkg.ts';
import { keyDirectory } from '../../src/frost/pinning.ts';
import { connectVault, serveVault } from '../../src/protocol.ts';
import { createVault, messageFor } from '../../src/vault.ts';
import { binding, dealId, freshDb, sealedDeal } from '../helpers.ts';
import { holderFor } from './devices.ts';
import { fakeApprover, mockHsm } from './hsm.ts';
import { MemoryRelay, party } from './world.ts';

async function world(opts: { approve?: ReturnType<typeof fakeApprover> } = {}) {
  const id = dealId();
  const relay = new MemoryRelay();
  const dbName = freshDb();
  let deal = undefined as unknown as SealedDeal;
  const vault = createVault({ role: 'lawyerA', dbName, deals: async () => deal });
  const { port1, port2 } = new MessageChannel();
  serveVault(port2, vault, vaultFrameHost({ role: 'lawyerA', dbName }));
  const app = connectVault(port1);
  const pub = await app.enroll(id, 'pair-A');
  const hsm = party(2, 'firm-hsm', 'Firm HSM (Example LLP)');
  const partner = party(3, 'partner', 'Partner (J. Doe)');
  const consoleInfo = {
    identifier: holderId(1),
    keyId: 'pair-A',
    role: 'console' as const,
    edPub: new Uint8Array([0xed, ...pub.ed25519]),
    pqPub: pub.mlDsa65,
    deviceId: 'console',
    label: 'Your console',
  };
  const holders = [consoleInfo, hsm.info, partner.info];
  relay.pin(...holders);
  const base = { dealId: id, slot: 'LA' as const, holders, relay, pinned: keyDirectory(holders), timeoutMs: 8_000 };
  const [c, h] = await Promise.all([
    app.dkg(
      { dealId: id, slot: 'LA', holders, localIndex: 1, keyId: 'pair-A', share2: 'firm-hsm', timeoutMs: 8_000 },
      { relay, sessions: openerSessions(relay, holders) },
    ),
    runSlotDkg({ ...base, sessions: relay.joiner(), local: [{ index: 2, keys: hsm.keys }] }),
    runSlotDkg({ ...base, sessions: relay.joiner(), local: [{ index: 3, keys: partner.keys }] }),
  ]);
  if (!c.ready || !h.ready) throw new Error('DKG');
  const slotPub = c.pub as never;
  deal = sealedDeal(slotPub, 'LA');
  let hsmDeal = deal;
  const approver = opts.approve ?? fakeApprover();
  const firm = mockHsm({
    holder: holderFor(relay, id, holders, 2, hsm.keys, 'LA'),
    share: h.shares.get(2) as KeyShare,
    pub: slotPub,
    deal: () => hsmDeal,
    dealId: id,
    approver: approver.approver,
  });
  const args = (request: ReturnType<typeof binding>, approval: Awaited<ReturnType<typeof approver.approve>>) => ({
    dealId: id,
    slot: 'LA' as const,
    holders,
    localIndex: 1,
    remote: 2,
    keyId: 'pair-A',
    request,
    approval,
    timeoutMs: 8_000,
  });
  const io = { relay, start: firm.start };
  return {
    id,
    app,
    pub: slotPub,
    deal: () => deal,
    firm,
    approver,
    args,
    io,
    setHsmDeal: (d: SealedDeal) => (hsmDeal = d),
  };
}

describe('the lawyer slot signs in the vault frame with the firm HSM', () => {
  it('signs after the approval over the same hash: the signature verifies under the slot key', async () => {
    const w = await world();
    const request = binding(w.deal(), 'LA');
    const approval = await w.approver.approve(sha256(messageFor(w.pub, request)));
    const sig = await w.app.signSlot(w.args(request, approval), w.io);
    expect(verifyEd25519Strict(sig, messageFor(w.pub, request), slotPubkey(w.pub))).toBe(true);
    expect(w.firm.decisions).toEqual([{ ok: true }]);
  });

  it('refuses an approval over another hash before the HSM is asked', async () => {
    const w = await world();
    const request = binding(w.deal(), 'LA');
    const approval = await w.approver.approve(new Uint8Array(32).fill(7));
    await expect(w.app.signSlot(w.args(request, approval), w.io)).rejects.toMatchObject({ code: 'APPROVAL_REFUSED' });
    expect(w.firm.decisions).toEqual([]);
  });

  it('refuses a request the frame seal does not allow, before any share is opened or the HSM asked', async () => {
    const w = await world();
    const request = {
      kind: 'xrpl-multisign' as const,
      tx: { TransactionType: 'AccountSet', Account: w.deal().walletAddress },
    };
    const approval = await w.approver.approve(new Uint8Array(32));
    await expect(w.app.signSlot(w.args(request as never, approval), w.io)).rejects.toMatchObject({
      code: 'MESSAGE_REFUSED',
    });
    expect(w.firm.decisions).toEqual([]);
  });

  it('a refusal by the HSM is APPROVAL_REFUSED', async () => {
    const w = await world();
    const request = binding(w.deal(), 'LA');
    const approval = await w.approver.approve(sha256(messageFor(w.pub, request)));
    w.setHsmDeal({ ...w.deal(), contractRoot: new Uint8Array(32) });
    await expect(w.app.signSlot(w.args(request, approval), w.io)).rejects.toMatchObject({ code: 'APPROVAL_REFUSED' });
  });

  it('refuses when the frame has no ceremony host', async () => {
    const w = await world();
    const { port1, port2 } = new MessageChannel();
    serveVault(port2, createVault({ role: 'lawyerA', dbName: freshDb(), deals: async () => w.deal() }));
    const request = binding(w.deal(), 'LA');
    const approval = await w.approver.approve(new Uint8Array(32));
    await expect(connectVault(port1).signSlot(w.args(request, approval), w.io)).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });
});
