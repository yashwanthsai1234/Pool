// P4.7-05, P4.7-21: a lawyer slot signs with the console share plus the firm HSM co-signer (task 3.10, mocked here),
// which needs the lawyer's user-verified WebAuthn approval over the same message hash. Real WebAuthn on Chromium.
import { type KeyShare, slotPubkey, verifyEd25519Strict } from '@legx/core/frost';
import { startRegistration } from '@simplewebauthn/browser';
import { afterEach, describe, expect, it } from 'vitest';
import { cdp, server } from 'vitest/browser';
import { type RequestApproval, webauthnApproval } from '../../src/frost/approval.ts';
import { relayCoSigner } from '../../src/frost/cosign.ts';
import { openerSessions, runSlotDkg } from '../../src/frost/dkg.ts';
import { keyDirectory } from '../../src/frost/pinning.ts';
import { createVault, messageFor } from '../../src/vault.ts';
import { binding, dealId, sealedDeal } from '../helpers.ts';
import { device, holderFor } from './devices.ts';
import { fakeApprover, mockHsm, RP_ID } from './hsm.ts';
import { MemoryRelay, party } from './world.ts';

async function lawyerDevices(approve: RequestApproval, approver: { p256Pub: Uint8Array; rpId: string }) {
  const id = dealId();
  const relay = new MemoryRelay();
  const consoleD = await device(id, 1, 'console', 'Your console');
  const hsm = party(2, 'firm-hsm', 'Firm HSM (Example LLP)');
  const partner = party(3, 'partner', 'Partner (J. Doe)');
  const holders = [consoleD.info, hsm.info, partner.info];
  relay.pin(...holders);
  const base = { dealId: id, slot: 'LA' as const, holders, relay, pinned: keyDirectory(holders), timeoutMs: 8_000 };
  const [c, h] = await Promise.all([
    runSlotDkg({ ...base, sessions: openerSessions(relay, holders), local: [{ index: 1, keys: consoleD.keys }] }),
    runSlotDkg({ ...base, sessions: relay.joiner(), local: [{ index: 2, keys: hsm.keys }] }),
    runSlotDkg({ ...base, sessions: relay.joiner(), local: [{ index: 3, keys: partner.keys }] }),
  ]);
  if (!c.ready || !h.ready) throw new Error('DKG');
  const pub = c.pub;
  const deal = sealedDeal(pub, 'LA');
  let hsmDeal = deal; // the HSM's own copy of the seal
  const hsmHolder = holderFor(relay, id, holders, 2, hsm.keys, 'LA');
  const firm = mockHsm({
    holder: hsmHolder,
    share: h.shares.get(2) as KeyShare,
    pub,
    deal: () => hsmDeal,
    dealId: id,
    approver,
  });
  const reasons: string[] = [];
  const cosigner = relayCoSigner({
    holder: holderFor(relay, id, holders, 1, consoleD.keys, 'LA'),
    relay,
    holders,
    dealId: id,
    slot: 'LA',
    remote: 2,
    messageOf: (r) => messageFor(pub, r),
    start: firm.start,
    approve,
    onRefused: (r) => reasons.push(r),
  });
  const vault = createVault({
    role: 'lawyerA',
    dbName: consoleD.dbName,
    deals: async () => deal,
    cosigner: () => cosigner,
  });
  await vault.storeShares({ dealId: id, pub, share1: c.shares.get(1) as KeyShare, share2: { mode: 'firm-hsm' } });
  const setHsmDeal = (d: typeof deal) => {
    hsmDeal = d;
  };
  return { id, pub, deal, setHsmDeal, vault, firm, reasons };
}

describe('P4.7-21 and P4.7-05 console share plus the firm HSM', () => {
  it('the HSM share is released only after the approval over the same hash; the signature verifies', async () => {
    const a = fakeApprover();
    const l = await lawyerDevices(a.approve, a.approver);
    const req = binding(l.deal, 'LA');
    const sig = await l.vault.signFrost(l.id, req);
    expect(verifyEd25519Strict(sig, messageFor(l.pub, req), slotPubkey(l.pub))).toBe(true);
    expect(a.calls).toHaveLength(1);
    expect(l.firm.decisions).toEqual([{ ok: true }]);
  });

  it('without the approval the console shows "Your firm\'s HSM needs your approval" and no share is released', async () => {
    const a = fakeApprover();
    const cancelled: RequestApproval = async () => {
      throw new Error('NotAllowedError');
    };
    const l = await lawyerDevices(cancelled, a.approver);
    await expect(l.vault.signFrost(l.id, binding(l.deal, 'LA'))).rejects.toThrow('APPROVAL_REFUSED');
    expect(l.reasons).toEqual(['APPROVAL_MISSING']);
    expect(l.firm.decisions).toEqual([]);
  });

  it('an approval without user verification, or for a transaction the seal does not allow, gets no share and a reason', async () => {
    const noUv = fakeApprover({ uv: false });
    const l = await lawyerDevices(noUv.approve, noUv.approver);
    await expect(l.vault.signFrost(l.id, binding(l.deal, 'LA'))).rejects.toThrow('APPROVAL_REFUSED');
    expect(l.reasons[0]).toBe('APPROVAL_NOT_UV');

    const a = fakeApprover();
    const m = await lawyerDevices(a.approve, a.approver);
    // the console's copy of the seal allows this exit; the HSM's own copy names another payout, so it refuses
    m.setHsmDeal({ ...m.deal, payoutB: { account: m.deal.payoutA.account } });
    const tx = {
      TransactionType: 'Payment',
      Account: m.deal.walletAddress,
      Destination: m.deal.payoutB.account,
      DestinationTag: m.deal.payoutB.tag as number,
      Amount: m.deal.exitAmountDrops,
      Fee: '12',
      Sequence: 5,
      SigningPubKey: '',
    };
    await expect(m.vault.signMultisig(m.id, tx)).rejects.toThrow('APPROVAL_REFUSED');
    expect(m.reasons).toEqual(['destination']);
    expect(m.firm.decisions).toEqual([{ ok: false, reason: 'destination' }]);
  });
});

describe.runIf(server.browser === 'chromium')('P4.7-21 real WebAuthn approval (CDP virtual authenticator)', () => {
  let authenticatorId = '';
  afterEach(async () => {
    if (authenticatorId) await cdp().send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  });

  it('requestApproval(hash) gives a user-verified assertion the HSM accepts', async () => {
    await cdp().send('WebAuthn.enable', { enableUI: false });
    ({ authenticatorId } = (await cdp().send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    })) as { authenticatorId: string });
    const reg = await startRegistration({
      optionsJSON: {
        challenge: 'AAAAAAAAAAAAAAAAAAAAAA',
        rp: { id: RP_ID, name: 'LegX console' },
        user: { id: 'bGF3eWVy', name: 'lawyerA', displayName: 'Lawyer A' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { userVerification: 'required', residentKey: 'discouraged' },
      },
    });
    const spki = Uint8Array.from(atob((reg.response.publicKey as string).replace(/-/g, '+').replace(/_/g, '/')), (c) =>
      c.charCodeAt(0),
    );
    const approver = { p256Pub: spki.slice(-65), rpId: RP_ID };
    const approve = webauthnApproval(RP_ID, { id: reg.id, transports: reg.response.transports ?? [] });
    const l = await lawyerDevices(approve, approver);
    const req = binding(l.deal, 'LA');
    const sig = await l.vault.signFrost(l.id, req);
    expect(verifyEd25519Strict(sig, messageFor(l.pub, req), slotPubkey(l.pub))).toBe(true);
    await cdp().send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
    await expect(l.vault.signFrost(l.id, binding(l.deal, 'LA'))).rejects.toThrow('APPROVAL_REFUSED');
  });
});
