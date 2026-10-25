// The signing, recovery, refresh and rotation screens (P4.7-03, 05, 07, 16, 17, 19, 20, 21, 22) on Chromium and WebKit,
// over MSW (the recovery routes and the firm HSM endpoint) and the in-memory relay, plus the empty states of the routes.
import type { ZkVerification } from '@legx/contracts/records';
import type { KeyShare } from '@legx/core/frost';
import type { FrostRefreshed } from '@legx/core/frostRefresh';
import { xwingShareCipher } from '@legx/vault/frost/cipher';
import { FIRM_HSM_SIGN_PATH, httpStart, relayCoSigner, requestFromJson } from '@legx/vault/frost/cosign';
import { openerSessions, runSlotDkg } from '@legx/vault/frost/dkg';
import { FrostHolder } from '@legx/vault/frost/holder';
import { keyDirectory } from '@legx/vault/frost/pinning';
import type { RecoveryApi } from '@legx/vault/frost/recovery';
import { refreshSlot } from '@legx/vault/frost/refresh';
import { createVault, messageFor } from '@legx/vault/vault';
import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import axe from 'axe-core';
import { HttpResponse, http } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { clientDevices, device, holderFor } from '../../../../packages/vault/test/frost/devices.ts';
import { fakeApprover, mockHsm } from '../../../../packages/vault/test/frost/hsm.ts';
import { MemoryRelay, party } from '../../../../packages/vault/test/frost/world.ts';
import { binding, dealId, sealedDeal } from '../../../../packages/vault/test/helpers.ts';
import { createQueryClient } from '../../src/lib/query.ts';
import { startMocks } from '../../src/mocks/browser.ts';
import { examplesOf } from '../../src/mocks/examples.ts';
import { createAppRouter } from '../../src/router.tsx';
import { RecoveryNotice, RecoveryScreen } from '../../src/routes/party/frost/-screens/recovery.tsx';
import { RefreshScreen } from '../../src/routes/party/frost/-screens/refresh.tsx';
import { RotationScreen } from '../../src/routes/party/frost/-screens/rotation.tsx';
import { SignScreen } from '../../src/routes/party/frost/-screens/sign.tsx';
import { api, fallback, ledger, recoveryHandlers, type Worker } from './harness.ts';
import '../../src/index.css';

vi.setConfig({ testTimeout: 40_000 });
let worker: Worker;
beforeAll(async () => {
  worker = await startMocks(...fallback());
});
afterEach(() => worker.resetHandlers());
afterAll(() => worker.stop());

describe('P4.7-03 and P4.7-07 the Approve screen on the phone', () => {
  it('asks the second device, signs, and says which holders took part', async () => {
    const d = await clientDevices();
    await render(
      <SignScreen
        summary="Pay 25 XRP to Bob"
        second="second-device"
        holders={['Your phone', 'Your second device']}
        sign={() => d.phoneVault.signFrost(d.id, binding(d.deal, 'A'))}
      />,
    );
    await page.getByRole('button', { name: 'Approve payment' }).click();
    await expect
      .element(page.getByRole('status'))
      .toMatchTextContent('Signed by Your phone and Your second device. The recovery agent was not needed.');
    expect(d.approveState.asked).toBe(1);
    await Promise.all(d.finished);
  });

  it('a refused approval or a failed session shows the error, and Try again starts a new session', async () => {
    const d = await clientDevices();
    d.approveState.ok = false;
    await render(
      <SignScreen
        summary="Pay 25 XRP to Bob"
        second="second-device"
        holders={['Your phone', 'Your second device']}
        sign={() => d.phoneVault.signFrost(d.id, binding(d.deal, 'A'))}
      />,
    );
    await page.getByRole('button', { name: 'Approve payment' }).click();
    await expect
      .element(page.getByRole('alert'))
      .toMatchTextContent('Your second device did not approve. Nothing was signed.');
    d.approveState.ok = true;
    await page.getByRole('button', { name: 'Try again' }).click();
    await expect.element(page.getByRole('status')).toMatchTextContent('Signed by Your phone and Your second device');
    await Promise.all(d.finished);
  });

  it('a nonce error is shown, and the next attempt is a new session', async () => {
    let n = 0;
    await render(
      <SignScreen
        summary="Pay 25 XRP to Bob"
        second="security-key"
        holders={['Your phone', 'Your security key']}
        sign={async () => {
          if (n++ === 0) throw Object.assign(new Error('NONCE_USED'), { code: 'NONCE_USED' });
        }}
      />,
    );
    await page.getByRole('button', { name: 'Approve payment' }).click();
    await expect
      .element(page.getByRole('alert'))
      .toMatchTextContent('Signing failed (NONCE_USED). A new signing session starts when you try again.');
    await page.getByRole('button', { name: 'Try again' }).click();
    await expect.element(page.getByRole('status')).toMatchTextContent('Signed by');
  });
});

/** A lawyer slot whose firm HSM sits behind MSW at the co-signer endpoint (task 3.10 mocked). */
async function lawyerSlot(approve: ReturnType<typeof fakeApprover>, approverKey = approve.approver) {
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
  const deal = sealedDeal(c.pub, 'LA');
  const firm = mockHsm({
    holder: holderFor(relay, id, holders, 2, hsm.keys, 'LA'),
    share: h.shares.get(2) as KeyShare,
    pub: c.pub,
    deal: () => deal,
    dealId: id,
    approver: approverKey,
  });
  worker.use(
    http.post(`*/api${FIRM_HSM_SIGN_PATH}`, async ({ request }) => {
      const body = (await request.json()) as { sessionId: string; request: never; approval?: never };
      try {
        await firm.start({
          sessionId: body.sessionId,
          request: requestFromJson(body.request),
          ...(body.approval ? { approval: body.approval } : {}),
        });
        return HttpResponse.json({ ok: true });
      } catch (e) {
        return HttpResponse.json({ reason: (e as Error).message }, { status: 403 });
      }
    }),
  );
  const reasons: string[] = [];
  const cosigner = relayCoSigner({
    holder: holderFor(relay, id, holders, 1, consoleD.keys, 'LA'),
    relay,
    holders,
    dealId: id,
    slot: 'LA',
    remote: 2,
    messageOf: (r) => messageFor(c.pub, r),
    start: httpStart(`/api${FIRM_HSM_SIGN_PATH}`, id),
    approve: approve.approve,
    onRefused: (r) => reasons.push(r),
  });
  const vault = createVault({
    role: 'lawyerA',
    dbName: consoleD.dbName,
    deals: async () => deal,
    cosigner: () => cosigner,
  });
  await vault.storeShares({
    dealId: id,
    pub: c.pub,
    share1: c.shares.get(1) as KeyShare,
    share2: { mode: 'firm-hsm' },
  });
  return { id, deal, vault, firm, reasons };
}

const lawyerScreen = (l: Awaited<ReturnType<typeof lawyerSlot>>) =>
  render(
    <SignScreen
      summary="Contract signature"
      second="firm-hsm"
      holders={['Your console', 'Firm HSM (Example LLP)']}
      sign={() => l.vault.signFrost(l.id, binding(l.deal, 'LA'))}
      refusal={() => l.reasons.at(-1)}
    />,
  );

describe('P4.7-21 and P4.7-05 the lawyer slot: console share plus the firm HSM', () => {
  it('signs after the approval, through the HSM endpoint', async () => {
    const a = fakeApprover();
    const l = await lawyerSlot(a);
    await lawyerScreen(l);
    await page.getByRole('button', { name: 'Approve payment' }).click();
    await expect
      .element(page.getByRole('status'))
      .toMatchTextContent('Signed by Your console and Firm HSM (Example LLP)');
    expect(a.calls).toHaveLength(1);
  });

  it('without the approval: "Your firm\'s HSM needs your approval", and the HSM released nothing', async () => {
    const a = fakeApprover();
    const l = await lawyerSlot({ ...a, approve: () => Promise.reject(new Error('cancelled')) });
    await lawyerScreen(l);
    await page.getByRole('button', { name: 'Approve payment' }).click();
    await expect
      .element(page.getByRole('alert'))
      .toMatchTextContent("Your firm's HSM needs your approval. Nothing was signed.");
    expect(l.firm.decisions).toEqual([]);
  });

  it('an approval by another credential: the HSM refuses and the console shows the reason', async () => {
    const l = await lawyerSlot(fakeApprover(), fakeApprover().approver);
    await lawyerScreen(l);
    await page.getByRole('button', { name: 'Approve payment' }).click();
    await expect
      .element(page.getByRole('alert'))
      .toMatchTextContent("Your firm's HSM refused: APPROVAL_SIG_INVALID. Nothing was signed.");
  });
});

// ---------- recovery ----------

const ZK = examplesOf('ZkVerification')[0] as ZkVerification;
const DEAL = '0192f3a0-0000-7000-8000-0000000000dd';
const proof =
  (over: { id?: string; face?: boolean; ageMs?: number } = {}) =>
  async () => ({
    verification: { ...ZK, uniqueIdentifier: over.id ?? 'ID-ALICE' },
    provedAt: ledger.now - (over.ageMs ?? 60_000),
    faceMatch: over.face ?? true,
  });
const recoveryApi = api as unknown as RecoveryApi;
const COMPLETE: FrostRefreshed = {
  kind: 'frost.refreshed',
  status: 'COMPLETE',
  missing: [],
  oldVerifyingShares: {},
  newVerifyingShares: {},
  statements: [],
};

function recoveryScreen(repairAndRefresh = vi.fn(async () => COMPLETE), getProof = proof(), singleDevice = false) {
  return render(
    <RecoveryScreen
      dealId={DEAL}
      slot="A"
      newKeyId="key-new-phone"
      onboardingIdentifier="ID-ALICE"
      agentLabel="Example Recovery Ltd"
      singleDevice={singleDevice}
      api={recoveryApi}
      ledgerNow={() => ledger.now}
      getProof={getProof}
      repairAndRefresh={repairAndRefresh}
      pollMs={50}
    />,
  );
}

describe('P4.7-16 the recovery screen on the new phone', () => {
  it('refuses a proof for another identifier, without a face match, or stale, with a reason', async () => {
    worker.use(...recoveryHandlers().handlers);
    for (const [p, reason] of [
      [proof({ id: 'ID-MALLORY' }), 'This passport proof is for another person than the one who onboarded.'],
      [proof({ face: false }), 'The proof has no face match. Scan again and complete the face check.'],
      [proof({ ageMs: 11 * 60_000 }), 'The proof is older than 10 minutes. Make a fresh one.'],
    ] as const) {
      const r = await recoveryScreen(vi.fn(), p);
      await page.getByRole('button', { name: 'Scan your passport' }).click();
      await expect.element(page.getByRole('alert')).toHaveTextContent(reason);
      await r.unmount();
    }
  });

  it('shows the 72-hour countdown and who was told; no recovery share is used before the delay ends', async () => {
    worker.use(...recoveryHandlers().handlers);
    const repair = vi.fn(async () => COMPLETE);
    await recoveryScreen(repair);
    await page.getByRole('button', { name: 'Scan your passport' }).click();
    await expect.element(page.getByTestId('countdown')).toHaveTextContent('72 h 00 min');
    await expect
      .element(page.getByText('We told your old device, Lawyer A, Lawyer B.', { exact: false }))
      .toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Repair and refresh' })).toBeDisabled();
    ledger.now += 71 * 3600_000;
    await expect.element(page.getByTestId('countdown')).toHaveTextContent('1 h 00 min');
    expect(repair).not.toHaveBeenCalled();
    ledger.now += 3600_000;
    await expect.element(page.getByRole('button', { name: 'Repair and refresh' })).toBeEnabled();
    await page.getByRole('button', { name: 'Repair and refresh' }).click();
    await expect.element(page.getByText(/Refresh complete/)).toBeVisible();
    await expect.element(page.getByText(/hygiene, not revocation/)).toBeVisible();
    expect(repair).toHaveBeenCalledOnce();
  });

  it('P4.7-19 recovering in single-device mode says the theft protection is lost', async () => {
    await recoveryScreen(undefined, proof(), true);
    await expect
      .element(page.getByRole('note'))
      .toMatchTextContent('Recovering in this mode means a thief with this phone needs nothing more.');
  });
});

describe('P4.7-17 the old device cancels during the delay', () => {
  it('the new phone says it was cancelled; a lawyer console shows the notice and the cancel', async () => {
    const rec = recoveryHandlers();
    worker.use(...rec.handlers);
    const repair = vi.fn(async () => COMPLETE);
    const phone = await recoveryScreen(repair);
    await page.getByRole('button', { name: 'Scan your passport' }).click();
    await expect.element(page.getByTestId('countdown')).toBeVisible();
    const recoveryId = [...rec.recoveries.keys()][0] as string;
    const notice = (canCancel: boolean) => (
      <RecoveryNotice
        dealId={DEAL}
        recoveryId={recoveryId}
        api={recoveryApi}
        ledgerNow={() => ledger.now}
        canCancel={canCancel}
        pollMs={50}
      />
    );
    const lawyer = await render(notice(false));
    await expect
      .element(lawyer.getByRole('alert'))
      .toMatchTextContent('Someone started recovering slot A on a new phone.');
    await expect.element(page.getByRole('button', { name: /cancel the recovery/ })).not.toBeInTheDocument();
    const old = await render(notice(true));
    await old.getByRole('button', { name: 'This was not me: cancel the recovery' }).click();
    // both the old device and the lawyer's console now show the cancel
    await expect.poll(() => page.getByText('Recovery cancelled by the old device.').all().length).toBe(2);
    await expect.element(phone.getByText('This recovery was cancelled from your old device.')).toBeVisible();
    expect([...rec.recoveries.values()][0]?.state).toBe('cancelled');
    ledger.now += 73 * 3600_000;
    await expect.element(phone.getByRole('button', { name: 'Repair and refresh' })).toBeDisabled();
    expect(repair).not.toHaveBeenCalled();
  });
});

// ---------- refresh and rotation ----------

describe('P4.7-22 the refresh screen', () => {
  async function run(agentSigns: boolean) {
    const d = await clientDevices();
    const agent = new FrostHolder({
      index: 3,
      keys: d.agent.keys,
      dealId: d.id,
      slot: 'A',
      holders: d.holders,
      relay: d.relay,
      cipher: xwingShareCipher,
      pinned: keyDirectory(d.holders),
      timeoutMs: 8_000,
    });
    const base = {
      dealId: d.id,
      slot: 'A' as const,
      holders: d.holders,
      relay: d.relay,
      pinned: keyDirectory(d.holders),
      epoch: 1,
      timeoutMs: 2_000,
    };
    const others = Promise.allSettled([
      refreshSlot({
        ...base,
        sessions: d.relay.joiner(),
        local: [{ index: 2, keys: d.second.keys }],
        vault: d.secondVault,
      }),
      (async () => {
        const sid = await d.relay.joiner()('refresh');
        const o = await agent.refresh(sid, { share: d.agentShare, pub: d.pub, participants: [1, 2, 3], epoch: 1 });
        if (agentSigns) await agent.signDeletion(sid, o.ctx, o.pub, 1);
      })(),
    ]);
    await render(
      <RefreshScreen
        run={(onEvent) =>
          refreshSlot({
            ...base,
            sessions: openerSessions(d.relay, d.holders),
            local: [{ index: 1, keys: d.phone.keys }],
            vault: d.phoneVault,
            onEvent,
          })
        }
      />,
    );
    await expect.element(page.getByRole('note')).toMatchTextContent(/hygiene, not revocation/);
    await page.getByRole('button', { name: 'Start the refresh' }).click();
    return others;
  }

  it('"refresh complete" only once every holder deleted its old share', async () => {
    const others = await run(true);
    await expect.element(page.getByText('Refresh complete.')).toBeVisible();
    const items = page.getByRole('list', { name: 'Deletion statements' }).getByRole('listitem');
    await expect
      .element(items.nth(2))
      .toMatchTextContent('Recovery agent (Example Recovery Ltd) deleted the old share');
    await others;
  });

  it('a missing deletion statement: not complete, and the screen says who it waits for', async () => {
    const others = await run(false);
    await expect.element(page.getByText(/^Not complete yet/)).toBeVisible();
    await expect
      .element(page.getByText('waiting for Recovery agent (Example Recovery Ltd)', { exact: false }))
      .toBeVisible();
    await expect.element(page.getByText('Refresh complete.')).not.toBeInTheDocument();
    await others;
  });
});

describe('P4.7-20 the rotation screen', () => {
  it('each step has its own check; the old key is retired only after the ledger validated the new signer list', async () => {
    let validate: (v: string) => void = () => undefined;
    const ledgerValidated = new Promise<string>((r) => {
      validate = r;
    });
    await render(
      <RotationScreen
        slot="LA"
        steps={{
          'new-dkg': async () => 'all three pairs test-signed',
          'signer-list-set-4-of-4': () => ledgerValidated,
          'new-seal': async () => 'seal verified',
          'new-contract-signatures': async () => 'both lawyers signed',
          'new-nft': async () => 'NFT minted in ledger 812',
        }}
      />,
    );
    await page.getByRole('button', { name: 'Start the rotation' }).click();
    const steps = page.getByRole('list', { name: 'Rotation steps' }).getByRole('listitem');
    await expect.element(steps.nth(0)).toMatchTextContent('all three pairs test-signed');
    await expect.element(page.getByText('The old slot key is still active.')).toBeVisible();
    validate('validated in ledger 811');
    await expect.element(steps.nth(1)).toMatchTextContent('validated in ledger 811');
    await expect.element(page.getByText('The old slot key is retired.')).toBeVisible();
    await expect.element(steps.nth(4)).toMatchTextContent('NFT minted in ledger 812');
  });

  it('a failed ledger step stops the rotation and the old key stays active', async () => {
    await render(
      <RotationScreen
        slot="A"
        steps={{
          'new-dkg': async () => 'ok',
          'signer-list-set-4-of-4': () => Promise.reject(new Error('tefBAD_QUORUM')),
        }}
      />,
    );
    await page.getByRole('button', { name: 'Start the rotation' }).click();
    await expect.element(page.getByText('tefBAD_QUORUM')).toBeVisible();
    await expect.element(page.getByText('The old slot key is still active.')).toBeVisible();
    await expect.element(page.getByRole('list', { name: 'Rotation steps' }).getByRole('listitem')).toHaveLength(3);
  });
});

describe('the FROST routes with nothing wired', () => {
  for (const path of [
    '/party/frost/dkg',
    '/party/frost/sign',
    '/party/frost/recovery',
    '/party/frost/recovery-notice',
    '/party/frost/refresh',
    '/party/frost/rotation',
    '/lawyers/frost/dkg',
    '/lawyers/frost/sign',
    '/lawyers/frost/recoveries',
    '/lawyers/frost/rotation',
  ]) {
    it(`${path} shows its empty state with no serious axe violation`, async () => {
      const queryClient = createQueryClient();
      const screen = await render(
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={createAppRouter(queryClient, path)} />
        </QueryClientProvider>,
      );
      await expect.element(page.getByRole('heading', { name: 'Nothing to do here yet' })).toBeVisible();
      const results = await axe.run(screen.container);
      expect(results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
    });
  }
});
