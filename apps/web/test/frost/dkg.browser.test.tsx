// The DKG screens (P4.7-01, 02, 13, 14, 15, 19) on Chromium and WebKit. The phone talks to the relay through the typed
// API client and MSW; the other holders (second device, recovery agent, or console side holders) run the same browser
// code against the in-memory relay directly.
import { type FrostMsg, holderId, THRESHOLD } from '@legx/core/frost';
import { xwingShareCipher } from '@legx/vault/frost/cipher';
import { type DkgEvent, type DkgResult, openerSessions, runSlotDkg } from '@legx/vault/frost/dkg';
import { FrostHolder } from '@legx/vault/frost/holder';
import { checkDevicePin, devicePinCode, fingerprint, keyDirectory } from '@legx/vault/frost/pinning';
import { type HolderInfo, signRelayMessage, toWire } from '@legx/vault/frost/wire';
import { SINGLE_DEVICE_LABEL } from '@legx/vault/rules';
import { createVault } from '@legx/vault/vault';
import { ed25519_FROST } from '@noble/curves/ed25519.js';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { device } from '../../../../packages/vault/test/frost/devices.ts';
import { MemoryRelay, type Party, party } from '../../../../packages/vault/test/frost/world.ts';
import { dealId } from '../../../../packages/vault/test/helpers.ts';
import { startMocks } from '../../src/mocks/browser.ts';
import { DkgScreen } from '../../src/routes/party/frost/-screens/dkg.tsx';
import { fallback, phoneRelay, relayHandlers, type Worker } from './harness.ts';
import '../../src/index.css';

vi.setConfig({ testTimeout: 90_000 });

let worker: Worker;
beforeAll(async () => {
  worker = await startMocks(...fallback());
});
afterEach(() => worker.resetHandlers());
afterAll(() => worker.stop());

type Remote = { p: Party; tamper?: (m: FrostMsg) => FrostMsg | Promise<FrostMsg> };

/** A client slot: the phone on screen; the second device and the agent run against the relay. */
async function world(opts: { singleDevice?: boolean } = {}) {
  const id = dealId();
  const relay = new MemoryRelay();
  worker.use(...relayHandlers(relay));
  const phone = await device(id, 1, 'phone', 'Your phone');
  const second = party(
    2,
    opts.singleDevice ? 'passkey-same-device' : 'second-authenticator',
    opts.singleDevice ? 'Passkey on this phone' : 'Your second device',
  );
  const agent = party(3, 'recovery-agent', 'Recovery agent (Example Recovery Ltd)');
  const holders: HolderInfo[] = [phone.info, second.info, agent.info];
  relay.pin(...holders);
  const vault = createVault({
    role: 'alice',
    dbName: phone.dbName,
    deals: () => Promise.reject(new Error('no seal yet')),
  });
  return { id, relay, phone, second, agent, holders, vault };
}
type World = Awaited<ReturnType<typeof world>>;

/** The remote holders' side: plain `runSlotDkg`, or a scripted holder with a tamper hook. */
function remote(w: World, r: Remote, holders = w.holders) {
  const index = Number(r.p.info.identifier === holderId(2) ? 2 : 3);
  if (r.tamper) {
    const h = new FrostHolder({
      index,
      keys: r.p.keys,
      dealId: w.id,
      slot: 'A',
      holders,
      relay: w.relay,
      cipher: xwingShareCipher,
      pinned: keyDirectory(holders),
      timeoutMs: 4_000,
    });
    return w.relay
      .joiner()('dkg')
      .then((sid) => h.dkg(sid, { tamper: r.tamper }));
  }
  return runSlotDkg({
    dealId: w.id,
    slot: 'A',
    holders,
    relay: w.relay,
    sessions: w.relay.joiner(),
    pinned: keyDirectory(holders),
    local: [{ index, keys: r.p.keys }],
    timeoutMs: 4_000,
  });
}

/** The phone's ceremony as the screen runs it: through MSW, storing share 1 only when the slot is ready. */
const phoneRun =
  (w: World, pinned = keyDirectory(w.holders)) =>
  async (onEvent: (e: DkgEvent) => void) => {
    const relay = phoneRelay(w.id, 'A');
    const r = await runSlotDkg({
      dealId: w.id,
      slot: 'A',
      holders: w.holders,
      relay,
      sessions: openerSessions(relay, w.holders),
      pinned,
      local: [{ index: 1, keys: w.phone.keys }],
      onEvent,
      timeoutMs: 4_000,
    });
    if (r.ready)
      await w.vault.storeShares({
        dealId: w.id,
        pub: r.pub,
        share1: r.shares.get(1) as never,
        share2: { mode: 'second-device' },
      });
    return r;
  };

const screen = (w: World, over: Partial<Parameters<typeof DkgScreen>[0]> = {}) =>
  render(
    <DkgScreen
      slot="A"
      holders={w.holders.map((h) => ({ label: h.label, fingerprint: fingerprint(h.edPub) }))}
      run={phoneRun(w)}
      {...over}
    />,
  );

const start = () => page.getByRole('button', { name: 'Start key setup' }).click();

describe('P4.7-01 the client DKG screen', () => {
  it('runs through the relay, shows three green pairs by name and the key fingerprint; share 1 is stored', async () => {
    const w = await world();
    await screen(w);
    const others = Promise.all([remote(w, { p: w.second }), remote(w, { p: w.agent })]);
    await start();
    await expect.element(page.getByText(/^Slot key ready/), { timeout: 15_000 }).toBeVisible();
    const pairs = page.getByRole('list', { name: 'Test signatures' }).getByRole('listitem');
    await expect.element(pairs.nth(0)).toHaveTextContent('PASS Your phone + Your second device');
    await expect.element(pairs.nth(1)).toHaveTextContent('PASS Your phone + Recovery agent (Example Recovery Ltd)');
    await expect
      .element(pairs.nth(2))
      .toHaveTextContent('PASS Your second device + Recovery agent (Example Recovery Ltd)');
    const [second] = (await others) as DkgResult[];
    if (!second?.ready) throw new Error('second device not ready');
    await expect
      .element(page.getByText(fingerprint(new Uint8Array([0xed, ...(second.pub.commitments[0] as Uint8Array)]))))
      .toBeVisible();
    expect(await w.vault.list()).toMatchObject([{ hasShare1: true, mode: 'second-device' }]);
  });
});

describe('P4.7-02 a bad share: abort, the party named, a complaint shown and sent, nothing stored', () => {
  it('names the second device and says a signed complaint went out', async () => {
    const w = await world();
    await screen(w);
    const others = Promise.allSettled([
      remote(w, {
        p: w.second,
        tamper: (m) =>
          m.kind === 'dkg-r2' && m.to === 1
            ? { ...m, fields: [(m.fields[0] as Uint8Array).map((b, i) => (i === 1130 ? b ^ 1 : b))] }
            : m,
      }),
      remote(w, { p: w.agent }),
    ]);
    await start();
    await expect.element(page.getByText('Cause: Your second device.'), { timeout: 60_000 }).toBeVisible();
    await expect.element(page.getByText('A signed complaint was sent to every holder.')).toBeVisible();
    await others;
    expect(w.relay.log.some((m) => atob(m.payload).includes('"dkg.complaint"'))).toBe(true);
    expect(await w.vault.list()).toEqual([]);
    // I-W-17: two rounds of 4 s timeouts on the other holders, WebKit and a loaded machine: the budget is explicit.
  }, 150_000);
});

describe('P4.7-13 key pinning on screen', () => {
  it('the QR pin step refuses a code for another key, naming it, and pins the right one', async () => {
    const w = await world();
    const mine = devicePinCode(w.second.info, w.phone.info); // what the second device shows
    const forged = devicePinCode(party(2, 'second-authenticator', 'Unknown device').info, w.phone.info);
    await screen(w, {
      pin: {
        code: devicePinCode(w.phone.info, w.second.info).qr,
        sas: devicePinCode(w.phone.info, w.second.info).sas,
        check: (code, sas) => checkDevicePin(code, w.second.info, w.phone.info, sas),
      },
    });
    await expect
      .element(page.getByRole('status', { name: 'Pairing code' }))
      .toHaveTextContent(devicePinCode(w.phone.info, w.second.info).qr);
    await expect.element(page.getByRole('button', { name: 'Start key setup' })).toBeDisabled();
    await page.getByLabelText('Code scanned from your other device').fill(forged.qr);
    await page.getByLabelText('Six digits shown on your other device').fill(forged.sas);
    await page.getByRole('button', { name: 'Pin this device' }).click();
    await expect
      .element(page.getByRole('alert'))
      .toHaveTextContent(
        `Refused the key of Your second device (${fingerprint(w.second.info.edPub)}): the scanned code is not for this key`,
      );
    await page.getByLabelText('Code scanned from your other device').fill(mine.qr);
    await page.getByLabelText('Six digits shown on your other device').fill(mine.sas);
    await page.getByRole('button', { name: 'Pin this device' }).click();
    await expect.element(page.getByRole('button', { name: 'Start key setup' })).toBeEnabled();
  });

  it('a recovery agent key that is not in the anchored list is refused before anything is sent', async () => {
    const w = await world();
    await screen(w, { run: phoneRun(w, keyDirectory([w.phone.info, w.second.info])) });
    await start();
    await expect
      .element(page.getByRole('alert'))
      .toHaveTextContent(
        `Refused key: Recovery agent (Example Recovery Ltd) (${fingerprint(w.agent.info.edPub)}). Nothing was sent.`,
      );
    expect(w.relay.sessions).toHaveLength(0);
  });
});

describe('P4.7-14 the echo step on screen', () => {
  it('another round 1 shown to the phone stops the DKG before any share is stored', async () => {
    const w = await world();
    let alt: Awaited<ReturnType<typeof signRelayMessage>> | undefined;
    w.relay.deliver = (to, rows) =>
      to !== w.phone.info.identifier || !alt
        ? rows
        : rows.map((r) =>
            atob(r.message.payload).includes('"dkg.round1"') && r.message.key_id === w.second.info.keyId
              ? { ...r, message: alt as never }
              : r,
          );
    await screen(w);
    const others = Promise.allSettled([
      remote(w, {
        p: w.second,
        tamper: async (m) => {
          if (m.kind === 'dkg-r1') {
            const o = ed25519_FROST.DKG.round1(holderId(2), THRESHOLD);
            const fields = [...o.public.commitment, o.public.proofOfKnowledge, m.fields[3] as Uint8Array];
            alt = await signRelayMessage(
              toWire({ dealId: w.id, slot: 'A', holders: w.holders }, { ...m, fields }),
              w.second.keys,
            );
          }
          return m;
        },
      }),
      remote(w, { p: w.agent }),
    ]);
    await start();
    await expect.element(page.getByText('Key setup stopped. No share was stored.'), { timeout: 15_000 }).toBeVisible();
    await expect.element(page.getByText(/TRANSCRIPT_MISMATCH/)).toBeVisible();
    await others;
    expect(await w.vault.list()).toEqual([]);
  });
});

describe('P4.7-15 the slot test on screen', () => {
  it('one failing pair: that pair is red, the slot is not ready, nothing is stored', async () => {
    const w = await world();
    await screen(w);
    // the agent finishes the DKG but never test-signs
    const agent = new FrostHolder({
      index: 3,
      keys: w.agent.keys,
      dealId: w.id,
      slot: 'A',
      holders: w.holders,
      relay: w.relay,
      cipher: xwingShareCipher,
      pinned: keyDirectory(w.holders),
    });
    const others = Promise.allSettled([
      remote(w, { p: w.second }),
      w.relay
        .joiner()('dkg')
        .then((sid) => agent.dkg(sid)),
    ]);
    await start();
    await expect
      .element(page.getByText('Slot key not ready: a test signature failed. No share was stored.'), { timeout: 20_000 })
      .toBeVisible();
    const pairs = page.getByRole('list', { name: 'Test signatures' }).getByRole('listitem');
    await expect.element(pairs.nth(0)).toHaveTextContent('PASS Your phone + Your second device');
    await expect.element(pairs.nth(1)).toHaveTextContent('FAIL Your phone + Recovery agent (Example Recovery Ltd)');
    await others;
    expect(await w.vault.list()).toEqual([]);
  });
});

describe('P4.7-19 single-device mode in the DKG screens', () => {
  it('shows the label on the screen and on the ready summary', async () => {
    const w = await world({ singleDevice: true });
    await screen(w, { singleDevice: true });
    await expect.element(page.getByRole('note')).toHaveTextContent(SINGLE_DEVICE_LABEL);
    const others = Promise.all([remote(w, { p: w.second }), remote(w, { p: w.agent })]);
    await start();
    await expect
      .element(page.getByText(/^Slot key ready/), { timeout: 15_000 })
      .toMatchTextContent(SINGLE_DEVICE_LABEL);
    await others;
  });
});
