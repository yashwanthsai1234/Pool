// P4.2-08 (spy test over the frame message schema), P4.2-10, P4.2-12, P4.2-13, P4.2-14, enrollment keys.

import type { KeyId } from '@legx/contracts/values';
import type { SealedDeal } from '@legx/core/frostRules';
import { mldsaSign, mldsaVerify, pqKeygen } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { VAULT_CSP } from '../src/csp.ts';
import { enrollmentKeys } from '../src/enrollment.ts';
import { connectCoSigner, connectVault, isVaultMessage, serveCoSigner, serveVault } from '../src/protocol.ts';
import { assertShareRecipient, type ClientShareRecipient, NEVER_TO_LAWYER } from '../src/rules.ts';
import { createVault } from '../src/vault.ts';
import {
  binding,
  containsSecret,
  copy,
  dealId,
  exitPayment,
  fakePrf,
  freshDb,
  isZero,
  makeSlot,
  recordPortMessages,
  sealedDeal,
} from './helpers.ts';

afterEach(() => {
  vi.restoreAllMocks();
});

describe("P4.2-14 share 2 on the client's second device", () => {
  function devices(approve: () => Promise<boolean>) {
    const { pub, shares } = makeSlot();
    const id = dealId();
    const deal = sealedDeal(pub, 'A');
    const deals = async () => deal;
    const second = createVault({ role: 'alice', dbName: freshDb(), deals, approve });
    const link = new MessageChannel();
    serveCoSigner(link.port2, second.cosigner());
    const phone = createVault({ role: 'alice', dbName: freshDb(), deals, cosigner: () => connectCoSigner(link.port1) });
    return { pub, shares, id, deal, second, phone };
  }

  it('signs only after the approval on the second device, and the phone never sees share 2', async () => {
    const posted = recordPortMessages();
    let ok = false;
    const d = devices(async () => ok);
    const share2 = d.shares[1].signingShare.slice();
    const salt = randomBytes(32);
    const saltCopy = salt.slice();
    await d.second.storeSecondDeviceShare({ dealId: d.id, pub: d.pub, share: copy(d.shares[1]), identitySalt: salt });
    await d.phone.storeShares({
      dealId: d.id,
      pub: d.pub,
      share1: copy(d.shares[0]),
      share2: { mode: 'second-device' },
    });
    await expect(d.phone.signFrost(d.id, binding(d.deal, 'A'))).rejects.toThrow('APPROVAL_REFUSED');
    ok = true;
    const sig = await d.phone.signMultisig(d.id, exitPayment(d.deal));
    expect(sig).toHaveLength(128);
    expect(posted.length).toBeGreaterThan(0);
    expect(posted.every(isVaultMessage)).toBe(true);
    expect(containsSecret(posted, [share2, saltCopy])).toBe(false);
    await expect(d.phone.withIdentitySalt(d.id, async () => 1)).rejects.toThrow('NOT_FOUND');
    await expect(d.second.withIdentitySalt(d.id, async (s) => s.length)).resolves.toBe(32);
  });

  it('the second device decodes the request itself and refuses an off-list one, even when approved', async () => {
    const d = devices(async () => true);
    await d.second.storeSecondDeviceShare({ dealId: d.id, pub: d.pub, share: copy(d.shares[1]) });
    const port = d.second.cosigner();
    await expect(port.commit({ dealId: d.id, request: binding(d.deal, 'B') })).rejects.toThrow('MESSAGE_REFUSED');
    const { session, commitment } = await port.commit({ dealId: d.id, request: binding(d.deal, 'A') });
    expect(commitment.identifier).toBe(d.shares[1].identifier);
    await expect(port.sign(session, [])).rejects.toThrow();
    await expect(port.sign(session, [])).rejects.toThrow('NOT_FOUND'); // one try per session: the share is gone
  });

  it('a holder that sends a bad signature share is caught by verifyShare', async () => {
    const d = devices(async () => true);
    await d.second.storeSecondDeviceShare({ dealId: d.id, pub: d.pub, share: copy(d.shares[1]) });
    const honest = d.second.cosigner();
    const cheat = { commit: honest.commit, sign: async () => randomBytes(32) };
    const phone = createVault({ role: 'alice', dbName: freshDb(), deals: async () => d.deal, cosigner: () => cheat });
    await phone.storeShares({
      dealId: d.id,
      pub: d.pub,
      share1: copy(d.shares[0]),
      share2: { mode: 'second-device' },
    });
    await expect(phone.signFrost(d.id, binding(d.deal, 'A'))).rejects.toThrow('SIGNATURE_INVALID');
  });
});

it("P4.2-10 a share never goes to the client's own lawyer (type level and run time)", () => {
  expect(() => assertShareRecipient('recovery-agent')).not.toThrow();
  // @ts-expect-error a lawyer role is not a client share recipient
  expect(() => assertShareRecipient('console')).toThrow('ROLE_REFUSED');
  expect(() => assertShareRecipient('firm-hsm' as ClientShareRecipient)).toThrow('ROLE_REFUSED');
  expect(NEVER_TO_LAWYER).toBe('Never give a share to your own lawyer');
});

it('P4.2-13 home-screen and tab partitions: the app says which holds the shares; a file moves share 2', async () => {
  const { pub, shares } = makeSlot();
  const id = dealId();
  const deal = sealedDeal(pub, 'A');
  const prf = fakePrf();
  const base = { role: 'alice' as const, deals: async () => deal, prf: prf.source };
  const tab = createVault({ ...base, dbName: freshDb(), context: () => 'browser-tab' });
  const home = createVault({ ...base, dbName: freshDb(), context: () => 'home-screen' });
  await tab.storeShares({
    dealId: id,
    pub,
    share1: copy(shares[0]),
    share2: { mode: 'security-key', credential: { id: 'c', transports: [] }, share: copy(shares[1]) },
  });
  expect((await tab.location()).message).toBe(
    'Your shares are saved in this browser tab. The home-screen app cannot see them; use a recovery file to move them.',
  );
  expect(await home.location()).toMatchObject({ context: 'home-screen', entries: 0 });
  expect((await home.location()).message).toContain('No shares are saved in this home-screen app');
  await expect(home.restore(await tab.backupShare2ToFile(id))).resolves.toEqual({ needsShare1: true });
  expect(await home.list()).toEqual([expect.objectContaining({ context: 'home-screen', hasShare1: false })]);
});

describe('enrollment keys', () => {
  it("Ed25519 with a non-extractable private key; the hybrid signer joins task 4.9's ML-DSA-65 half", async () => {
    const keys = enrollmentKeys({ role: 'alice', dbName: freshDb() });
    const id = dealId();
    const pubKey = await keys.create(id);
    expect(await keys.create(id)).toEqual(pubKey);
    const msg = randomBytes(40);
    expect(ed25519.verify(await keys.sign(id, msg), msg, pubKey, { zip215: false })).toBe(true);
    const pq = pqKeygen(randomBytes(32));
    const signer = await keys.hybridSigner(id, 'ed#1' as KeyId, {
      keyId: 'pq#1' as KeyId,
      publicKey: pq.publicKey,
      sign: async (m, ctx) => mldsaSign('ml-dsa-65', pq.secretKey, m, ctx),
    });
    const sig = await signer.signHybrid(msg, 'legx/dsse/v1');
    expect(ed25519.verify(sig.ed25519, msg, pubKey)).toBe(true);
    expect(mldsaVerify('ml-dsa-65', pq.publicKey, msg, sig.mlDsa65, 'legx/dsse/v1')).toBe(true);
    await expect(keys.sign(dealId(), msg)).rejects.toThrow('NOT_FOUND');
  });
});

it('P4.2-08 nothing secret reaches fetch, WebSocket.send, console or postMessage over a full lifecycle', async () => {
  // Spies call through: the test runner itself talks over fetch, WebSocket, console and postMessage.
  const spies = [
    vi.spyOn(window, 'fetch'),
    vi.spyOn(WebSocket.prototype, 'send'),
    vi.spyOn(window, 'postMessage'),
    ...(['log', 'info', 'warn', 'error', 'debug', 'trace'] as const).map((k) => vi.spyOn(console, k)),
  ];
  const posted = recordPortMessages();

  const { pub, shares } = makeSlot();
  const id = dealId();
  const deal: SealedDeal = sealedDeal(pub, 'A');
  const prf = fakePrf();
  const salt = randomBytes(32);
  const needles: Uint8Array[] = [shares[0].signingShare.slice(), shares[1].signingShare.slice(), salt.slice()];
  const frame = createVault({ role: 'alice', dbName: freshDb(), deals: async () => deal, prf: prf.source });
  await frame.storeShares({
    dealId: id,
    pub,
    share1: copy(shares[0]),
    share2: { mode: 'security-key', credential: { id: 'c', transports: [] }, share: copy(shares[1]) },
    identitySalt: salt,
  });
  const channel = new MessageChannel();
  serveVault(channel.port2, frame);
  const app = connectVault(channel.port1);

  const sig = await app.signFrost(id, binding(deal, 'A'));
  expect(sig).toHaveLength(64);
  await app.signMultisig(id, exitPayment(deal) as Record<string, string | number>);
  const file = await app.backupShare2ToFile(id);
  const restoredFrame = createVault({ role: 'alice', dbName: freshDb(), deals: async () => deal, prf: prf.source });
  const c2 = new MessageChannel();
  serveVault(c2.port2, restoredFrame);
  await expect(connectVault(c2.port1).restore(file)).resolves.toEqual({ needsShare1: true });
  await expect(app.signFrost(id, binding(deal, 'B'))).rejects.toThrow('MESSAGE_REFUSED');
  await expect(app.list()).resolves.toHaveLength(1);
  channel.port1.postMessage({ hello: 'not a vault message' }); // ignored by the frame, never answered

  expect(prf.outputs.length).toBeGreaterThan(0);
  expect(prf.outputs.every(isZero)).toBe(true);
  needles.push(...prf.copies);
  expect(
    containsSecret(
      spies.map((x) => x.mock.calls),
      needles,
    ),
  ).toBe(false);
  expect(containsSecret(posted, needles)).toBe(false);
  expect(posted.filter((m) => !isVaultMessage(m))).toEqual([{ hello: 'not a vault message' }]);
});

describe('P4.2-12 the vault frame CSP and Trusted Types', () => {
  function frame(body: string, csp = VAULT_CSP): Promise<Window & { ran?: boolean }> {
    return new Promise((resolve) => {
      const f = document.createElement('iframe');
      document.body.append(f);
      f.addEventListener('load', () => resolve(f.contentWindow as Window & { ran?: boolean }));
      f.srcdoc = `<!doctype html><meta http-equiv="Content-Security-Policy" content="${csp}"><body>${body}`;
    });
  }
  const tick = () => new Promise((r) => setTimeout(r, 150));

  it('has no unsafe source and no network', () => {
    expect(VAULT_CSP).not.toMatch(/unsafe|\*/);
    for (const d of [
      "connect-src 'none'",
      "script-src 'self'",
      "require-trusted-types-for 'script'",
      "trusted-types 'none'",
    ])
      expect(VAULT_CSP).toContain(d);
  });

  it('blocks an inline script (control: it runs without the policy)', async () => {
    expect((await frame('<script>window.ran = true</script>')).ran).toBeUndefined();
    expect((await frame('<script>window.ran = true</script>', "script-src 'unsafe-inline'")).ran).toBe(true);
  });

  it('blocks a javascript: URL', async () => {
    const w = await frame('<a id="a" href="javascript:window.ran=true">x</a>');
    (w.document.getElementById('a') as HTMLAnchorElement).click();
    await tick();
    expect(w.ran).toBeUndefined();
    const control = await frame('<a id="a" href="javascript:window.ran=true">x</a>', "script-src 'unsafe-inline'");
    (control.document.getElementById('a') as HTMLAnchorElement).click();
    await tick();
    expect(control.ran).toBe(true);
  });

  it('Trusted Types rejects a string sink', async (ctx) => {
    const w = await frame('<div id="d"></div>');
    if (!('trustedTypes' in w)) ctx.skip();
    const d = w.document.getElementById('d') as HTMLElement;
    expect(() => {
      d.innerHTML = '<b>x</b>';
    }).toThrow(/Trusted/);
    expect(() =>
      (w as unknown as { trustedTypes: TrustedTypePolicyFactory }).trustedTypes.createPolicy('x', {}),
    ).toThrow();
  });

  it('blocks fetch from the frame (connect-src none)', async () => {
    const w = await frame('');
    await expect((w as unknown as { fetch: typeof fetch }).fetch('/')).rejects.toThrow();
  });
});
