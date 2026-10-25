// Real WebAuthn PRF through Chrome DevTools Protocol virtual authenticators (Chromium only; WebKit has no CDP
// WebAuthn domain, so WebKit runs the same vault paths with the fake PRF source in the other files).
// Source: https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/ (addVirtualAuthenticator, hasPrf,
//   isUserVerified, getCredentials, setUserVerified, removeVirtualAuthenticator)
// Source: https://vitest.dev/api/browser/commands#cdp-session (`cdp()` in the Playwright Chromium provider)
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cdp, server } from 'vitest/browser';
import { webauthnPrf } from '../src/prf.ts';
import { createVault } from '../src/vault.ts';
import { binding, copy, dealId, freshDb, makeSlot, sealedDeal } from './helpers.ts';

type Options = { transport: 'usb' | 'internal'; hasPrf: boolean };
const added: string[] = [];
async function authenticator(o: Options): Promise<string> {
  const { authenticatorId } = (await cdp().send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: o.transport,
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: o.hasPrf,
    },
  })) as { authenticatorId: string };
  added.push(authenticatorId);
  return authenticatorId;
}
const credentialsOn = async (id: string) =>
  ((await cdp().send('WebAuthn.getCredentials', { authenticatorId: id })) as { credentials: unknown[] }).credentials
    .length;

describe.runIf(server.browser === 'chromium')('WebAuthn PRF (virtual authenticators)', () => {
  const prf = webauthnPrf({ id: location.hostname, name: 'LegX vault test' });
  const user = { id: crypto.getRandomValues(new Uint8Array(16)), name: 'alice' };

  beforeEach(async () => {
    await cdp().send('WebAuthn.enable', { enableUI: false });
  });
  afterEach(async () => {
    for (const authenticatorId of added.splice(0))
      await cdp().send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  });

  it('P4.2-05 share 2 on a separate security key: restore on a fresh profile with the same key signs with share 1', async () => {
    const phone = await authenticator({ transport: 'internal', hasPrf: false }); // like Chrome's profile authenticator
    const key = await authenticator({ transport: 'usb', hasPrf: true });
    const reg = await prf.register('security-key', user);
    expect(reg.prf).toBe(true);
    expect(await credentialsOn(key)).toBe(1);
    expect(await credentialsOn(phone)).toBe(0);

    const { pub, shares } = makeSlot();
    const id = dealId();
    const deal = sealedDeal(pub, 'A');
    const deps = { role: 'alice' as const, deals: async () => deal, prf };
    const first = createVault({ ...deps, dbName: freshDb() });
    await first.storeShares({
      dealId: id,
      pub,
      share1: copy(shares[0]),
      share2: { mode: 'security-key', credential: reg.credential, share: copy(shares[1]) },
    });
    await expect(first.signFrost(id, binding(deal, 'A'))).resolves.toHaveLength(64);
    const file = await first.backupShare2ToFile(id);

    const fresh = createVault({ ...deps, dbName: freshDb() });
    await expect(fresh.restore(file)).resolves.toEqual({ needsShare1: true });
    await fresh.installShare1(id, copy(shares[0]));
    await expect(fresh.signFrost(id, binding(deal, 'A'))).resolves.toHaveLength(64);
  });

  it('P4.2-07 a failed user verification on the key: PASSKEY_REQUIRED', async () => {
    const key = await authenticator({ transport: 'usb', hasPrf: true });
    const reg = await prf.register('security-key', user);
    const { pub, shares } = makeSlot();
    const id = dealId();
    const deal = sealedDeal(pub, 'A');
    const vault = createVault({ role: 'alice', deals: async () => deal, prf, dbName: freshDb() });
    await vault.storeShares({
      dealId: id,
      pub,
      share1: copy(shares[0]),
      share2: { mode: 'security-key', credential: reg.credential, share: copy(shares[1]) },
    });
    await cdp().send('WebAuthn.setUserVerified', { authenticatorId: key, isUserVerified: false });
    await expect(vault.signFrost(id, binding(deal, 'A'))).rejects.toThrow('PASSKEY_REQUIRED');
  });

  it('a security key without PRF: registration says so, evaluation is PASSKEY_REQUIRED, the recovery code is the fallback', async () => {
    await authenticator({ transport: 'usb', hasPrf: false });
    const reg = await prf.register('security-key', user);
    expect(reg.prf).toBe(false);
    await expect(prf.evaluate(reg.credential, new Uint8Array(32))).rejects.toThrow('PASSKEY_REQUIRED');
    const { pub, shares } = makeSlot();
    const id = dealId();
    const deal = sealedDeal(pub, 'A');
    let code = '';
    const vault = createVault({
      role: 'alice',
      deals: async () => deal,
      prf,
      dbName: freshDb(),
      showRecoveryCode: (c) => {
        code = c;
      },
      askRecoveryCode: async () => code,
    });
    await vault.storeShares({
      dealId: id,
      pub,
      share1: copy(shares[0]),
      share2: { mode: 'recovery-code', share: copy(shares[1]) },
    });
    await expect(vault.signFrost(id, binding(deal, 'A'))).resolves.toHaveLength(64);
  }, 60_000);

  it('P4.2-15 single-device mode on a platform passkey with PRF', async () => {
    const platform = await authenticator({ transport: 'internal', hasPrf: true });
    const reg = await prf.register('same-phone', user);
    expect(reg.prf).toBe(true);
    expect(await credentialsOn(platform)).toBe(1);
    const { pub, shares } = makeSlot();
    const id = dealId();
    const deal = sealedDeal(pub, 'A');
    const vault = createVault({ role: 'alice', deals: async () => deal, prf, dbName: freshDb() });
    const r = await vault.storeShares({
      dealId: id,
      pub,
      share1: copy(shares[0]),
      share2: { mode: 'single-device', credential: reg.credential, share: copy(shares[1]), acceptedWarning: true },
    });
    expect(r.label).toBe('Single-device mode: no protection if this phone is stolen');
    await expect(vault.signFrost(id, binding(deal, 'A'))).resolves.toHaveLength(64);
  });
});
