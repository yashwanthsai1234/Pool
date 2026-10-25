// I-29 the post-quantum binding screen (P4.9 UI part) on Chromium and WebKit: the real vault, the real binding session,
// the coordinator mocked by the world's `server`. The screen shows the values the device computed itself.
import { pqBindMsg } from '@legx/core/pq';
import { type BindingOffer, PQ_BINDING_TEXT, pqBindingSession } from '@legx/vault/pq/binding';
import { describe, expect, it, vi } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { bindingWorld } from '../../../../packages/vault/test/pq/support.ts';
import { PqBindingScreen } from '../../src/routes/party/-pq-binding.tsx';
import '../../src/index.css';

vi.setConfig({ testTimeout: 20_000 });
type World = Awaited<ReturnType<typeof bindingWorld>>;

const props = (w: World, over: { offer?: BindingOffer; submit?: World['server'] } = {}) => ({
  slot: 'A' as const,
  open: (onProgress: Parameters<typeof pqBindingSession>[0]['onProgress']) =>
    pqBindingSession({
      slot: 'A',
      seal: w.seal,
      pinned: w.pinned,
      offer: over.offer ?? w.offer,
      ...(onProgress ? { onProgress } : {}),
    }),
  half: w.phone,
  peer: async (s: ReturnType<typeof pqBindingSession>) => {
    const msg = pqBindMsg(w.seal.dealSeal, w.seal.slotPub, w.seal.pqKeyHash);
    s.add({ keyId: w.pinned[1].keyId, sig: await w.second.sign(msg, 'legx/pq-binding/v1') });
  },
  crossSign: w.crossSign,
  submit: over.submit ?? w.server,
});

describe('I-29 PQ binding screen', () => {
  it('shows the device-computed values, signs, waits, cross-signs, and the coordinator accepts the binding', async () => {
    const w = await bindingWorld();
    await render(<PqBindingScreen {...props(w)} />);
    await expect.element(page.getByText(PQ_BINDING_TEXT.help)).toBeVisible();
    await expect.element(page.getByTestId('pq-key-hash')).toBeVisible();
    await page.getByRole('button', { name: 'Sign the binding' }).click();
    await expect.element(page.getByText(/Post-quantum binding recorded/), { timeout: 15_000 }).toBeVisible();
    expect(w.events).toHaveLength(1);
  });

  it('a key set that does not hash to the seal shows Key mismatch and signs nothing', async () => {
    const w = await bindingWorld();
    const bad = { ...w.offer, holders: [w.offer.holders[1], w.offer.holders[0], w.offer.holders[2]] } as never;
    await render(<PqBindingScreen {...props(w, { offer: bad })} />);
    await expect.element(page.getByText(PQ_BINDING_TEXT.keyMismatch)).toBeVisible();
    expect(page.getByRole('button', { name: 'Sign the binding' }).elements()).toHaveLength(0);
    expect(w.server).not.toHaveBeenCalled();
  });

  it('an offer for another deal seal shows the seal mismatch text and signs nothing', async () => {
    const w = await bindingWorld();
    const bad = { ...w.offer, dealSeal: new Uint8Array(32) };
    await render(<PqBindingScreen {...props(w, { offer: bad })} />);
    await expect.element(page.getByText(PQ_BINDING_TEXT.sealMismatch)).toBeVisible();
    expect(w.server).not.toHaveBeenCalled();
  });

  it('a refused submit is reported and the binding is not shown as recorded', async () => {
    const w = await bindingWorld();
    await render(<PqBindingScreen {...props(w, { submit: vi.fn().mockRejectedValue(new Error('down')) })} />);
    await page.getByRole('button', { name: 'Sign the binding' }).click();
    await expect.element(page.getByText(/Not recorded/), { timeout: 15_000 }).toBeVisible();
    expect(page.getByText(/Post-quantum binding recorded/).elements()).toHaveLength(0);
  });
});
