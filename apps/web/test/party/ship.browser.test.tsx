// OD-37 screens (build/SHIP_RECEIPT.md 6) on Chromium and WebKit: Bob's Ship, Alice's Confirm delivery, the confirmation
// that shows what is signed, the manifest mismatch, and axe. The ship port is a fake over the real core manifest root.
import { bytesToHex } from '@legx/core/dealcore';
import { manifestRoot } from '@legx/core/shipment';
import { QueryClientProvider } from '@tanstack/react-query';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { createApiClient } from '../../src/lib/api.ts';
import { createQueryClient } from '../../src/lib/query.ts';
import { PartyProvider, type PartyServices, type ShipPort } from '../../src/routes/party/-context.tsx';
import { ReceiveScreen, ShipScreen } from '../../src/routes/party/-ship.tsx';
import '../../src/index.css';

const items = [{ sku: 'A-1', description: 'Widget', qty: 2, weight_g: 150 }];
const manifest = { items, packed_at: '2026-10-25T10:00:00Z', total_weight_g: 300 };
const rootOf = (m: { items: typeof items }) => bytesToHex(manifestRoot(m.items));

function port(over: Partial<ShipPort> = {}): ShipPort & { signed: unknown[] } {
  const signed: unknown[] = [];
  return {
    signed,
    manifestRoot: rootOf,
    signShipment: async (i) => {
      signed.push(i);
      return { signature: 'ab'.repeat(64), manifestRoot: rootOf(i.manifest) };
    },
    shipment: async () => ({ manifest, signedRoot: rootOf(manifest), carrier: 'DHL', trackingId: 'TRK1' }),
    signReceipt: async (i) => {
      signed.push(i);
      return { signature: 'cd'.repeat(64) };
    },
    ...over,
  };
}

async function show(role: 'alice' | 'bob', ship: ShipPort) {
  const services = {
    dealId: '0192f0c8-3c4e-7a2b-8c3d-000000009001',
    role,
    ship,
    api: createApiClient({ signRequest: async () => ({}) as never }),
  } as unknown as PartyServices;
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <PartyProvider value={services}>{role === 'bob' ? <ShipScreen /> : <ReceiveScreen />}</PartyProvider>
    </QueryClientProvider>,
  );
}

const shows = (l: { element: () => Element }, t: string) => expect.poll(() => l.element().textContent).toContain(t);
const violations = async (c: Element) => (await axe.run(c as HTMLElement)).violations.map((v) => v.id);

describe('Bob: Ship', () => {
  it('shows the live manifest root, asks for confirmation with what is signed, and signs only after it', async () => {
    const p = port();
    const s = await show('bob', p);
    await page.getByLabelText('SKU').fill('A-1');
    await page.getByLabelText('Description').fill('Widget');
    await page.getByLabelText('Quantity').fill('2');
    await page.getByLabelText('Weight (g)').fill('150');
    await page.getByLabelText('Carrier').fill('DHL');
    await page.getByLabelText('Tracking ID').fill('TRK1');
    await shows(page.getByTestId('manifest-root'), rootOf(manifest));
    expect(await violations(s.container)).toEqual([]);
    await page.getByRole('button', { name: 'Sign shipment' }).click();
    await expect.element(page.getByRole('dialog')).toBeVisible();
    for (const [id, text] of [
      ['confirm-manifest-root', rootOf(manifest)],
      ['confirm-carrier', 'DHL'],
      ['confirm-tracking', 'TRK1'],
    ] as const)
      await shows(page.getByTestId(id), text);
    expect(p.signed).toHaveLength(0);
    await page.getByRole('button', { name: 'Confirm and sign' }).click();
    await vi.waitFor(() => expect(p.signed).toHaveLength(1));
    await shows(page.getByRole('status'), 'Shipped: you signed');
  });

  it('cancel signs nothing', async () => {
    const p = port();
    await show('bob', p);
    await page.getByLabelText('SKU').fill('A-1');
    await page.getByLabelText('Description').fill('Widget');
    await page.getByLabelText('Carrier').fill('DHL');
    await page.getByLabelText('Tracking ID').fill('TRK1');
    await page.getByLabelText('Weight (g)').fill('150');
    await page.getByRole('button', { name: 'Sign shipment' }).click();
    await page.getByRole('button', { name: 'Cancel' }).click();
    expect(p.signed).toHaveLength(0);
  });
});

describe('Alice: Confirm delivery', () => {
  it('ticks the manifest against the signed root and signs a receipt after confirmation', async () => {
    const p = port();
    const s = await show('alice', p);
    await shows(page.getByTestId('root-check'), 'matches the root Bob signed');
    expect(await violations(s.container)).toEqual([]);
    await page.getByRole('button', { name: 'Sign receipt' }).click();
    await shows(page.getByTestId('confirm-condition'), 'ok');
    await page.getByRole('button', { name: 'Confirm and sign' }).click();
    await vi.waitFor(() => expect(p.signed).toEqual([{ condition: 'ok' }]));
  });

  it('shows a red mismatch and cannot sign when the manifest differs from the signed root', async () => {
    const p = port({
      shipment: async () => ({
        manifest: { ...manifest, items: [{ ...items[0], qty: 3 }] as typeof items },
        signedRoot: rootOf(manifest),
        carrier: 'DHL',
        trackingId: 'TRK1',
      }),
    });
    const s = await show('alice', p);
    await shows(page.getByTestId('root-check'), 'Mismatch');
    await expect.element(page.getByRole('button', { name: 'Sign receipt' })).toBeDisabled();
    expect(p.signed).toHaveLength(0);
    expect(await violations(s.container)).toEqual([]);
  });

  it('damaged shows the dispute path', async () => {
    await show('alice', port());
    await page.getByLabelText('Arrived damaged').click();
    await shows(page.getByTestId('dispute-path'), 'dispute');
  });
});
