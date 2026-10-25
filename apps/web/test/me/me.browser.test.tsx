// /register and /me (build/PRODUCT_DEMO.md sections 1, 3, 5) on Chromium and WebKit at iPhone size, over MSW.
import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import axe from 'axe-core';
import { HttpResponse, http } from 'msw';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import type { Deal, Participant, Stage } from '../../src/lib/demo-deals.tsx';
import { createQueryClient } from '../../src/lib/query.ts';
import { startMocks } from '../../src/mocks/browser.ts';
import { createAppRouter } from '../../src/router.tsx';
import '../../src/index.css';

const person = (name: string, c: string): Participant => ({
  rid: `rid_${c.repeat(16)}`,
  name,
  fingerprint: c.repeat(64),
  xrplAddress: `r${c}`,
});
const alice = person('Alice', 'a');
const bob = person('Bob', 'b');
const carol = person('Carol', 'c');
const NAMES = [
  'Contract signed',
  'Sender passport',
  'Recipient passport',
  'Sender keys',
  'Recipient keys',
  'Escrow funded',
  'Wallet locked',
  'Shipment signed',
  'Receipt signed',
  'Sender approves',
  'Recipient approves',
  'Release gate',
  'Funds released',
  'Wallet closed',
];
const ACTORS = ['auto', 'sender', 'recipient', 'sender', 'recipient', 'sender', 'auto', 'recipient', 'sender'];
const stages = (done: number): Stage[] =>
  NAMES.map((name, i) => ({
    n: i + 1,
    name,
    actor: (ACTORS[i] ?? (i === 9 ? 'sender' : i === 10 ? 'recipient' : 'auto')) as Stage['actor'],
    status: i < done ? 'done' : 'pending',
    txHashes: [],
  }));
const tally = { done: 0, of: 2, by: [] };
const deal = (id: string, sender: Participant, recipient: Participant, done: number): Deal => ({
  id,
  dealId: `01900000-0000-7000-8000-00000000000${id}`,
  createdAt: '2026-01-01T00:00:00Z',
  status: 'locked',
  sender,
  recipient,
  amountXrp: 50,
  terms: 't',
  contract: { sha256: 'f'.repeat(64), pdfUrl: '/x.pdf', nftId: 'N', nftOwner: 'rW', mintTx: 'T' },
  escrow: {
    status: 'not funded',
    amountXrp: 50,
    walletAddress: 'rW',
    keys: tally,
    passports: tally,
    approvals: tally,
  },
  stages: stages(done),
  ledger: { network: 'standalone' },
});

let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks();
});
afterEach(() => worker.resetHandlers());
afterAll(() => worker.stop());
beforeEach(async () => {
  await page.viewport(390, 844);
  localStorage.clear();
});

const render_ = (path: string) => {
  const queryClient = createQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={createAppRouter(queryClient, path)} />
    </QueryClientProvider>,
  );
};
const serve = (deals: Deal[], approve?: Parameters<typeof http.post>[1]) =>
  worker.use(
    http.get('/api/demo/participants', () => HttpResponse.json([alice, bob, carol])),
    http.get('/api/demo/deals', () => HttpResponse.json(deals)),
    http.get('/api/demo/deals/:id', ({ params }) => HttpResponse.json(deals.find((d) => d.id === params.id))),
    http.post('/api/demo/deals/:id/approve', approve ?? (() => HttpResponse.json(deals[0]))),
  );
/** Action buttons only: the RID chip's copy button and a toast's dismiss button are not actions. */
const actions = () =>
  page
    .getByRole('button')
    .elements()
    .filter((b) => !/Copy RID|RID copied|Dismiss/.test(b.getAttribute('aria-label') ?? ''));
const noSeriousAxe = async (c: Element) => {
  const r = await axe.run(c);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);
};

describe('/register', () => {
  it('registers, remembers the RID, and goes straight to My deals with a welcome toast', async () => {
    let body: unknown;
    serve([]);
    worker.use(
      http.post('/api/demo/participants', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(alice);
      }),
    );
    const screen = await render_('/register');
    await page.getByLabelText('Your name').fill('Alice');
    await page.getByRole('button', { name: 'Register' }).click();
    await expect.element(page.getByRole('heading', { name: 'Hello Alice' })).toBeVisible();
    expect(document.querySelector('nav [aria-current="page"]')?.textContent).toBe('My deals');
    await expect.element(page.getByRole('status').filter({ hasText: 'You are registered as Alice' })).toBeVisible();
    // the RID chip: short RID visible, full RID and fingerprint in the tooltip
    const chip = document.querySelector(`[title^="${alice.rid}"]`);
    expect(chip?.getAttribute('title')).toContain(alice.fingerprint);
    expect(body).toEqual({ name: 'Alice' });
    expect(localStorage.getItem('legx.demo.rid')).toBe(alice.rid);
    await noSeriousAxe(screen.container);
  });

  it('has axe-clean form and a 44px touch target', async () => {
    const screen = await render_('/register');
    await expect.element(page.getByRole('button', { name: 'Register' })).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Register' })).toBeDisabled();
    await expect.element(page.getByText('Type your name first')).toBeVisible();
    const box = page.getByRole('button', { name: 'Register' }).element().getBoundingClientRect();
    expect(box.height).toBeGreaterThanOrEqual(48);
    // pinned to the bottom of the phone screen
    expect(box.bottom).toBeGreaterThan(844 - 120);
    await noSeriousAxe(screen.container);
  });
});

describe('/me', () => {
  it('sends an unregistered device to /register', async () => {
    await render_('/me');
    await expect
      .element(page.getByRole('main').getByRole('link', { name: 'Register' }).nth(1))
      .toHaveAttribute('href', '/register');
  });

  it('shows only my deals, and only my next-stage button', async () => {
    localStorage.setItem('legx.demo.rid', alice.rid);
    serve([deal('1', alice, bob, 1), deal('2', bob, carol, 1)]);
    const screen = await render_('/me');
    await expect.element(page.getByRole('heading', { name: 'Hello Alice' })).toBeVisible();
    await expect.element(page.getByRole('heading', { name: /Alice to Bob/ })).toBeVisible();
    expect(page.getByRole('heading', { name: /Bob to Carol/ }).elements()).toHaveLength(0);
    // stage 2 is the sender's: Alice gets the button, and only one
    await expect.element(page.getByRole('button', { name: 'Verify my passport' })).toBeVisible();
    expect(actions()).toHaveLength(1);
    await expect.element(page.getByRole('status').filter({ hasText: 'Your turn: Verify my passport' })).toBeVisible();
    await expect.element(page.getByText('demo: keys held by the server')).toBeVisible();
    await noSeriousAxe(screen.container);
  });

  it('posts {rid, stage} when the button is pressed', async () => {
    localStorage.setItem('legx.demo.rid', alice.rid);
    let body: unknown;
    serve([deal('1', alice, bob, 1)], async ({ request }) => {
      body = await request.json();
      return HttpResponse.json(deal('1', alice, bob, 2));
    });
    await render_('/me');
    await page.getByRole('button', { name: 'Verify my passport' }).click();
    await expect.poll(() => body).toEqual({ rid: alice.rid, stage: 2 });
  });

  it('shows Waiting for <name> with no button when the next stage is the other person', async () => {
    localStorage.setItem('legx.demo.rid', bob.rid);
    serve([deal('1', alice, bob, 1)]);
    await render_('/me');
    await expect.element(page.getByText('Waiting for Alice', { exact: true })).toBeVisible();
    await expect
      .element(page.getByRole('status').filter({ hasText: 'Waiting for Alice to verify their passport' }))
      .toBeVisible();
    expect(actions()).toHaveLength(0);
  });

  it('shows a success toast with the transaction link, and the dot turns green at once', async () => {
    localStorage.setItem('legx.demo.rid', alice.rid);
    const after = deal('1', alice, bob, 6);
    after.escrow = { ...after.escrow, status: 'locked', fundTx: 'ABCDEF0123456789' };
    after.ledger = { network: 'standalone', explorerBase: 'https://x.test' };
    let served = deal('1', alice, bob, 5);
    worker.use(
      http.get('/api/demo/participants', () => HttpResponse.json([alice, bob, carol])),
      http.get('/api/demo/deals', () => HttpResponse.json([served])),
      http.get('/api/demo/deals/:id', () => HttpResponse.json(served)),
      http.post('/api/demo/deals/:id/approve', () => {
        served = after;
        return HttpResponse.json(after);
      }),
    );
    const screen = await render_('/me');
    await page.getByRole('button', { name: 'Fund escrow: 50 XRP' }).click();
    const toast = page.getByRole('status').filter({ hasText: 'Escrow funded: 50 XRP locked' });
    await expect.element(toast).toBeVisible();
    await expect
      .element(toast.getByRole('link'))
      .toHaveAttribute('href', 'https://x.test/transactions/ABCDEF0123456789');
    await expect.poll(() => screen.container.querySelectorAll('[data-status="done"]').length).toBe(6);
    await expect.element(page.getByText('Locked', { exact: true })).toBeVisible();
    await noSeriousAxe(screen.container);
  });

  it('shows skeletons while loading and a plain empty state', async () => {
    localStorage.setItem('legx.demo.rid', alice.rid);
    let release = () => {};
    const gate = new Promise<void>((r) => {
      release = r;
    });
    worker.use(
      http.get('/api/demo/participants', () => HttpResponse.json([alice])),
      http.get('/api/demo/deals', async () => {
        await gate;
        return HttpResponse.json([]);
      }),
    );
    const screen = await render_('/me');
    await expect.poll(() => screen.container.querySelectorAll('[aria-busy="true"]').length).toBeGreaterThan(0);
    release();
    await expect.element(page.getByRole('heading', { name: 'No deals yet' })).toBeVisible();
  });

  it('labels the funding button with the amount', async () => {
    localStorage.setItem('legx.demo.rid', alice.rid);
    serve([deal('1', alice, bob, 5)]);
    await render_('/me');
    await expect.element(page.getByRole('button', { name: 'Fund escrow: 50 XRP' })).toBeVisible();
  });

  for (const [status, text] of [
    [403, 'not your stage'],
    [409, 'wrong order'],
  ] as const) {
    it(`shows a ${status} clearly`, async () => {
      localStorage.setItem('legx.demo.rid', alice.rid);
      serve([deal('1', alice, bob, 1)], () => new HttpResponse(text, { status }));
      const screen = await render_('/me');
      await page.getByRole('button', { name: 'Verify my passport' }).click();
      await expect.element(page.getByRole('alert')).toBeVisible();
      await expect.poll(() => page.getByRole('alert').element().textContent).toContain(`${status} ${text}`);
      expect(page.getByRole('alert').element().textContent).toContain(
        status === 403 ? 'That step is not yours' : 'out of order',
      );
      await noSeriousAxe(screen.container);
    });
  }
});
