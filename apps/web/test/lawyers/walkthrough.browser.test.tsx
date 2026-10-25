// The guided deal walkthrough in the lawyer console (build/WALKTHROUGH.md "Web"), against MSW that follows the server spec.
import axe from 'axe-core';
import { HttpResponse, http } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { startMocks } from '../../src/mocks/browser.ts';
import { Walkthrough } from '../../src/routes/lawyers/-walkthrough/ui.tsx';
import '../../src/index.css';

const TITLES = [
  'Lawyers enroll',
  'Deal created',
  'Contract signed',
  'Funding',
  'Identity and keys',
  'Lock',
  'Bob signs the shipment',
  'Alice signs the receipt',
  'Presence',
  'Release gate',
  'Release',
  'Close',
];
const HASH = (n: number) => `${String(n).padStart(2, '0')}`.repeat(32).toUpperCase();

const has = (loc: { element(): Element }, sub: string) =>
  expect.poll(() => loc.element().textContent ?? '').toContain(sub);

let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks();
});
afterEach(() => worker.resetHandlers());
afterAll(() => worker.stop());

function server(opts: { failAt?: number; bodies?: unknown[]; nexts?: number[] } = {}) {
  let n = 0;
  worker.use(
    http.get('*/api/demo/attack', () => HttpResponse.json({ attacks: [] })),
    http.post('*/api/demo/walkthrough', async ({ request }) => {
      opts.bodies?.push(await request.json());
      return HttpResponse.json({
        id: 'w1',
        dealId: 'DEAL1',
        steps: TITLES.map((title, i) => ({ id: `s${i + 1}`, title })),
      });
    }),
    http.post('*/api/demo/walkthrough/w1/next', () => {
      if (opts.failAt === n + 1) {
        opts.failAt = undefined;
        return HttpResponse.json({ code: 'BOOM' }, { status: 500 });
      }
      n += 1;
      opts.nexts?.push(n);
      const title = TITLES[n - 1];
      return HttpResponse.json({
        step: title,
        status: 'done',
        txHashes: n === 4 ? [HASH(n), HASH(n + 50)] : [],
        ledgerIndex: 100 + n,
        detail: `${title} ok (simulated phone)`,
        ...(title === 'Release gate'
          ? {
              gate: [
                { ok: true, level: 'block', code: 'BAR_A_OK' },
                { ok: false, level: 'warn', code: 'PQ_BINDINGS_OK', detail: 'missing' },
              ],
            }
          : {}),
        ...(title === 'Release' ? { bob: { before: '100', after: '110' } } : {}),
      });
    }),
  );
}

async function open(network: 'standalone' | 'testnet' = 'standalone') {
  const screen = await render(<Walkthrough network={network} pauseMs={0} />);
  await expect.element(page.getByRole('button', { name: 'New deal' })).toBeVisible();
  return screen;
}

async function create() {
  await page.getByRole('button', { name: 'New deal' }).click();
  await page.getByRole('button', { name: 'Create deal' }).click();
  await expect.element(page.getByRole('heading', { name: 'Deal walkthrough' })).toBeVisible();
}

describe('the walkthrough form', () => {
  it('renders nothing when the server is not the demo profile', async () => {
    worker.use(http.get('*/api/demo/attack', () => new HttpResponse(null, { status: 404 })));
    const screen = await render(<Walkthrough network="standalone" pauseMs={0} />);
    await new Promise((r) => setTimeout(r, 200));
    expect(screen.container.textContent).toBe('');
  });

  it('posts the fixed 50 XRP amount and the identity (delivery is mandatory, so it is not asked)', async () => {
    const bodies: unknown[] = [];
    server({ bodies });
    await open();
    await page.getByRole('button', { name: 'New deal' }).click();
    await page.getByRole('combobox').selectOptions('chip');
    await page.getByRole('button', { name: 'Create deal' }).click();
    await expect.element(page.getByRole('heading', { name: 'Deal walkthrough' })).toBeVisible();
    expect(bodies).toEqual([{ amountXrp: 50, identity: 'chip' }]);
  });

  it('shows the amount as fixed at 50 XRP', async () => {
    server();
    await open();
    await page.getByRole('button', { name: 'New deal' }).click();
    await expect.element(page.getByLabelText('Amount (XRP)')).toHaveAttribute('readonly');
    await expect.element(page.getByLabelText('Amount (XRP)')).toHaveValue('50');
  });

  it('shows a refusal from the server', async () => {
    server();
    worker.use(http.post('*/api/demo/walkthrough', () => HttpResponse.json({ code: 'NO' }, { status: 403 })));
    await open();
    await create_expecting_error();
  });
});

async function create_expecting_error() {
  await page.getByRole('button', { name: 'New deal' }).click();
  await page.getByRole('button', { name: 'Create deal' }).click();
  await has(page.getByRole('alert'), 'HTTP 403');
}

describe('the stepper', () => {
  it('enables only the next Run, in order, and shows hashes, gate findings and the balance change', async () => {
    server();
    await open();
    await create();
    const run = (i: number) => page.getByRole('button', { name: `Run step ${i + 1}` });
    await expect.element(run(0)).toBeEnabled();
    await expect.element(run(1)).toBeDisabled();
    for (let i = 0; i < TITLES.length; i++) {
      await run(i).click();
      await has(page.getByTestId(`step-${i + 1}`), 'done');
      if (i + 1 < TITLES.length) {
        await expect.element(run(i + 1)).toBeEnabled();
        await expect.element(run(i)).toBeDisabled();
      }
    }
    await has(page.getByTestId('step-4'), HASH(4));
    await has(page.getByTestId('step-10'), 'BAR_A_OK');
    await has(page.getByTestId('step-10'), 'PQ_BINDINGS_OK');
    await has(page.getByTestId('step-11'), 'Bob before: 100');
    await has(page.getByTestId('step-11'), 'after: 110');
    expect(page.getByRole('link').elements()).toHaveLength(0);
  });

  it('links hashes to the explorer on Testnet only', async () => {
    server();
    await open('testnet');
    await create();
    await page.getByRole('button', { name: 'Run step 1' }).click();
    for (let i = 2; i <= 4; i++) await page.getByRole('button', { name: `Run step ${i}` }).click();
    const link = page.getByRole('link', { name: HASH(4) });
    await expect.element(link).toHaveAttribute('href', `https://testnet.xrpl.org/transactions/${HASH(4)}`);
  });

  it('shows a failed step, keeps its Run enabled for a retry, and moves on after it', async () => {
    server({ failAt: 2 });
    await open();
    await create();
    await page.getByRole('button', { name: 'Run step 1' }).click();
    await page.getByRole('button', { name: 'Run step 2' }).click();
    await has(page.getByRole('alert'), 'Step 2 failed: HTTP 500');
    await has(page.getByTestId('step-2'), 'failed');
    await page.getByRole('button', { name: 'Run step 2' }).click();
    await has(page.getByTestId('step-2'), 'done');
    await expect.element(page.getByRole('button', { name: 'Run step 3' })).toBeEnabled();
  });

  it('Run all runs every step in order and stops at an error', async () => {
    const nexts: number[] = [];
    server({ nexts, failAt: 4 });
    await open();
    await create();
    await page.getByRole('button', { name: 'Run all' }).click();
    await has(page.getByRole('alert'), 'Step 4 failed');
    expect(nexts).toEqual([1, 2, 3]);
    await page.getByRole('button', { name: 'Run all' }).click();
    await has(page.getByTestId('step-12'), 'done');
    expect(nexts).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    await expect.element(page.getByRole('button', { name: 'Run all' })).toBeDisabled();
  });

  it('has no serious or critical axe violation', async () => {
    server();
    const screen = await open();
    await create();
    await page.getByRole('button', { name: 'Run step 1' }).click();
    await has(page.getByTestId('step-1'), 'done');
    const results = await axe.run(screen.container);
    const bad = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(' | ')}`)).toEqual([]);
  });
});
