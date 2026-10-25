import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import axe from 'axe-core';
import { HttpResponse, http } from 'msw';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { API_BASE } from '../src/lib/paths.ts';
import { createQueryClient } from '../src/lib/query.ts';
import { startMocks } from '../src/mocks/browser.ts';
import { createLiveMock } from '../src/mocks/live.ts';
import { createAppRouter } from '../src/router.tsx';
import '../src/index.css';

const DEAL = '0192f0c8-3c4e-7a2b-8c3d-000000000001';
const NAMES = ['Contract signed', 'Sender passport', 'Recipient passport', 'Sender keys'];
const stages = (done: number) =>
  NAMES.map((name, i) => ({ n: i + 1, name, actor: 'sender', status: i < done ? 'done' : 'pending', txHashes: [] }));
const party = (rid: string, name: string) => ({ rid, name, fingerprint: 'ab', xrplAddress: 'rX' });
const tally = (done: number) => ({ done, of: 2, by: [] });
let doneCount = 1;
const deal = () => ({
  id: 'd1',
  dealId: DEAL,
  createdAt: '2026-01-01T00:00:00Z',
  status: 'locked',
  sender: party('rid-alice-0001', 'Alice'),
  recipient: party('rid-bob-000002', 'Bob'),
  amountXrp: 25,
  terms: 't',
  contract: { sha256: 'x', pdfUrl: '/x', nftId: 'n', nftOwner: 'o', mintTx: 'm' },
  escrow: {
    status: 'locked',
    amountXrp: 25,
    walletAddress: 'rW',
    keys: tally(1),
    passports: tally(2),
    approvals: tally(0),
  },
  stages: stages(doneCount),
  ledger: { network: 'devnet' },
});

const mock = createLiveMock();
let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks(
    mock.handler,
    http.get(`${API_BASE}/demo/deals/:id`, () => HttpResponse.json(deal())),
  );
});
afterAll(() => worker.stop());

describe('/present/:id', () => {
  it('turns dots green on feed rows, pulses the current stage, passes axe', async () => {
    const qc = createQueryClient();
    const router = createAppRouter(qc, '/present/d1');
    const screen = await render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    await expect.element(page.getByRole('list', { name: 'Deal progress' })).toBeVisible();
    const items = () => [...screen.container.querySelectorAll('li[data-status]')];
    await expect
      .poll(() => items().map((i) => i.getAttribute('data-status')))
      .toEqual(['done', 'pending', 'pending', 'pending']);
    const cur = screen.container.querySelector('[aria-current="step"]');
    expect(cur?.textContent).toContain('Sender passport');
    expect(getComputedStyle(cur?.querySelector('span') as Element).animationName).toContain('pulse');
    expect(screen.container.querySelector('[aria-label="Escrow"]')?.textContent).toMatch(
      /Keys 1\/2 · Passports 2\/2 · Approvals 0\/2/,
    );
    expect(screen.container.querySelector('h1')?.textContent).toContain('Alice');
    doneCount = 3;
    await expect
      .poll(() => items().map((i) => i.getAttribute('data-status')), { timeout: 6000 })
      .toEqual(['done', 'done', 'done', 'pending']);
    const results = await axe.run(screen.container);
    expect(results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
  });
});
