import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import axe from 'axe-core';
import { HttpResponse, http } from 'msw';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import type { Deal, Participant } from '../../src/lib/demo-deals.tsx';
import { createQueryClient } from '../../src/lib/query.ts';
import { startMocks } from '../../src/mocks/browser.ts';
import { createLiveMock } from '../../src/mocks/live.ts';
import { createAppRouter } from '../../src/router.tsx';
import '../../src/index.css';

const person = (name: string, rid: string): Participant => ({
  rid,
  name,
  fingerprint: 'ab'.repeat(32),
  xrplAddress: `r${name}`,
});
const alice = person('Alice', 'rid_aaaaaaaaaaaaaaaa');
const bob = person('Bob', 'rid_bbbbbbbbbbbbbbbb');
const STAGES = Array.from({ length: 14 }, (_, n) => ({
  n: n + 1,
  name: `Stage ${n + 1}`,
  actor: 'sender' as const,
  status: 'pending' as 'pending' | 'done',
  txHashes: [],
}));
const tally = { done: 1, of: 2, by: [{ rid: alice.rid, name: 'Alice' }] };
const deal = (id: string, status: 'locked' | 'released', done: number): Deal => ({
  id,
  dealId: `0192f0c8-3c4e-7a2b-8c3d-00000000000${id.slice(-1)}`,
  createdAt: '2026-10-25T10:00:00Z',
  status,
  sender: alice,
  recipient: bob,
  amountXrp: 50,
  terms: 'Ten crates of tea',
  contract: { sha256: 'cd'.repeat(32), pdfUrl: '/c.pdf', nftId: 'NFT123', nftOwner: 'rWallet', mintTx: 'MINTTX' },
  escrow: {
    status: status === 'released' ? 'released' : 'locked',
    amountXrp: 50,
    walletAddress: 'rWallet',
    releaseTx: status === 'released' ? 'RELTX' : undefined,
    keys: tally,
    passports: tally,
    approvals: tally,
  },
  stages: STAGES.map((s, i) => ({ ...s, status: i < done ? 'done' : 'pending' })),
  gate: status === 'released' ? { passed: true, findings: [{ code: 'G-01', ok: true }] } : undefined,
  releasedAt: status === 'released' ? '2026-10-25T11:00:00Z' : undefined,
  releasedBy:
    status === 'released' ? [{ rid: alice.rid, name: 'Alice', signatureFingerprint: 'feedfacefeedface' }] : undefined,
  ledger: { network: 'standalone' },
});

const mock = createLiveMock();
let locked = deal('deal-1', 'locked', 3);
const released = deal('deal-2', 'released', 14);
let created: FormData | undefined;
let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks(
    mock.handler,
    http.get('/api/demo/participants', () => HttpResponse.json([alice, bob])),
    http.get('/api/demo/deals/:id', ({ params }) => HttpResponse.json(params.id === 'deal-2' ? released : locked)),
    http.get('/api/demo/deals', ({ request }) =>
      HttpResponse.json(new URL(request.url).searchParams.get('status') === 'released' ? [released] : [locked]),
    ),
    http.post('/api/demo/deals', async ({ request }) => {
      created = await request.formData();
      return HttpResponse.json(locked);
    }),
  );
});
afterAll(() => worker.stop());
beforeEach(() => {
  locked = deal('deal-1', 'locked', 3);
  created = undefined;
});

const show = () => {
  const qc = createQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={createAppRouter(qc, '/deals')} />
    </QueryClientProvider>,
  );
};
const greens = (c: Element) => c.querySelectorAll('[data-status="done"]').length;

describe('/deals', () => {
  it('lists every participant in both dropdowns and refuses the same person twice', async () => {
    await show();
    const sender = page.getByLabelText('Sender (funds the escrow)');
    await expect.element(sender.getByRole('option', { name: 'Bob · rid_bbbb…' })).toBeInTheDocument();
    await sender.selectOptions(alice.rid);
    await page.getByLabelText('Recipient (paid on release)').selectOptions(alice.rid);
    await expect.element(page.getByText('Sender and recipient must differ.')).toBeVisible();
    await expect.element(page.getByRole('button', { name: 'Create deal' })).toBeDisabled();
  });

  it('creates a deal with the PDF as multipart form data', async () => {
    await show();
    await expect.element(page.getByRole('option', { name: 'Bob · rid_bbbb…' }).first()).toBeInTheDocument();
    await page.getByLabelText('Sender (funds the escrow)').selectOptions(alice.rid);
    await page.getByLabelText('Recipient (paid on release)').selectOptions(bob.rid);
    await page.getByLabelText('Terms').fill('Tea');
    await page.getByLabelText('Contract PDF').upload(new File(['%PDF-1.4'], 'c.pdf', { type: 'application/pdf' }));
    await expect.element(page.getByText(/KB · SHA-256 [0-9a-f]{64}/)).toBeVisible();
    await page.getByRole('button', { name: 'Create deal' }).click();
    await expect.poll(() => created?.get('senderRid')).toBe(alice.rid);
    await expect.element(page.getByRole('article', { name: 'Deal detail' })).toBeVisible();
    expect(created?.get('recipientRid')).toBe(bob.rid);
    expect(created?.get('amountXrp')).toBe('50');
    const pdf = created?.get('contractPdf');
    expect(pdf instanceof File && pdf.type).toBe('application/pdf');
  });

  it('shows locked then released tabs, and the released detail with all metadata', async () => {
    await show();
    await expect.element(page.getByText('Alice to Bob · 50 XRP')).toBeVisible();
    await page.getByRole('tab', { name: /Released escrows/ }).click();
    await page.getByText('Alice to Bob · 50 XRP').click();
    await expect.element(page.getByRole('heading', { name: /Release gate/ })).toBeVisible();
    await expect.element(page.getByText(/signature feedfacefeedface/)).toBeVisible();
    await expect.element(page.getByRole('link', { name: 'PDF preview' })).toHaveAttribute('href', '/api/c.pdf');
    await expect.element(page.getByText(/NFT123 owned by rWallet/)).toBeVisible();
    await page.getByText('All metadata').click();
    await expect.element(page.getByText(/"sha256"/)).toBeVisible();
  });

  it('turns dots green after a poll when the server moves the deal on', async () => {
    const screen = await show();
    await expect.element(page.getByText('Alice to Bob · 50 XRP')).toBeVisible();
    await expect.poll(() => greens(screen.container)).toBe(3);
    locked = deal('deal-1', 'locked', 5);
    await expect.poll(() => greens(screen.container), { timeout: 6000 }).toBe(5);
  });

  it('has no serious axe violations', async () => {
    const screen = await show();
    await expect.element(page.getByText('Alice to Bob · 50 XRP')).toBeVisible();
    const bad = (await axe.run(screen.container)).violations.filter(
      (v) => v.impact === 'serious' || v.impact === 'critical',
    );
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(' | ')}`)).toEqual([]);
  });
});
