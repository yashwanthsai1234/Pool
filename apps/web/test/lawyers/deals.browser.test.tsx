// I-W-10 / OD-35: the lawyer console lists its deals from the vault's own metadata. For each deal it calls `deals.mine`
// signed with that deal's console enrollment key (no long-lived key links one lawyer's deals) to learn the role and the state.
import { ApiAuth } from '@legx/contracts/api';
import { connectVault, createVault, serveVault, vaultFrameHost } from '@legx/vault';
import { HttpResponse, http } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { dealId, freshDb } from '../../../../packages/vault/test/helpers.ts';
import { frameApiClient } from '../../src/lib/vault-frame.tsx';
import { startMocks } from '../../src/mocks/browser.ts';
import { contractLedgerRelay, rpcPublicLedger } from '../../src/routes/lawyers/-console/compose.ts';
import { LawyerDeals, listLawyerDeals } from '../../src/routes/lawyers/-deals.tsx';
import '../../src/index.css';

let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks();
});
afterEach(() => worker.resetHandlers());
afterAll(() => worker.stop());

async function lawyer() {
  const dbName = freshDb();
  const { port1, port2 } = new MessageChannel();
  serveVault(
    port2,
    createVault({ role: 'lawyerA', dbName, deals: () => Promise.reject(new Error('x')) }),
    vaultFrameHost({ role: 'lawyerA', dbName }),
  );
  const vault = connectVault(port1);
  const ids = [dealId(), dealId(), dealId()];
  await vault.enroll(ids[0] as string, 'console-0');
  await vault.enroll(ids[1] as string, 'console-1');
  await vault.enroll(ids[2] as string, 'console-2');
  const keysSeen: string[] = [];
  worker.use(
    http.get('*/api/deals', ({ request }) => {
      const auth = ApiAuth.parse(JSON.parse(request.headers.get('x-legx-auth') ?? '{}'));
      const pair = auth.signatures[0]?.keyid.split('#')[0] ?? '';
      keysSeen.push(pair);
      if (pair === 'console-2') return HttpResponse.json({ code: 'FORBIDDEN' }, { status: 403 });
      return HttpResponse.json({
        deals: [
          {
            dealId: ids[Number(pair.slice(-1))],
            role: 'lawyerA',
            state: pair === 'console-0' ? 'DRAFT' : 'SHELL_OPEN',
          },
        ],
      });
    }),
  );
  const apiFor = (id: string) => frameApiClient(vault, async () => 900, id);
  return { vault, ids, keysSeen, apiFor };
}

describe('OD-35 the lawyer console lists its deals', () => {
  it('asks once per deal, signed with that deal key, and returns role and state', async () => {
    const w = await lawyer();
    const rows = await listLawyerDeals(w.vault, w.apiFor);
    expect(w.keysSeen.sort()).toEqual(['console-0', 'console-1', 'console-2']);
    expect(rows.find((r) => r.dealId === w.ids[0])).toMatchObject({ role: 'lawyerA', state: 'DRAFT' });
    expect(rows.find((r) => r.dealId === w.ids[1])).toMatchObject({ state: 'SHELL_OPEN' });
  });

  it('a deal the server refuses is shown with its error, never dropped', async () => {
    const w = await lawyer();
    const rows = await listLawyerDeals(w.vault, w.apiFor);
    expect(rows.find((r) => r.dealId === w.ids[2])).toMatchObject({ error: expect.any(String) });
  });

  it('renders the deals with their state, and the empty state when the vault holds none', async () => {
    const w = await lawyer();
    const rows = await listLawyerDeals(w.vault, w.apiFor);
    const screen = await render(<LawyerDeals rows={rows} />);
    await expect.element(page.getByText(/SHELL_OPEN/)).toBeVisible();
    await expect.element(page.getByText(/could not be read/)).toBeVisible();
    await screen.unmount();
    await render(<LawyerDeals rows={[]} />);
    await expect.element(page.getByText('No deals assigned')).toBeVisible();
  });
});

describe('console ports over the contract routes', () => {
  it('the ledger relay reads the snapshot, the sequence and submits through ledger.*', async () => {
    const w = await lawyer();
    const sent: unknown[] = [];
    worker.use(
      http.get('*/api/deals/:id/ledger-snapshot', () =>
        HttpResponse.json({ releaseInput: { lawyerNonce: { $b64: 'AQID' }, n: 7 } }),
      ),
      http.get('*/api/ledger/accounts/:a', () =>
        HttpResponse.json({ exists: true, ledgerIndex: 5, flags: 0, sequence: 44, balanceDrops: '1' }),
      ),
      http.post('*/api/ledger/submit', async ({ request }) => {
        sent.push(await request.json());
        return HttpResponse.json({ status: 'validated', result: 'tesSUCCESS', hash: 'AB'.repeat(32), ledgerIndex: 6 });
      }),
    );
    const relay = contractLedgerRelay(w.apiFor(w.ids[0] as string));
    const snap = (await relay.snapshot(w.ids[0] as string)) as unknown as { lawyerNonce: Uint8Array; n: number };
    expect([...snap.lawyerNonce]).toEqual([1, 2, 3]);
    expect(snap.n).toBe(7);
    expect(await relay.accountSequence('rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f')).toBe(44);
    expect(await relay.submit('AA')).toEqual({
      validated: true,
      hash: 'AB'.repeat(32),
      ledgerIndex: 6,
      result: 'tesSUCCESS',
    });
    expect(sent).toEqual([{ txBlob: 'AA' }]);
  });

  it('a rejected or expired submission is not validated', async () => {
    const w = await lawyer();
    worker.use(
      http.post('*/api/ledger/submit', () => HttpResponse.json({ status: 'rejected', result: 'tecNO_PERMISSION' })),
    );
    const relay = contractLedgerRelay(w.apiFor(w.ids[0] as string));
    expect(await relay.submit('AA')).toMatchObject({ validated: false, result: 'tecNO_PERMISSION' });
  });

  it('the public ledger reads the validated header and a hash by index from the lawyer’s own node', async () => {
    const calls: unknown[] = [];
    const fetchRpc = (async (_u: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      calls.push(body.params[0]);
      return Response.json({
        result: {
          validated: true,
          ledger_hash: 'CD'.repeat(32),
          ledger: {
            ledger_index: String(body.params[0].ledger_index === 'validated' ? 900 : body.params[0].ledger_index),
            close_time: 123,
          },
        },
      });
    }) as typeof fetch;
    const ledger = rpcPublicLedger('https://node.example', fetchRpc);
    expect(await ledger.latest()).toEqual({ index: 900, hash: 'CD'.repeat(32), closeTime: 123 });
    expect(await ledger.hashAt(850)).toBe('CD'.repeat(32));
  });
});
