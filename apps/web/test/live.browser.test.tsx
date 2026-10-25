import { type QueryClient, QueryClientProvider } from '@tanstack/react-query';
import fc from 'fast-check';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { dealStateKey, type LiveRows, type LiveStatus, liveRowsKey, startLiveFeed } from '../src/lib/live.ts';
import { LiveDealStatus } from '../src/lib/live-status.tsx';
import { createQueryClient } from '../src/lib/query.ts';
import { startMocks } from '../src/mocks/browser.ts';
import { createLiveMock, statePayload } from '../src/mocks/live.ts';

// The mock keeps its outbox between tests, so each test gets a deal of its own.
let DEAL = '';
let counter = 0;
beforeEach(() => {
  DEAL = `0192f0c8-3c4e-7a2b-8c3d-${String(++counter).padStart(12, '0')}`;
});
const mock = createLiveMock();
let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks(mock.handler);
});
afterAll(() => worker.stop());
afterEach(() => mock.drop());

const rowsOf = (qc: QueryClient, dealId = DEAL) => qc.getQueryData<LiveRows>(liveRowsKey(dealId));
const seqs = (qc: QueryClient, dealId = DEAL) => rowsOf(qc, dealId)?.rows.map((r) => r.seq) ?? [];
const FAST = () => 1;

function renderLive(qc: QueryClient, backoffMs: (n: number) => number = FAST) {
  return render(
    <QueryClientProvider client={qc}>
      <LiveDealStatus dealId={DEAL} backoffMs={backoffMs} />
    </QueryClientProvider>,
  );
}

describe('P4.1-03 the live feed updates the cache and the screen', () => {
  it('shows each pushed state, including rows published before the page connected', async () => {
    const id = '0192f0c8-3c4e-7a2b-8c3d-0000000a0003';
    mock.publish(id, 'deal.state', statePayload('DRAFT'));
    const qc = createQueryClient();
    render(
      <QueryClientProvider client={qc}>
        <LiveDealStatus dealId={id} backoffMs={FAST} />
      </QueryClientProvider>,
    );
    await expect.element(page.getByRole('status')).toHaveTextContent('Live');
    await expect.element(page.getByText('DRAFT')).toBeVisible();
    mock.publish(id, 'deal.state', statePayload('SHELL_OPEN'));
    mock.publish(id, 'deal.event', btoa('{}'));
    await expect.element(page.getByText('SHELL_OPEN')).toBeVisible();
    await vi.waitFor(() => expect(seqs(qc, id)).toEqual([0, 1, 2]));
    expect(qc.getQueryData(dealStateKey(id))).toBe('SHELL_OPEN');
    expect(mock.requests.filter((r) => r.subscribe === id)[0]).toEqual({ subscribe: id, after: -1 });
  });

  it('ignores a deal.state payload that is not a deal state', async () => {
    const id = '0192f0c8-3c4e-7a2b-8c3d-0000000a0004';
    mock.publish(id, 'deal.state', statePayload('NOT_A_STATE'));
    mock.publish(id, 'deal.state', btoa('not json'));
    const qc = createQueryClient();
    const feed = startLiveFeed({ dealId: id, queryClient: qc, backoffMs: FAST });
    await vi.waitFor(() => expect(seqs(qc, id)).toEqual([0, 1]));
    expect(qc.getQueryData(dealStateKey(id))).toBeUndefined();
    feed.stop();
  });
});

describe('I-3.7-b / I-3.7-c the server push and the signed upgrade', () => {
  it('a ledger.validated push is read, not treated as a malformed frame, and the feed stays open', async () => {
    const id = '0192f0c8-3c4e-7a2b-8c3d-0000000a0007';
    const qc = createQueryClient();
    const ledgers: number[] = [];
    const feed = startLiveFeed({
      dealId: id,
      queryClient: qc,
      backoffMs: FAST,
      onLedger: (l) => ledgers.push(l.index),
    });
    await vi.waitFor(() => expect(mock.requests.some((r) => r.subscribe === id)).toBe(true));
    mock.pushRaw(id, {
      type: 'ledger',
      topic: 'ledger.validated',
      payload: { index: 1236001, hash: 'AB'.repeat(32), close_time: 800000000 },
    });
    mock.pushRaw(id, { type: 'future-kind', x: 1 });
    mock.publish(id, 'deal.state', statePayload('DRAFT'));
    await vi.waitFor(() => expect(qc.getQueryData(dealStateKey(id))).toBe('DRAFT'));
    expect(ledgers).toEqual([1236001]);
    expect(mock.requests.filter((r) => r.subscribe === id)).toHaveLength(1); // never reconnected
    feed.stop();
  });

  it('signs the upgrade: the auth header travels in ?auth= on every (re)connect', async () => {
    const id = '0192f0c8-3c4e-7a2b-8c3d-0000000a0008';
    const qc = createQueryClient();
    let n = 0;
    const feed = startLiveFeed({
      dealId: id,
      queryClient: qc,
      backoffMs: FAST,
      auth: async () => JSON.stringify({ nonce: `n${++n}` }),
    });
    await vi.waitFor(() => expect(mock.requests.some((r) => r.subscribe === id)).toBe(true));
    expect(decodeURIComponent(mock.urls.at(-1)?.split('?auth=')[1] ?? '')).toBe('{"nonce":"n1"}');
    mock.drop();
    await vi.waitFor(() => expect(n).toBe(2));
    feed.stop();
  });

  it('a signer that fails opens no socket and retries', async () => {
    const id = '0192f0c8-3c4e-7a2b-8c3d-0000000a0009';
    const before = mock.urls.length;
    const states: LiveStatus[] = [];
    const feed = startLiveFeed({
      dealId: id,
      queryClient: createQueryClient(),
      backoffMs: () => 20,
      onStatus: (s) => states.push(s),
      auth: () => Promise.reject(new Error('vault locked')),
    });
    await vi.waitFor(() => expect(states).toContain('reconnecting'));
    expect(mock.urls.length).toBe(before);
    feed.stop();
  });
});

describe('P4.1-04 the socket drops and reconnects', () => {
  it('shows "Reconnecting", asks for rows after its last seq, and shows no gap', async () => {
    const qc = createQueryClient();
    renderLive(qc, () => 400);
    mock.publish(DEAL, 'deal.state', statePayload('DRAFT'));
    mock.publish(DEAL, 'deal.state', statePayload('SHELL_OPEN'));
    await vi.waitFor(() => expect(seqs(qc)).toEqual([0, 1]));
    mock.drop();
    mock.publish(DEAL, 'deal.state', statePayload('KEYS_READY')); // lands while the client is away
    mock.publish(DEAL, 'deal.state', statePayload('WALLET_LOCKED'));
    await expect.element(page.getByRole('status')).toHaveTextContent('Reconnecting');
    await expect.element(page.getByRole('status')).toHaveTextContent('Live');
    expect(mock.requests.filter((r) => r.subscribe === DEAL).at(-1)).toEqual({ subscribe: DEAL, after: 1 });
    await expect.element(page.getByText('WALLET_LOCKED')).toBeVisible();
    expect(seqs(qc)).toEqual([0, 1, 2, 3]);
  });

  it('drops a repeated row when the server replays too much', async () => {
    const qc = createQueryClient();
    const feed = startLiveFeed({ dealId: DEAL, queryClient: qc, backoffMs: FAST });
    for (let i = 0; i < 4; i++) mock.publish(DEAL, 'deal.event', btoa(String(i)));
    await vi.waitFor(() => expect(seqs(qc)).toEqual([0, 1, 2, 3]));
    mock.overlapNextReplay(3);
    mock.drop();
    mock.publish(DEAL, 'deal.event', btoa('4'));
    await vi.waitFor(() => expect(seqs(qc)).toEqual([0, 1, 2, 3, 4]));
    feed.stop();
  });

  it('reconnects when a pushed row is missing, and fetches it again', async () => {
    const qc = createQueryClient();
    const feed = startLiveFeed({ dealId: DEAL, queryClient: qc, backoffMs: FAST });
    mock.publish(DEAL, 'deal.event', btoa('0'));
    await vi.waitFor(() => expect(seqs(qc)).toEqual([0]));
    mock.skipNextPush(1);
    mock.publish(DEAL, 'deal.event', btoa('1')); // never sent
    mock.publish(DEAL, 'deal.event', btoa('2')); // the client sees seq 2 after 0: a gap
    await vi.waitFor(() => expect(seqs(qc)).toEqual([0, 1, 2]));
    expect(mock.requests.filter((r) => r.subscribe === DEAL).at(-1)?.after).toBe(0);
    feed.stop();
  });

  it('stops for good when the server says this role may not read the deal', async () => {
    const qc = createQueryClient();
    const statuses: LiveStatus[] = [];
    const before = mock.requests.length;
    const feed = startLiveFeed({ dealId: DEAL, queryClient: qc, backoffMs: FAST, onStatus: (s) => statuses.push(s) });
    await vi.waitFor(() => expect(mock.requests.length).toBe(before + 1));
    mock.reject('FORBIDDEN');
    await vi.waitFor(() => expect(statuses.at(-1)).toBe('closed'));
    await new Promise((r) => setTimeout(r, 50));
    expect(mock.requests.length).toBe(before + 1); // no retry loop
    expect(statuses).not.toContain('reconnecting');
    feed.stop();
  });

  it('resubscribes after the server overflowed the queue (4408)', async () => {
    const qc = createQueryClient();
    const feed = startLiveFeed({ dealId: DEAL, queryClient: qc, backoffMs: FAST });
    mock.publish(DEAL, 'deal.event', btoa('0'));
    await vi.waitFor(() => expect(seqs(qc)).toEqual([0]));
    mock.reject('OVERFLOW');
    mock.publish(DEAL, 'deal.event', btoa('1'));
    await vi.waitFor(() => expect(seqs(qc)).toEqual([0, 1]));
    feed.stop();
  });

  it('stop() closes the socket and cancels a pending reconnect', async () => {
    const qc = createQueryClient();
    const feed = startLiveFeed({ dealId: DEAL, queryClient: qc, backoffMs: () => 100 });
    mock.publish(DEAL, 'deal.event', btoa('0'));
    await vi.waitFor(() => expect(seqs(qc)).toEqual([0]));
    mock.drop();
    feed.stop();
    const before = mock.requests.length;
    await new Promise((r) => setTimeout(r, 250));
    expect(mock.requests.length).toBe(before);
  });
});

// A fresh deal id per run, in the shape of a UUIDv7.
const dealIdArb = fc
  .tuple(fc.stringMatching(/^[0-9a-f]{3}$/), fc.stringMatching(/^[0-9a-f]{12}$/))
  .map(([a, b]) => `0192f0c8-3c4e-7${a}-8c3d-${b}`.toLowerCase());
const opArb = fc.constantFrom('publish', 'publish', 'publish', 'drop', 'overlap', 'skip', 'wait');

describe('random disconnects (property)', () => {
  it('whatever drops, overlaps and lost rows happen, the cache holds every row exactly once, in order', async () => {
    await fc.assert(
      fc.asyncProperty(dealIdArb, fc.array(opArb, { maxLength: 25 }), async (dealId, ops) => {
        const qc = createQueryClient();
        const seen: number[] = [];
        // Every cache write must extend the rows by exactly one: no repeat and no gap, at any moment.
        const unsubscribe = qc.getQueryCache().subscribe((event) => {
          const data =
            event.query.queryKey[2] === 'live' ? (event.query.state.data as LiveRows | undefined) : undefined;
          if (data) seen.push(data.rows.length === 0 ? -1 : (data.rows.at(-1)?.seq ?? -1));
        });
        const feed = startLiveFeed({ dealId, queryClient: qc, backoffMs: FAST });
        let published = 0;
        for (const op of ops) {
          if (op === 'publish') {
            mock.publish(dealId, 'deal.event', btoa(String(published++)));
          } else if (op === 'drop') mock.drop();
          else if (op === 'overlap') mock.overlapNextReplay(2);
          else if (op === 'skip') mock.skipNextPush(1);
          else await new Promise((r) => setTimeout(r, 2));
        }
        mock.drop(); // a final resync, so a trailing lost row is fetched too
        await vi.waitFor(() => expect(rowsOf(qc, dealId)?.rows.length ?? 0).toBe(published), { timeout: 4000 });
        feed.stop();
        unsubscribe();
        expect(seqs(qc, dealId)).toEqual(Array.from({ length: published }, (_, i) => i));
        const writes = seen.filter((s) => s >= 0);
        expect(writes).toEqual([...new Set(writes)].sort((a, b) => a - b));
        expect(writes.every((s, i) => s === i)).toBe(true);
      }),
      { numRuns: 30 },
    );
  }, 120_000);
});
