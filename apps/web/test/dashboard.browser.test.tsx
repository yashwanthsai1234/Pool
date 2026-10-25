// Task 4.5: the dashboard and attack mode. P4.5-01 to P4.5-06, plus the "all directions" cases (attacks twice in a row,
// hostile feed rows, a broken chain) and an axe run on the populated dark screen.
import { GATE_CODES, LOCK_CODES } from '@legx/contracts/records';
import { QueryClientProvider } from '@tanstack/react-query';
import axe from 'axe-core';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { cdp, page, server } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { createQueryClient } from '../src/lib/query.ts';
import { startMocks } from '../src/mocks/browser.ts';
import { createLiveMock, statePayload } from '../src/mocks/live.ts';
import {
  ATTACKS,
  type AttackClient,
  type AttackId,
  type AttackResult,
  httpAttackClient,
} from '../src/routes/dashboard/-attack-api.ts';
import { Dashboard } from '../src/routes/dashboard/-dashboard.tsx';
import { explorerUrl, type Network } from '../src/routes/dashboard/-explorer.ts';
import { buildView, LOCK_STEPS } from '../src/routes/dashboard/-model.ts';
import '../src/index.css';

const mock = createLiveMock();
let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks(mock.handler);
});
afterAll(() => worker.stop());
afterEach(() => mock.drop());

let counter = 0;
let DEAL = '';
beforeEach(() => {
  DEAL = `0192f0c8-3c4e-7a2b-8c3d-${String(++counter + 4500).padStart(12, '0')}`;
});

const HASH = (n: number) => n.toString(16).toUpperCase().padStart(64, 'A');
const json = (x: unknown) => btoa(JSON.stringify(x));

/** A `deal.event` row as the server pushes it (OD-9): `{ envelope, summary }`. */
function event(
  kind: string,
  seq: number,
  data: object = {},
  ledger?: { tx_hash: string; ledger_index: number },
  state?: string,
) {
  const statement = { predicate: { kind, seq, data } };
  const envelope = json({ payloadType: 'application/vnd.in-toto+json', payload: json(statement) });
  return json({ envelope, summary: { kind, ...(state ? { state } : {}), ...(ledger ? { ledger } : {}) } });
}
const observation = (type: string, n: number) =>
  json({ hash: HASH(n), ledger_index: 100 + n, account: 'rX', tx_type: type });

const RESULTS: Record<AttackId, AttackResult> = {
  'stranger-finish': {
    attack: 'stranger-finish',
    defeated: true,
    code: 'tecNO_PERMISSION',
    detail: 'stranger',
    txHash: HASH(900),
    ledgerIndex: 40,
  },
  'master-key-on': {
    attack: 'master-key-on',
    defeated: true,
    code: 'MASTER_DISABLED',
    detail: 'key left on',
    findings: [{ ok: false, level: 'block', code: 'MASTER_DISABLED' }],
  },
  'double-exit': {
    attack: 'double-exit',
    defeated: true,
    code: 'tefPAST_SEQ',
    detail: 'second exit',
    txHash: HASH(901),
    ledgerIndex: 111,
  },
  'bundle-byte': { attack: 'bundle-byte', defeated: true, code: 'FAIL:archive', detail: 'one bit changed' },
  'fake-passport': {
    attack: 'fake-passport',
    defeated: true,
    code: 'DS_NOT_CHAINED',
    detail: 'rogue CSCA',
    findings: [{ ok: false, level: 'block', code: 'PASSPORT_A_OK', detail: 'DS_NOT_CHAINED' }],
  },
  'stale-bar': {
    attack: 'stale-bar',
    defeated: true,
    code: 'BAR_A_OK,BAR_B_OK',
    detail: 'stale',
    findings: [
      { ok: false, level: 'block', code: 'BAR_A_OK', detail: 'STALE' },
      { ok: false, level: 'block', code: 'BAR_B_OK', detail: 'STALE' },
    ],
  },
  'stripped-pq': {
    attack: 'stripped-pq',
    defeated: true,
    code: 'B:CROSS_SIG_MISSING',
    detail: 'stripped',
    findings: [{ ok: false, level: 'block', code: 'PQ_BINDINGS_OK', detail: 'B:CROSS_SIG_MISSING' }],
  },
  'replayed-zk': { attack: 'replayed-zk', defeated: true, code: 'BOUND_VALUE_MISMATCH', detail: 'replay' },
  'foreign-share': { attack: 'foreign-share', defeated: true, code: 'SHARE_INVALID', detail: 'foreign share' },
};
function stubClient(available = true): AttackClient & { calls: AttackId[] } {
  const calls: AttackId[] = [];
  return {
    calls,
    available: async () => available,
    run: async (id) => {
      calls.push(id);
      return RESULTS[id];
    },
  };
}

function show(client: AttackClient = stubClient(), network: Network = 'testnet') {
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <Dashboard dealId={DEAL} network={network} attackClient={client} />
    </QueryClientProvider>,
  );
}
const passCodes = (container: Element) =>
  [...container.querySelectorAll('[data-code][data-status="pass"]')].map((e) => e.getAttribute('data-code'));
const statusOf = (container: Element, code: string) =>
  container.querySelector(`[data-code="${code}"]`)?.getAttribute('data-status');

describe('P4.5-01 the ledger log and explorer links', () => {
  it('uses the patterns of IMPLEMENTATION 4.5 for transactions, accounts and NFTs, on both explorers', () => {
    expect(explorerUrl('testnet', 'tx', 'AB12')).toBe('https://testnet.xrpl.org/transactions/AB12');
    expect(explorerUrl('testnet', 'account', 'rAddr')).toBe('https://testnet.xrpl.org/accounts/rAddr');
    expect(explorerUrl('testnet', 'nft', '0008')).toBe('https://testnet.xrpl.org/nft/0008');
    expect(explorerUrl('testnet', 'tx', 'AB12', true)).toBe('https://test.bithomp.com/en/explorer/AB12');
    expect(explorerUrl('testnet', 'account', 'rAddr', true)).toBe('https://test.bithomp.com/en/account/rAddr');
    expect(explorerUrl('testnet', 'nft', '0008', true)).toBe('https://test.bithomp.com/en/nft/0008');
    expect(explorerUrl('devnet', 'tx', 'AB12')).toBe('https://devnet.xrpl.org/transactions/AB12');
    expect(explorerUrl('standalone', 'tx', 'AB12')).toBeUndefined();
    expect(explorerUrl('devnet', 'tx', 'AB12', true)).toBeUndefined(); // bithomp backup is Testnet only
    expect(explorerUrl('testnet', 'tx', '../x?y')).toBe('https://testnet.xrpl.org/transactions/..%2Fx%3Fy'); // hostile id
  });

  it('shows each validated step with a link for the active network, in feed order', async () => {
    mock.publish(DEAL, 'deal.event', event('shell.opened', 0, {}, { tx_hash: HASH(1), ledger_index: 11 }));
    mock.publish(DEAL, 'deal.event', event('nft.minted', 1, {}, { tx_hash: HASH(2), ledger_index: 12 }));
    mock.publish(DEAL, 'deal.event', event('bar.verified', 2)); // no ledger step: not in the ledger log
    const s = await show();
    await vi.waitFor(() => expect(s.container.querySelectorAll('section[aria-label="Ledger log"] a')).toHaveLength(2));
    const hrefs = [...s.container.querySelectorAll('section[aria-label="Ledger log"] a')].map((a) =>
      a.getAttribute('href'),
    );
    expect(hrefs).toEqual([
      `https://testnet.xrpl.org/transactions/${HASH(1)}`,
      `https://testnet.xrpl.org/transactions/${HASH(2)}`,
    ]);
    await expect.element(page.getByText('Contract NFT minted')).toBeVisible();
    mock.publish(DEAL, 'deal.event', event('escrow.created', 3, {}, { tx_hash: HASH(3), ledger_index: 13 }));
    await vi.waitFor(() => expect(s.container.querySelectorAll('section[aria-label="Ledger log"] a')).toHaveLength(3));
  });

  it('the standalone ledger has no explorer, so no link', async () => {
    mock.publish(DEAL, 'deal.event', event('shell.opened', 0, {}, { tx_hash: HASH(1), ledger_index: 11 }));
    const s = await show(stubClient(), 'standalone');
    await expect.element(page.getByText('Shell opened')).toBeVisible();
    expect(s.container.querySelectorAll('section[aria-label="Ledger log"] a')).toHaveLength(0);
  });
});

describe('P4.5-02 the lock checker turns PASS one step at a time', () => {
  const step = (type: string, n: number) => ({ topic: 'ledger.observation' as const, payload: observation(type, n) });
  const rowsFor = (n: number) => LOCK_STEPS.slice(0, n).map((s, i) => ({ seq: i, ...step(s.type, i) }));

  it('follows the ledger: after step k exactly the codes of steps 1..k pass', () => {
    for (let k = 0; k <= LOCK_STEPS.length; k++) {
      const view = buildView(rowsFor(k), undefined);
      const expected = LOCK_STEPS.slice(0, k).flatMap((s) => s.codes);
      expect(
        view.lock
          .filter((i) => i.status === 'pass')
          .map((i) => i.code)
          .sort(),
      ).toEqual([...expected].sort());
      expect(view.lock).toHaveLength(LOCK_CODES.length);
    }
  });

  it('a transaction out of order does not pass a later step', () => {
    const view = buildView(
      [
        { seq: 0, ...step('DepositPreauth', 1) },
        { seq: 1, ...step('CredentialAccept', 2) },
      ],
      undefined,
    );
    expect(view.lock.every((i) => i.status === 'pending')).toBe(true);
  });

  it('on screen, each pushed step turns its items PASS and nothing else', async () => {
    const s = await show();
    await expect.element(page.getByRole('status', { name: 'Live feed' })).toHaveTextContent('Feed: open');
    expect(passCodes(s.container).filter((c) => LOCK_CODES.includes(c as never))).toEqual([]);
    let seq = 0;
    const seen: string[] = [];
    for (const st of LOCK_STEPS.slice(0, 3)) {
      mock.publish(DEAL, 'ledger.observation', observation(st.type, seq++));
      seen.push(...st.codes);
      await vi.waitFor(() =>
        expect(
          passCodes(s.container)
            .filter((c) => LOCK_CODES.includes(c as never))
            .sort(),
        ).toEqual([...seen].sort()),
      );
    }
    await expect
      .element(page.getByTestId('Lock checker-count'))
      .toHaveTextContent(`${seen.length} of ${LOCK_CODES.length} pass`);
  });

  it('lock.verified is the final word: a failing finding turns its item red', () => {
    const findings = LOCK_CODES.map((code) => ({ ok: code !== 'MASTER_DISABLED', level: 'block', code }));
    const rows = [{ seq: 0, topic: 'deal.event' as const, payload: event('lock.verified', 0, { findings }) }];
    const view = buildView(rows, undefined);
    expect(view.lock.find((i) => i.code === 'MASTER_DISABLED')?.status).toBe('fail');
    expect(view.lock.filter((i) => i.status === 'pass')).toHaveLength(LOCK_CODES.length - 1);
  });
});

describe('the other panels', () => {
  it('the deal state, 15 gate codes, FROST pair, evidence chain and Merkle root', async () => {
    mock.publish(DEAL, 'deal.state', statePayload('WALLET_LOCKED'));
    mock.publish(
      DEAL,
      'deal.event',
      event('frost.signed', 0, { slot: 'LB', signer_key_ids: ['LB/console', 'LB/firm-hsm'] }),
    );
    mock.publish(
      DEAL,
      'deal.event',
      event('release.gate.passed', 1, {
        gate: { findings: GATE_CODES.map((code) => ({ ok: true, level: 'block', code })) },
      }),
    );
    mock.publish(
      DEAL,
      'deal.event',
      event('checkpoint.anchored', 2, {
        tree_size: 3,
        root: 'ab'.repeat(32),
        anchor_tx_hash: HASH(7),
        anchor_ledger: 77,
      }),
    );
    const s = await show();
    await expect.element(page.getByText('WALLET_LOCKED')).toHaveAttribute('aria-current', 'step');
    await vi.waitFor(() =>
      expect(s.container.querySelectorAll('section[aria-label="Release gate"] li[data-status="pass"]')).toHaveLength(
        15,
      ),
    );
    expect(GATE_CODES).toHaveLength(15);
    await expect.element(page.getByText('LB/console + LB/firm-hsm')).toBeVisible();
    await expect.element(page.getByTestId('chain-status')).toHaveTextContent('intact, gap-free');
    await expect.element(page.getByTestId('merkle-root')).toHaveTextContent('abababab…abababab');
    await expect.element(page.getByRole('link', { name: /AAAAAA/ }).first()).toBeVisible();
  });

  it('a gap in the event sequence shows the chain as BROKEN', async () => {
    mock.publish(DEAL, 'deal.event', event('shell.opened', 0));
    mock.publish(DEAL, 'deal.event', event('nft.minted', 2));
    await show();
    await expect.element(page.getByTestId('chain-status')).toHaveTextContent('BROKEN');
  });

  it('hostile rows are ignored: bad JSON, an unknown kind with no ledger, a wrong ledger shape', async () => {
    mock.publish(DEAL, 'deal.event', btoa('not json'));
    mock.publish(DEAL, 'deal.event', json({ summary: { kind: 'x.y', ledger: { tx_hash: 5, ledger_index: 'no' } } }));
    mock.publish(DEAL, 'ledger.observation', btoa('[1,2'));
    mock.publish(DEAL, 'deal.event', event('shell.opened', 0, {}, { tx_hash: HASH(1), ledger_index: 11 }));
    const s = await show();
    await expect.element(page.getByText('Shell opened')).toBeVisible();
    expect(s.container.querySelectorAll('section[aria-label="Ledger log"] li')).toHaveLength(1);
  });
});

describe('P4.5-03 the attack buttons', () => {
  it.each(ATTACKS)('$id: posts, then shows the engine code or check that stopped it', async ({ id, label }) => {
    const client = stubClient();
    const s = await show(client);
    await page.getByRole('button', { name: label }).click();
    await expect.element(page.getByTestId('attack-code')).toHaveTextContent(RESULTS[id].code);
    expect(client.calls).toEqual([id]);
    await expect.element(page.getByText('Attack stopped')).toBeVisible();
    expect(s.container.querySelectorAll('section[aria-label="Attack mode"] button')).toHaveLength(9);
  });

  it('master key left on: the lock checker item turns red; a stale bar turns BAR_A_OK and BAR_B_OK red', async () => {
    const s = await show();
    await page.getByRole('button', { name: 'Master key left on' }).click();
    await vi.waitFor(() => expect(statusOf(s.container, 'MASTER_DISABLED')).toBe('fail'));
    await page.getByRole('button', { name: 'Stale bar check' }).click();
    await vi.waitFor(() => expect(statusOf(s.container, 'BAR_A_OK')).toBe('fail'));
    expect(statusOf(s.container, 'BAR_B_OK')).toBe('fail');
    expect(statusOf(s.container, 'MASTER_DISABLED')).toBe('pending'); // the newer result replaced the older one
  });

  it('each attack twice in a row gives the same result both times', async () => {
    const client = stubClient();
    await show(client);
    for (const { id, label } of ATTACKS) {
      for (let i = 0; i < 2; i++) {
        await page.getByRole('button', { name: label }).click();
        await expect.element(page.getByTestId('attack-code')).toHaveTextContent(RESULTS[id].code);
      }
    }
    expect(client.calls).toHaveLength(18);
  });

  it('the buttons are disabled while one attack runs, and a failed run shows the error', async () => {
    let release: (r: AttackResult) => void = () => undefined;
    const slow: AttackClient = {
      available: async () => true,
      run: () => new Promise((r) => (release = r)),
    };
    await show(slow);
    await page.getByRole('button', { name: 'Double exit on slot S' }).click();
    await expect.element(page.getByRole('button', { name: 'Master key left on' })).toBeDisabled();
    release(RESULTS['double-exit']);
    await expect.element(page.getByTestId('attack-code')).toHaveTextContent('tefPAST_SEQ');
  });

  it('a failed run shows the error', async () => {
    const failing: AttackClient = {
      available: async () => true,
      run: async () => Promise.reject(new Error('attack x failed: HTTP 500')),
    };
    await show(failing);
    await page.getByRole('button', { name: 'Stale bar check' }).click();
    await expect.element(page.getByText('attack x failed: HTTP 500')).toBeVisible();
  });

  it('a transaction hash in a result links to the explorer of the active network', async () => {
    const s = await show();
    await page.getByRole('button', { name: 'Stranger finishes the escrow' }).click();
    await vi.waitFor(() =>
      expect(s.container.querySelector('[data-testid="attack-result"] a')?.getAttribute('href')).toBe(
        `https://testnet.xrpl.org/transactions/${HASH(900)}`,
      ),
    );
  });
});

describe('P4.5-04 attack mode is off unless the server runs the demo profile', () => {
  it('no buttons are rendered when the server does not answer the attack list', async () => {
    const s = await show(stubClient(false));
    await expect.element(page.getByRole('heading', { name: 'Deal dashboard' })).toBeVisible();
    await new Promise((r) => setTimeout(r, 100));
    expect(s.container.querySelector('section[aria-label="Attack mode"]')).toBeNull();
    expect(s.container.querySelectorAll('button')).toHaveLength(0);
  });

  it('the http client is available only on a 200: a production server answers 401 or 404, or is unreachable', async () => {
    const fetchWith = (status: number | 'throw') =>
      vi.stubGlobal('fetch', async () =>
        status === 'throw' ? Promise.reject(new TypeError('down')) : new Response('{}', { status }),
      );
    try {
      for (const [status, want] of [
        [200, true],
        [401, false],
        [404, false],
        [500, false],
        ['throw', false],
      ] as const) {
        fetchWith(status);
        expect(await httpAttackClient('/api').available(), String(status)).toBe(want);
      }
      fetchWith(404);
      await expect(httpAttackClient('/api').run('double-exit')).rejects.toThrow('HTTP 404');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('a reply that is not an attack result is refused', async () => {
    vi.stubGlobal(
      'fetch',
      async () => new Response(JSON.stringify({ attack: 'drop-tables', defeated: true }), { status: 200 }),
    );
    try {
      await expect(httpAttackClient('/api').run('double-exit')).rejects.toThrow();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('P4.5-05 visual snapshot at 1920 x 1080, dark', () => {
  it('matches the baseline', async () => {
    await page.viewport(1920, 1080);
    mock.publish(DEAL, 'deal.state', statePayload('WALLET_LOCKED'));
    for (const [i, st] of LOCK_STEPS.entries()) mock.publish(DEAL, 'ledger.observation', observation(st.type, i));
    mock.publish(DEAL, 'deal.event', event('shell.opened', 0, {}, { tx_hash: HASH(1), ledger_index: 11 }));
    mock.publish(DEAL, 'deal.event', event('escrow.created', 1, {}, { tx_hash: HASH(2), ledger_index: 12 }));
    mock.publish(DEAL, 'deal.event', event('wallet.locked', 2, {}, { tx_hash: HASH(3), ledger_index: 13 }));
    mock.publish(
      DEAL,
      'deal.event',
      event('frost.signed', 3, { slot: 'A', signer_key_ids: ['A/phone', 'A/second-authenticator'] }),
    );
    mock.publish(
      DEAL,
      'deal.event',
      event('checkpoint.anchored', 4, {
        tree_size: 5,
        root: 'cd'.repeat(32),
        anchor_tx_hash: HASH(8),
        anchor_ledger: 15,
      }),
    );
    const client = stubClient();
    const s = await show(client);
    await vi.waitFor(() => expect(s.container.querySelectorAll('section[aria-label="Ledger log"] li')).toHaveLength(3));
    await page.getByRole('button', { name: 'Stale bar check' }).click();
    await expect.element(page.getByTestId('attack-code')).toHaveTextContent('BAR_A_OK,BAR_B_OK');
    await new Promise((r) => setTimeout(r, 1500)); // let the 900 ms highlight finish: the snapshot must be still
    // The baselines are macOS renders; fonts differ on other platforms, so the pixel comparison runs only there.
    if (server.platform === 'darwin')
      await expect.element(page.getByTestId('dashboard')).toMatchScreenshot('dashboard-1920x1080-dark');
  });
});

describe('P4.5-06 prefers-reduced-motion', () => {
  const motion = (s: { container: Element }) =>
    [...s.container.querySelectorAll('.legx-flash, .legx-meter')].map((e) => {
      const c = getComputedStyle(e);
      return { name: c.animationName, transition: c.transitionDuration };
    });

  it('the stylesheet removes every animation and transition under the media query', async () => {
    const rules: string[] = [];
    for (const sheet of document.styleSheets)
      for (const r of sheet.cssRules)
        if (r instanceof CSSMediaRule && r.conditionText.includes('prefers-reduced-motion'))
          rules.push(...[...r.cssRules].map((x) => x.cssText));
    const text = rules.join(' ');
    expect(text).toContain('.legx-flash');
    expect(text).toMatch(/animation-name: none/);
    expect(text).toMatch(/transition: none/);
  });

  it('with the preference on, no element animates', async (ctx) => {
    const session = cdp();
    try {
      await session.send('Emulation.setEmulatedMedia', {
        features: [{ name: 'prefers-reduced-motion', value: 'reduce' }],
      });
    } catch {
      return ctx.skip(); // WebKit has no CDP: the stylesheet test above covers it
    }
    try {
      mock.publish(DEAL, 'deal.state', statePayload('DRAFT'));
      const s = await show();
      await expect.element(page.getByText('DRAFT')).toBeVisible();
      expect(matchMedia('(prefers-reduced-motion: reduce)').matches).toBe(true);
      const all = motion(s);
      expect(all.length).toBeGreaterThan(0);
      expect(all.every((m) => m.name === 'none')).toBe(true);
    } finally {
      await session.send('Emulation.setEmulatedMedia', {
        features: [{ name: 'prefers-reduced-motion', value: 'no-preference' }],
      });
    }
  });

  it('with no preference the highlight does animate (so the test above could fail)', async () => {
    mock.publish(DEAL, 'deal.state', statePayload('DRAFT'));
    const s = await show();
    await expect.element(page.getByText('DRAFT')).toBeVisible();
    expect(motion(s).some((m) => m.name !== 'none')).toBe(true);
  });
});

describe('accessibility', () => {
  it('has no serious or critical axe violations on the populated dark screen', async () => {
    for (const [i, st] of LOCK_STEPS.slice(0, 4).entries())
      mock.publish(DEAL, 'ledger.observation', observation(st.type, i));
    mock.publish(DEAL, 'deal.event', event('shell.opened', 0, {}, { tx_hash: HASH(1), ledger_index: 11 }));
    const s = await show();
    await page.getByRole('button', { name: 'Master key left on' }).click();
    await expect.element(page.getByTestId('attack-code')).toHaveTextContent('MASTER_DISABLED');
    await new Promise((r) => setTimeout(r, 1200));
    const results = await axe.run(s.container);
    const bad = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.html.slice(0, 120)).join(' | ')}`)).toEqual([]);
  });
});

describe('OD-31 the dashboard signs its feed upgrade with the observer key', () => {
  it('opens the socket with ?auth= when a feed is given, and still shows live rows', async () => {
    const auth = vi.fn(async () => JSON.stringify({ nonce: 'x' }));
    const feed = { auth, onLedger: () => {} };
    const screen = await render(
      <QueryClientProvider client={createQueryClient()}>
        <Dashboard dealId={DEAL} network="testnet" attackClient={stubClient()} feed={feed} />
      </QueryClientProvider>,
    );
    await vi.waitFor(() => expect(mock.urls.some((u) => u.includes('?auth='))).toBe(true));
    expect(auth).toHaveBeenCalled();
    mock.publish(DEAL, 'deal.state', statePayload('SHELL_OPEN'));
    await expect.element(screen.getByText('Feed: open')).toBeVisible();
  });
});
