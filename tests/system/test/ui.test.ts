// The real web app (Vite dev server, Chromium through Playwright) against the composed server. These tests check
// that the browser side is wired to the server outside the app's own tests, which inject every service.
import { type Browser, chromium, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDeal, type Deal } from '../support/deal.ts';
import { containersUp, LEDGER_CONTAINER, PG_CONTAINER, type Stack, startStack } from '../support/stack.ts';
import { startWeb, WEB_URL } from '../support/web.ts';

let stack: Stack;
let deal: Deal;
let web: Awaited<ReturnType<typeof startWeb>>;
let browser: Browser;
let page: Page;

beforeAll(async () => {
  if (!containersUp())
    throw new Error(
      `start ${PG_CONTAINER} and ${LEDGER_CONTAINER} first (LEGX_SYS_PG, LEGX_SYS_LEDGER, LEGX_SYS_*_CONTAINER)`,
    );
  stack = await startStack();
  deal = await createDeal(stack);
  web = await startWeb();
  browser = await chromium.launch();
  page = await browser.newPage();
}, 240_000);
afterAll(async () => {
  await browser?.close();
  await web?.stop();
  await stack?.stop();
});

const text = async (path: string, settleMs = 4000) => {
  await page.goto(`${WEB_URL}${path}`);
  await page.waitForTimeout(settleMs);
  return await page.locator('body').innerText();
};

describe('UI the browser app is wired to the server', () => {
  it('the dashboard waiting screen renders', async () => {
    expect(await text('/dashboard', 1000)).toContain('Waiting for the first deal');
  });
  it('the web proxy (/api) reaches the server: /api/health answers the profile (I-W-2)', async () => {
    const res = await fetch(`${WEB_URL}/api/health`);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { profile: string }).profile).toBe('demo');
  });
  it('the dashboard shows attack mode: the nine attacks are listed (I-W-2)', async () => {
    const body = await text(`/dashboard?deal=${deal.dealId}`, 6000);
    expect(body).toContain('Stranger finishes the escrow');
  });
  it.fails('the dashboard authenticates its live feed: no observer key exists to do so (I-W-11, OD-31)', async () => {
    const body = await text(`/dashboard?deal=${deal.dealId}`, 6000);
    expect(body.toLowerCase()).toMatch(/live|connected/);
    expect(body.toLowerCase()).not.toMatch(/offline|disconnected|reconnecting/);
  });
  it.fails('the party app shows Alice her deal (I-31: no PartyProvider is mounted outside tests)', async () => {
    expect(await text(`/party/alice?deal=${deal.dealId}`)).not.toContain('no deal yet');
  });
  it.fails('the lawyer console lists the lawyer deals (I-W-10: no console wiring is provided outside tests)', async () => {
    expect(await text('/lawyers')).not.toContain('No deals assigned');
  });
});
