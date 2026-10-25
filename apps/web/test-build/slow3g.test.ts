// I-5 / P4.1-05b: the phone route over a throttled link, for real (CDP network emulation, not an injected flag).
// "Slow 3G" is the DevTools preset: about 400 kbit/s down and up, 400 ms round trip.
// Source: https://chromedevtools.github.io/devtools-protocol/tot/Network/#method-emulateNetworkConditions
// Source: https://github.com/GoogleChrome/lighthouse/blob/main/core/config/constants.ts (throttling presets)
import { chromium } from 'playwright';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { PHONE_ROUTE_BUDGET_BYTES } from '../scripts/budget.ts';
import { buildTo, serve } from './builds.ts';

let server: Awaited<ReturnType<typeof serve>>;
beforeAll(async () => {
  server = await serve(await buildTo(false));
});
afterAll(() => server.close());

it('the phone route shows its first screen within 20 s on Slow 3G, over no more than the budget', async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ serviceWorkers: 'block' });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('Network.enable');
  await cdp.send('Network.emulateNetworkConditions', {
    offline: false,
    latency: 400,
    downloadThroughput: (400 * 1000) / 8,
    uploadThroughput: (400 * 1000) / 8,
  });
  let wire = 0;
  cdp.on('Network.loadingFinished', (e: { encodedDataLength: number }) => {
    wire += e.encodedDataLength;
  });
  const t0 = Date.now();
  await page.goto(`${server.url}/party/alice`);
  await page.getByRole('heading', { name: 'Hello Alice, no deal yet' }).waitFor({ timeout: 20_000 });
  const seconds = (Date.now() - t0) / 1000;
  await browser.close();
  expect(seconds).toBeGreaterThan(1); // the throttle is really on: four round trips alone cost 1.6 s
  expect(seconds).toBeLessThan(20);
  expect(wire).toBeLessThan(PHONE_ROUTE_BUDGET_BYTES + 20_000); // the route's own files plus the HTML and manifest
}, 60_000);
