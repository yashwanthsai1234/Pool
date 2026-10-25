import { type Browser, chromium, webkit } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildTo, serve } from './builds.ts';

const ROUTES = [
  ['/party/alice', 'Hello Alice, no deal yet'],
  ['/lawyers', 'No deals assigned'],
  ['/dashboard', 'Waiting for the first deal'],
] as const;

let normal: string;
let killed: string;
let server: Awaited<ReturnType<typeof serve>>;
beforeAll(async () => {
  [normal, killed] = [await buildTo(false), await buildTo(true)];
  server = await serve(normal);
});
afterAll(() => server.close());

describe.each([
  ['chromium', chromium],
  ['webkit', webkit],
] as const)('built app in %s', (_name, engine) => {
  let browser: Browser;
  beforeAll(async () => {
    browser = await engine.launch();
  });
  afterAll(() => browser.close());

  for (const [path, heading] of ROUTES) {
    it(`${path} boots under the production CSP with no violation and no console error`, async () => {
      const page = await (await browser.newContext({ serviceWorkers: 'block' })).newPage();
      const problems: string[] = [];
      page.on('console', (m) => m.type() === 'error' && problems.push(`console: ${m.text()}`));
      page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
      await page.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', (e) =>
          console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`),
        );
      });
      await page.goto(server.url + path);
      await page.getByRole('heading', { name: heading }).waitFor();
      expect(problems).toEqual([]);
      await page.context().close();
    });
  }

  // connect-src 'self' must cover a same-host WebSocket in WebKit too (CSP3: 'self' matches ws/wss on the same host).
  // Source: https://www.w3.org/TR/CSP3/#match-url-to-source-expression
  it("connect-src 'self' allows the same-host WebSocket and blocks another host", async () => {
    const page = await (await browser.newContext({ serviceWorkers: 'block' })).newPage();
    await page.goto(`${server.url}/lawyers`);
    const violations = await page.evaluate(async () => {
      const found: string[] = [];
      document.addEventListener('securitypolicyviolation', (e) => found.push(`${e.violatedDirective} ${e.blockedURI}`));
      const attempt = (url: string) =>
        new Promise<string>((resolve) => {
          try {
            const ws = new WebSocket(url); // the preview server has no socket: it fails, but only after the CSP check
            ws.onerror = () => resolve('network error');
            ws.onclose = () => resolve('network error');
          } catch (e) {
            resolve(`threw ${(e as Error).name}`); // WebKit throws for a URL its CSP blocks
          }
        });
      const same = await attempt(`ws://${location.host}/ws`);
      const sameHost = [...found];
      const other = await attempt('ws://other.example.invalid/ws');
      await new Promise((r) => setTimeout(r, 50));
      return { same, other, sameHost, all: found };
    });
    expect(violations.same).toBe('network error'); // reached the network: the CSP let it through
    expect(violations.sameHost).toEqual([]);
    expect(violations.all.some((v) => v.startsWith('connect-src'))).toBe(true); // control: the check is live
    await page.context().close();
  });

  it('registers the service worker under Trusted Types, then the kill-switch build removes it', async () => {
    server.setDir(normal);
    const context = await browser.newContext();
    const page = await context.newPage();
    const problems: string[] = [];
    page.on('console', (m) => m.type() === 'error' && problems.push(m.text()));
    await page.goto(`${server.url}/lawyers`);
    await page.evaluate(() => navigator.serviceWorker.ready.then(() => undefined));
    expect(await page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length)).toBe(1);
    expect(problems).toEqual([]);

    server.setDir(killed); // the "redeploy" with the kill switch on
    await page.evaluate(async () => {
      for (const r of await navigator.serviceWorker.getRegistrations()) await r.update();
    });
    await expect
      .poll(() => page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length), {
        timeout: 20_000,
      })
      .toBe(0);
    await context.close();
  });
});
