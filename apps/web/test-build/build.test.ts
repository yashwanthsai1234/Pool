import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { CSP_META } from '../csp.ts';
import { PHONE_ROUTE_BUDGET_BYTES, phoneRouteFiles, phoneRouteGzipBytes } from '../scripts/budget.ts';
import { buildTo } from './builds.ts';

let normal: string;
let killed: string;
beforeAll(async () => {
  normal = await buildTo(false);
  killed = await buildTo(true);
});

describe('production build', () => {
  // P4.1-06
  it('phone route stays under the gzip budget and does not ship other routes or xrpl', () => {
    const bytes = phoneRouteGzipBytes(normal);
    expect(bytes).toBeGreaterThan(10_000); // sanity: we measured something real
    expect(bytes).toBeLessThan(PHONE_ROUTE_BUDGET_BYTES);
    const files = phoneRouteFiles(normal).join(' ');
    expect(files).not.toMatch(/dashboard|lawyers|wasm/);
  });

  it('index.html carries the CSP and has no inline script', () => {
    const html = readFileSync(join(normal, 'index.html'), 'utf8');
    expect(html.replaceAll('&#39;', "'")).toContain(`content="${CSP_META}"`);
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/);
    expect(html).not.toMatch(/\son\w+=/);
  });

  it('service worker never touches /api or /ws and does not precache WASM', () => {
    const sw = readFileSync(join(normal, 'sw.js'), 'utf8');
    expect(sw).toContain('denylist:[/^\\/api(\\/|$)/,/^\\/ws(\\/|$)/]');
    expect(sw).not.toMatch(/\.wasm/);
    expect(sw.match(/registerRoute\(/g)).toHaveLength(1); // only the navigation route: no runtime caching of any request
    const precached = readdirSync(join(normal, 'assets')).filter((f) => f.endsWith('.wasm'));
    expect(precached).toEqual([]);
  });

  it('does not ship or precache the MSW worker', () => {
    expect(readdirSync(normal)).not.toContain('mockServiceWorker.js');
    expect(readFileSync(join(normal, 'sw.js'), 'utf8')).not.toContain('mockServiceWorker');
    for (const file of readdirSync(join(normal, 'assets'))) {
      if (file.endsWith('.js'))
        expect(readFileSync(join(normal, 'assets', file), 'utf8')).not.toMatch(/mockServiceWorker/);
    }
  });

  it('PWA_SELF_DESTROY=1 builds a kill-switch worker with no precache', () => {
    const sw = readFileSync(join(killed, 'sw.js'), 'utf8');
    expect(sw).toMatch(/unregister/);
    expect(sw).not.toMatch(/precacheAndRoute/);
    expect(readdirSync(normal).some((f) => f.startsWith('workbox-'))).toBe(true);
    expect(readdirSync(killed).some((f) => f.startsWith('workbox-'))).toBe(false);
  });
});
