// `pnpm demo:rehearse [web-url]` : Playwright (Chromium, laptop and iPhone sizes) captures one screenshot per demo scene
// into demo/rehearsal/. A human records the backup video from this rehearsal (docs/DEMO.md). Needs the web app running
// (`pnpm dev` plus `vite` in apps/web, or `pnpm demo:phones`); default URL http://127.0.0.1:$WEB_PORT (5173).
import { mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ROOT } from './lib.ts';

const base = process.argv[2] ?? `http://127.0.0.1:${process.env.WEB_PORT ?? 5173}`;
const out = resolve(ROOT, 'demo/rehearsal');
mkdirSync(out, { recursive: true });
const pw = await import(
  pathToFileURL(createRequire(resolve(ROOT, 'apps/web/package.json')).resolve('playwright')).href
);
const { chromium, devices } = pw.default ?? pw;
const scenes = [
  { name: '1-dashboard-projector', path: '/dashboard', phone: false },
  { name: '2-lawyers-console', path: '/lawyers', phone: false },
  { name: '3-alice-phone', path: '/party/alice', phone: true },
  { name: '4-bob-phone', path: '/party/bob', phone: true },
];
const browser = await chromium.launch();
for (const s of scenes) {
  const ctx = await browser.newContext(s.phone ? devices['iPhone 14'] : { viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const res = await page.goto(base + s.path, { waitUntil: 'networkidle' });
  if (!res?.ok()) throw new Error(`${s.path}: HTTP ${res?.status()}`);
  await page.screenshot({ path: `${out}/${s.name}.png`, fullPage: true });
  process.stdout.write(`captured ${s.name}\n`);
  await ctx.close();
}
await browser.close();
