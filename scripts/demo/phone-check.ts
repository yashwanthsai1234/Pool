// `node scripts/demo/phone-check.ts <tunnel-url>` : WebKit at iPhone size opens the party pages through the tunnel and
// checks the secure-context APIs the phones need (crypto.subtle, PublicKeyCredential). Optional: SHOTS=dir saves screenshots.
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ROOT } from './lib.ts';

const base = process.argv[2];
if (!base) throw new Error('usage: phone-check.ts <tunnel-url>');
const pw = await import(
  pathToFileURL(createRequire(resolve(ROOT, 'apps/web/package.json')).resolve('playwright')).href
);
const { webkit, devices } = pw.default ?? pw;
const browser = await webkit.launch();
const ctx = await browser.newContext({ ...devices['iPhone 14'] });
let bad = 0;
for (const role of ['alice', 'bob']) {
  const page = await ctx.newPage();
  const res = await page.goto(`${base}/party/${role}`, { waitUntil: 'networkidle' });
  const api = await page.evaluate(() => ({
    secure: isSecureContext,
    subtle: typeof crypto?.subtle?.digest === 'function',
    webauthn: typeof PublicKeyCredential === 'function',
    body: document.body.innerText.slice(0, 80).replace(/\s+/g, ' '),
  }));
  const ok = res?.ok() && api.secure && api.subtle && api.webauthn;
  if (!ok) bad++;
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'} ${role}: HTTP ${res?.status()} ${JSON.stringify(api)}\n`);
  if (process.env.SHOTS) await page.screenshot({ path: `${process.env.SHOTS}/phone-${role}.png` });
}
await browser.close();
process.exit(bad ? 1 : 0);
