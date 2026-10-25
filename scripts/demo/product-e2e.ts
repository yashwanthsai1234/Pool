// `pnpm demo:product [web-url]`: end-to-end product demo test (build/PRODUCT_DEMO.md). Playwright: Chromium laptop, WebKit
// iPhone phones. Registers Alice and Bob, creates a deal on /deals, approves every stage from the right /me page, checks the
// /present dots live, then checks the Released tab metadata. Screenshots go to demo/product-e2e/. Needs the stack and the web app.
// Source: https://playwright.dev/docs/api/class-page
import { mkdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ROOT } from './lib.ts';

const base = process.argv[2] ?? `http://127.0.0.1:${process.env.WEB_PORT ?? 5173}`;
const out = resolve(ROOT, 'demo/product-e2e');
mkdirSync(out, { recursive: true });
const pw = await import(
  pathToFileURL(createRequire(resolve(ROOT, 'apps/web/package.json')).resolve('playwright')).href
);
const { chromium, webkit, devices } = pw.default ?? pw;

type Stage = { n: number; name: string; actor: string; status: string };
let step = 'start';
const results: string[] = [];
const softFails = new Set<string>();
const ok = (m: string) => {
  results.push(`PASS ${m}`);
  process.stdout.write(`PASS ${m}\n`);
};
const need = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(msg);
};

// A tiny valid one-page PDF.
const pdf = Buffer.from(
  '%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n' +
    '3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 100]>>endobj\ntrailer<</Root 1 0 R/Size 4>>\n%%EOF\n',
);

const chrome = await chromium.launch();
const safari = await webkit.launch();
try {
  const laptop = await (await chrome.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  const ph = devices['iPhone 14'];
  const alice = await (await safari.newContext(ph)).newPage();
  const bob = await (await safari.newContext(ph)).newPage();
  const shot = (p: typeof laptop, name: string) => p.screenshot({ path: `${out}/${name}.png`, fullPage: true });

  step = '1 register';
  const stamp = Date.now().toString(36).slice(-4);
  const names = { alice: `Alice${stamp}`, bob: `Bob${stamp}` };
  const rids: Record<string, string> = {};
  for (const [who, page] of [
    ['alice', alice],
    ['bob', bob],
  ] as const) {
    await page.goto(`${base}/register`, { waitUntil: 'networkidle' });
    await page.getByLabel('Your name').fill(names[who]);
    await shot(page, `01-register-${who}-empty`);
    await page.getByRole('button', { name: 'Register' }).click();
    // Register goes straight to My deals (UX principle 6), so the RID comes from the greeting chip.
    await page.waitForURL(/\/me$/, { timeout: 60_000 });
    await page.getByText(/rid_[a-z2-7]+/).first().waitFor({ timeout: 60_000 });
    rids[who] = (await page.evaluate(() => localStorage.getItem('legx.demo.rid'))) ?? '';
    need(rids[who], `no RID saved for ${who}`);
    await shot(page, `01-register-${who}`);
  }
  ok(`register Alice ${rids.alice}, Bob ${rids.bob}`);

  const present = await (await chrome.newContext({ viewport: { width: 1920, height: 1080 } })).newPage();
  for (const k of [1, 2, 3]) {
  const amount = 24 + k;
  step = `2 create deal ${k}`;
  const known = new Set(((await (await fetch(`${base}/api/demo/deals`)).json()) as { id: string }[]).map((d) => d.id));
  await laptop.goto(`${base}/deals`, { waitUntil: 'networkidle' });
  const form = laptop.getByRole('form', { name: 'Create deal' });
  await form.getByLabel(/Sender/).selectOption({ value: rids.alice });
  await form.getByLabel(/Recipient/).selectOption({ value: rids.bob });
  await form.getByLabel(/Amount/).fill(String(amount));
  await form.getByLabel('Terms').fill('Deliver 100 units of widgets within 30 days');
  await form.getByLabel('Contract PDF').setInputFiles({ name: 'contract.pdf', mimeType: 'application/pdf', buffer: pdf });
  await shot(laptop, `02-create-form-${k}`);
  await form.getByRole('button', { name: 'Create deal' }).click();
  // Creating a deal goes straight to its detail page (UX principle 6); then check the list row too.
  await laptop.getByRole('article', { name: 'Deal detail' }).waitFor({ timeout: 120_000 });
  await shot(laptop, `02b-new-deal-detail-${k}`);
  await laptop.goto(`${base}/deals`, { waitUntil: 'networkidle' });
  const row = laptop.getByRole('button', { name: new RegExp(`${names.alice} to ${names.bob} · ${amount} XRP`) });
  await row.waitFor({ timeout: 30_000 });
  await shot(laptop, `03-locked-list-${k}`);
  const deals = (await (await fetch(`${base}/api/demo/deals`)).json()) as { id: string }[];
  const id = deals.find((d) => !known.has(d.id))?.id ?? '';
  need(id, 'created deal not returned by GET /demo/deals');
  ok(`create deal ${id}`);

  await present.goto(`${base}/present/${id}`, { waitUntil: 'networkidle' });
  const dots = present.getByRole('list', { name: 'Deal progress' }).locator('li');
  const green = () => present.locator('[aria-label="Deal progress"] li[data-status="done"]').count();
  const getStages = async () =>
    ((await (await fetch(`${base}/api/demo/deals/${id}`)).json()) as { stages: Stage[] }).stages;
  need((await dots.count()) === 14, `expected 14 dots, got ${await dots.count()}`);

  step = '3 approve every stage';
  const phone = { sender: alice, recipient: bob } as const;
  let guard = 0;
  while (guard++ < 40) {
    const stages = await getStages();
    const next = stages.find((s) => s.status === 'pending');
    if (!next) break;
    if (next.actor === 'auto') {
      await new Promise((r) => setTimeout(r, 1000));
      continue;
    }
    step = `3 stage ${next.n} ${next.name} (${next.actor})`;
    const page = phone[next.actor as 'sender' | 'recipient'];
    await page.goto(`${base}/me`, { waitUntil: 'networkidle' });
    const btn = page.locator('.fixed.bottom-0 button').first();
    await btn.waitFor({ timeout: 30_000 });
    await btn.click();
    const doneBefore = stages.filter((s) => s.status === 'done').length;
    // /present dots must turn green live, with no reload. A miss is recorded and the page reloaded so the run goes on.
    const live = await present
      .waitForFunction(
        (n: number) => document.querySelectorAll('[aria-label="Deal progress"] li[data-status="done"]').length > n,
        doneBefore,
        { timeout: 20_000 },
      )
      .then(() => true)
      .catch(() => false);
    if (!live) {
      softFails.add(`/present dots did not turn green without a reload (after stage ${next.n})`);
      await present.reload({ waitUntil: 'networkidle' });
    }
    await shot(page, `04-d${k}-stage-${String(next.n).padStart(2, '0')}-${next.actor}-phone`);
    await shot(present, `05-d${k}-present-after-stage-${String(next.n).padStart(2, '0')}`);
  }
  step = '3 all stages';
  const final = await getStages();
  need(final.every((s) => s.status === 'done'), `stages not all done: ${final.map((s) => `${s.n}:${s.status}`).join(' ')}`);
  ok('approve every stage from the right /me page');

  step = '4 present dots live';
  await present.reload({ waitUntil: 'networkidle' });
  await present.waitForFunction(() => document.querySelectorAll('[aria-label="Deal progress"] li[data-status="done"]').length === 14, undefined, { timeout: 60_000 });
  need((await green()) === 14, 'not all 14 dots green on /present');
  await shot(present, `06-d${k}-present-all-green`);
  ok('/present shows 14/14 green after reload');

  step = `5 released tab ${k}`;
  await laptop.goto(`${base}/deals`, { waitUntil: 'networkidle' });
  await laptop.getByRole('tab', { name: /Released escrows/ }).click();
  await laptop.getByRole('button', { name: new RegExp(`${names.alice} to ${names.bob} · ${amount} XRP`) }).click();
  const detail = laptop.getByRole('article', { name: 'Deal detail' });
  await detail.waitFor({ timeout: 30_000 });
  const text = (await detail.innerText()) + (await detail.locator('pre').textContent({ timeout: 5000 }).catch(() => ''));
  const d = (await (await fetch(`${base}/api/demo/deals/${id}`)).json()) as any;
  const missing: string[] = [];
  const has = (label: string, v: unknown) => {
    if (!v || !String(text).includes(String(v))) missing.push(`${label}=${v}`);
  };
  has('sender name', names.alice);
  has('recipient name', names.bob);
  has('sender rid', rids.alice);
  has('recipient rid', rids.bob);
  has('nft id', d.contract.nftId);
  has('nft owner', d.contract.nftOwner);
  has('mint tx', d.contract.mintTx);
  has('fund tx', d.escrow.fundTx);
  has('release tx', d.escrow.releaseTx);
  has('close tx', d.escrow.closeTx);
  need(d.releasedBy?.length === 2, `releasedBy has ${d.releasedBy?.length} entries`);
  for (const r of d.releasedBy ?? []) has(`signature fingerprint ${r.name}`, r.signatureFingerprint);
  need(d.contract.nftOwner === d.escrow.walletAddress, `NFT owner ${d.contract.nftOwner} is not the deal wallet ${d.escrow.walletAddress}`);
  await shot(laptop, `07-d${k}-released-detail`);
  const href = await detail.getByRole('link', { name: /PDF/ }).first().getAttribute('href');
  const pr = await fetch(new URL(href ?? '', base));
  need(pr.ok && (pr.headers.get('content-type') ?? '').includes('pdf'), `PDF link ${href} -> ${pr.status}`);
  ok(`deal ${k}: PDF link opens`);
  need(missing.length === 0, `released detail lacks: ${missing.join(', ')}`);
  ok('Released tab shows names, RIDs, fingerprints, NFT owner, tx hashes');
  }
  need(softFails.size === 0, `live: ${[...softFails][0]} (+${softFails.size - 1} more)`);
  ok('/present dots turned green live');
} catch (e) {
  const msg = `FAIL at step "${step}": ${(e as Error).message.split('\n')[0]}`;
  process.stdout.write(`${msg}\n`);
  writeFileSync(resolve(out, 'result.txt'), `${results.join('\n')}\n${msg}\n`);
  await chrome.close();
  await safari.close();
  process.exit(1);
}
writeFileSync(resolve(out, 'result.txt'), `${results.join('\n')}\n`);
await chrome.close();
await safari.close();
