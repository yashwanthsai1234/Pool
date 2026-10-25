// The walkthrough routes exist only in the demo profile (build/WALKTHROUGH.md, like P4.5-04): production has no such
// routes, and a production process handed the demo hook refuses to start. The full walk runs in
// test-int/demo-walkthrough.int.test.ts.
import { afterEach, describe, expect, it } from 'vitest';
import { ProfileViolation } from '../src/config.ts';
import { demoAttacks } from '../src/demo-attacks/index.ts';
import { ATTACKS, type Scenes } from '../src/demo-attacks/types.ts';
import { base32lower, ridOf } from '../src/demo-product/participants.ts';
import { withWalkthrough } from '../src/demo-walkthrough/index.ts';
import { type Composed, compose } from './support/server.ts';

const scenes = Object.fromEntries(
  ATTACKS.map((a) => [a, async () => ({ defeated: true, code: 'x', detail: '' })]),
) as unknown as Scenes;
const hook = () =>
  withWalkthrough(demoAttacks(scenes), {
    env: { LEGX_DEMO_STATE: '/nonexistent' },
    ledgerWs: 'ws://127.0.0.1:1',
    pgUrl: 'postgres://x',
  });

let c: Composed | undefined;
afterEach(async () => {
  await c?.close();
  c = undefined;
});

describe('demo profile', () => {
  it('mounts the walkthrough next to attack mode, without an auth header', async () => {
    c = await compose({ demo: hook() });
    const app = c.server.app;
    expect((await app.inject({ method: 'GET', url: '/demo/attack' })).statusCode).toBe(200);
    const bad = await app.inject({
      method: 'POST',
      url: '/demo/walkthrough',
      payload: { amountXrp: 50, identity: 'x' },
    });
    expect(bad.statusCode).toBe(400);
    const any = await app.inject({
      method: 'POST',
      url: '/demo/walkthrough',
      payload: { amountXrp: 7, identity: 'chip' },
    });
    expect([any.statusCode, any.json().error]).toEqual([409, 'not_seeded']); // any amount: deal.ts takes escrowDrops
    const unseeded = await app.inject({
      method: 'POST',
      url: '/demo/walkthrough',
      payload: { amountXrp: 50, identity: 'zk', delivery: 'physical' },
    });
    expect([unseeded.statusCode, unseeded.json().error]).toEqual([409, 'not_seeded']);
    expect((await app.inject({ method: 'GET', url: '/demo/walkthrough/nope' })).statusCode).toBe(404);
    expect((await app.inject({ method: 'POST', url: '/demo/walkthrough/nope/next' })).statusCode).toBe(404);
    expect((await app.inject({ method: 'GET', url: '/demo/participants' })).json()).toEqual([]);
    expect((await app.inject({ method: 'POST', url: '/demo/participants', payload: { name: '' } })).statusCode).toBe(
      400,
    );
    expect((await app.inject({ method: 'GET', url: '/demo/deals/x' })).statusCode).toBe(404);
  });
});

describe('production profile', () => {
  const prod = { profile: 'production' as const, ports: { ledger: { impl: 'xrpld', demo: false } }, agents: undefined };

  it('does not mount the routes: the guard answers 401 and nothing runs', async () => {
    c = await compose(prod);
    const app = c.server.app;
    expect((await app.inject({ method: 'POST', url: '/demo/walkthrough', payload: {} })).statusCode).toBe(401);
    expect((await app.inject({ method: 'GET', url: '/demo/walkthrough/x' })).statusCode).toBe(401);
    expect((await app.inject({ method: 'POST', url: '/demo/walkthrough/x/next' })).statusCode).toBe(401);
    // nor the product demo's (build/PRODUCT_DEMO.md)
    for (const [method, url] of [
      ['POST', '/demo/participants'],
      ['GET', '/demo/participants'],
      ['POST', '/demo/deals'],
      ['GET', '/demo/deals'],
      ['GET', '/demo/deals/x'],
      ['GET', '/demo/deals/x/contract.pdf'],
      ['POST', '/demo/deals/x/approve'],
    ] as const)
      expect((await app.inject({ method, url })).statusCode, url).toBe(401);
  });

  it('refuses to start when handed the walkthrough hook (P3.7-05)', async () => {
    await expect(compose({ ...prod, demo: hook() })).rejects.toBeInstanceOf(ProfileViolation);
  });
});

describe('product demo RIDs', () => {
  it('base32lower is RFC 4648 lower case without padding', () => {
    // Source: https://www.rfc-editor.org/rfc/rfc4648#section-10
    expect(base32lower(Buffer.from('foobar'))).toBe('mzxw6ytboi');
    expect(base32lower(Buffer.from('f'))).toBe('my');
  });
  it('a RID fingerprints both keys', () => {
    const a = ridOf(new Uint8Array(32), new Uint8Array(1952));
    expect(a.rid).toMatch(/^rid_[a-z2-7]{16}$/);
    expect(ridOf(new Uint8Array(32).fill(1), new Uint8Array(1952)).rid).not.toBe(a.rid);
    expect(ridOf(new Uint8Array(32), new Uint8Array(1952).fill(1)).rid).not.toBe(a.rid);
  });
});
