// P4.5-04 (server side) and P3.7-05: attack routes exist only in the demo profile, and a production process that is
// handed the demo hook refuses to start. The scenes here are stubs; the real ones run in test-int/demo-attacks.int.test.ts.
import { afterEach, describe, expect, it } from 'vitest';
import { ProfileViolation } from '../src/config.ts';
import { demoAttacks } from '../src/demo-attacks/index.ts';
import { ATTACKS, type SceneOutcome, type Scenes } from '../src/demo-attacks/types.ts';
import { type Composed, compose } from './support/server.ts';

const outcome: SceneOutcome = { defeated: true, code: 'tecNO_PERMISSION', detail: 'stub', txHash: 'AB'.repeat(32) };
const stubs = (over: Partial<Record<(typeof ATTACKS)[number], () => Promise<SceneOutcome>>> = {}): Scenes =>
  Object.fromEntries(ATTACKS.map((a) => [a, over[a] ?? (async () => outcome)])) as unknown as Scenes;

let c: Composed | undefined;
afterEach(async () => {
  await c?.close();
  c = undefined;
});

describe('demo profile', () => {
  it('lists the nine attacks and runs one without an auth header', async () => {
    c = await compose({ demo: demoAttacks(stubs()) });
    const list = await c.server.app.inject({ method: 'GET', url: '/demo/attack' });
    expect(list.statusCode).toBe(200);
    expect(list.json().attacks).toEqual([...ATTACKS]);
    for (const a of ATTACKS) {
      const r = await c.server.app.inject({ method: 'POST', url: `/demo/attack/${a}` });
      expect(r.statusCode, a).toBe(200);
      expect(r.json()).toEqual({ attack: a, ...outcome });
    }
  });

  it('an unknown attack is 404 and a failing scene is 500 without internals in the status', async () => {
    c = await compose({
      demo: demoAttacks(
        stubs({
          'double-exit': async () => {
            throw new Error('ledger down');
          },
        }),
      ),
    });
    expect((await c.server.app.inject({ method: 'POST', url: '/demo/attack/nope' })).statusCode).toBe(404);
    const r = await c.server.app.inject({ method: 'POST', url: '/demo/attack/double-exit' });
    expect(r.statusCode).toBe(500);
    expect(r.json().error).toBe('scene_failed');
  });

  it('scenes run one at a time, in request order', async () => {
    const log: string[] = [];
    const slow = (name: string, ms: number) => async () => {
      log.push(`start ${name}`);
      await new Promise((r) => setTimeout(r, ms));
      log.push(`end ${name}`);
      return outcome;
    };
    c = await compose({
      demo: demoAttacks(stubs({ 'stranger-finish': slow('a', 60), 'master-key-on': slow('b', 1) })),
    });
    await Promise.all([
      c.server.app.inject({ method: 'POST', url: '/demo/attack/stranger-finish' }),
      c.server.app.inject({ method: 'POST', url: '/demo/attack/master-key-on' }),
    ]);
    expect(log).toEqual(['start a', 'end a', 'start b', 'end b']);
  });

  it('only the attack paths skip the auth header guard', async () => {
    c = await compose({ demo: demoAttacks(stubs()) });
    const r = await c.server.app.inject({ method: 'GET', url: '/demo/other' });
    expect(r.statusCode).toBe(401);
  });
});

describe('production profile', () => {
  const prod = { profile: 'production' as const, ports: { ledger: { impl: 'xrpld', demo: false } }, agents: undefined };

  it('has no attack routes: the guard answers 401 and a signed or unsigned POST never runs a scene', async () => {
    c = await compose(prod);
    expect((await c.server.app.inject({ method: 'GET', url: '/demo/attack' })).statusCode).toBe(401);
    expect((await c.server.app.inject({ method: 'POST', url: '/demo/attack/stranger-finish' })).statusCode).toBe(401);
  });

  it('refuses to start when handed the demo hook (P3.7-05)', async () => {
    await expect(compose({ ...prod, demo: demoAttacks(stubs()) })).rejects.toBeInstanceOf(ProfileViolation);
  });
});
