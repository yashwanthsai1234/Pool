// P4.7-11: signing speed on a mid-range phone profile. Chromium with a 4x CPU throttle through CDP
// (Emulation.setCPUThrottlingRate); WebKit has no CDP, so it runs unthrottled as a reference. The budgets: a two-share
// signature under 1 s, the DKG under 5 s of device time. Here all three holders of the DKG run in this one page, so the
// DKG time is an upper bound for one device's time. The real mid-range Android run is a manual test.
// Source: https://chromedevtools.github.io/devtools-protocol/tot/Emulation/#method-setCPUThrottlingRate
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { cdp, server } from 'vitest/browser';
import { openerSessions, runSlotDkg } from '../../src/frost/dkg.ts';
import { keyDirectory } from '../../src/frost/pinning.ts';
import { createVault } from '../../src/vault.ts';
import { binding, dealId, fakePrf, freshDb, sealedDeal } from '../helpers.ts';
import { MemoryRelay, party } from './world.ts';

const throttled = server.browser === 'chromium';
const best = (xs: number[]) => Math.min(...xs);
/** Time of a fixed CPU-bound loop (the best of 9, so other test files running at once matter less). */
function busy(): number {
  const times: number[] = [];
  for (let r = 0; r < 9; r++) {
    const t = performance.now();
    let x = 0;
    for (let i = 0; i < 3_000_000; i++) x = (x + i * i) % 1_000_003;
    if (x < 0) throw new Error('unreachable');
    times.push(performance.now() - t);
  }
  return Math.min(...times);
}

describe(`P4.7-11 speed (${throttled ? '4x CPU throttle' : 'no throttle'})`, () => {
  let slowdown = 1;
  beforeAll(async () => {
    if (!throttled) return;
    const before = busy();
    await cdp().send('Emulation.setCPUThrottlingRate', { rate: 4 });
    slowdown = busy() / before;
  });
  afterAll(async () => {
    if (throttled) await cdp().send('Emulation.setCPUThrottlingRate', { rate: 1 });
  });

  it('DKG under 5 s and a two-share signature under 1 s', { timeout: 120_000 }, async () => {
    const dkgTimes: number[] = [];
    const signTimes: number[] = [];
    for (let run = 0; run < 3; run++) {
      const id = dealId();
      const relay = new MemoryRelay();
      const phone = party(1, 'phone', 'Your phone');
      const key = party(2, 'second-authenticator', 'Your security key');
      const agent = party(3, 'recovery-agent', 'Recovery agent');
      const holders = [phone.info, key.info, agent.info];
      relay.pin(...holders);
      const base = {
        dealId: id,
        slot: 'A' as const,
        holders,
        relay,
        pinned: keyDirectory(holders),
        timeoutMs: 60_000,
        pollMs: 2,
      };
      const t0 = performance.now();
      const [p] = await Promise.all([
        runSlotDkg({
          ...base,
          sessions: openerSessions(relay, holders),
          local: [
            { index: 1, keys: phone.keys },
            { index: 2, keys: key.keys },
          ],
        }),
        runSlotDkg({ ...base, sessions: relay.joiner(), local: [{ index: 3, keys: agent.keys }] }),
      ]);
      dkgTimes.push(performance.now() - t0);
      if (!p.ready) throw new Error('DKG');
      const prf = fakePrf();
      const deal = sealedDeal(p.pub, 'A');
      const vault = createVault({ role: 'alice', dbName: freshDb(), deals: async () => deal, prf: prf.source });
      const credential = (await prf.source.register('security-key', { id: new Uint8Array(16), name: 'a' })).credential;
      await vault.storeShares({
        dealId: id,
        pub: p.pub,
        share1: p.shares.get(1) as never,
        share2: { mode: 'security-key', credential, share: p.shares.get(2) as never },
      });
      const t1 = performance.now();
      await vault.signFrost(id, binding(deal, 'A'));
      signTimes.push(performance.now() - t1);
    }
    // the numbers go in build/status/4.7.md
    console.info(
      `P4.7-11 ${server.browser} (measured slowdown ${slowdown.toFixed(1)}x): DKG ${dkgTimes.map(Math.round).join(', ')} ms; sign ${signTimes.map(Math.round).join(', ')} ms`,
    );
    // the throttle reaches this frame: about 4x alone, about 2x while other test files share the CPU (1.0x unthrottled)
    if (throttled) expect(slowdown).toBeGreaterThan(1.5);
    expect(best(signTimes)).toBeLessThan(1_000);
    expect(best(dkgTimes)).toBeLessThan(5_000);
  });
});
