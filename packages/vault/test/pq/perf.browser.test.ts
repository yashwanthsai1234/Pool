// P4.9-07: key generation plus binding on a mid-range phone profile. Chromium runs with a 4x CPU throttle through CDP
// (Emulation.setCPUThrottlingRate); WebKit has no CDP and runs unthrottled as a reference. Budget: under 1.5 s for
// the phone's work (its keygen, its ML-DSA signature, the slot cross-signature and the full check), with progress
// states shown. The second holder's signature comes from its own device and is not timed. A real Android is manual.
// Source: https://chromedevtools.github.io/devtools-protocol/tot/Emulation/#method-setCPUThrottlingRate
import { pqBindMsg } from '@legx/core/pq';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { cdp, server } from 'vitest/browser';
import { pqBindingSession } from '../../src/pq/binding.ts';
import { pqKeys } from '../../src/pq/keys.ts';
import { dealId, freshDb } from '../helpers.ts';
import { bindingWorld } from './support.ts';

const throttled = server.browser === 'chromium';
/** Time of a fixed CPU-bound loop (best of 9), to measure the slowdown the throttle really gives. */
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

describe(`P4.9-07 speed (${throttled ? '4x CPU throttle' : 'no throttle'})`, () => {
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

  it('keygen plus binding under 1.5 s, with progress states', { timeout: 120_000 }, async () => {
    const times: number[] = [];
    for (let run = 0; run < 3; run++) {
      const w = await bindingWorld();
      const msg = pqBindMsg(w.seal.dealSeal, w.seal.slotPub, w.seal.pqKeyHash);
      const secondSig = { keyId: w.pinned[1].keyId, sig: await w.second.sign(msg, 'legx/pq-binding/v1') };
      const steps: string[] = [];
      const t0 = performance.now();
      // Keygen on this device (a fresh deal id, same work as the phone's enrollment).
      await pqKeys({ role: 'alice', dbName: freshDb() }).create(dealId());
      const s = pqBindingSession({
        slot: 'A',
        seal: w.seal,
        pinned: w.pinned,
        offer: w.offer,
        onProgress: (p) => steps.push(p),
      });
      await s.signWith(w.phone);
      s.add(secondSig);
      await s.finish(w.crossSign, async () => {});
      times.push(performance.now() - t0);
      expect(steps).toEqual(['signing', 'cross-signing', 'verifying', 'submitting']);
    }
    // Recorded in build/status/4.9.md.
    console.info(
      `P4.9-07 ${server.browser} slowdown ${slowdown.toFixed(1)}x runs ${times.map(Math.round).join(', ')} ms`,
    );
    if (throttled) expect(slowdown).toBeGreaterThan(1.5);
    expect(Math.min(...times)).toBeLessThan(1500);
  });
});
