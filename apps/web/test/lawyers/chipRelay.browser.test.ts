// Task 4.6: the console's side of the relay: opens the session, polls for the phone's sealed bundle.
import { describe, expect, it } from 'vitest';
import { chipRelay } from '../../src/routes/lawyers/-console/chipRelay.ts';

const QR = `legxchip1:${'ab'.repeat(16)}:${'00'.repeat(8)}:AAAA`;

describe('chip relay client', () => {
  it('opens the session named by the QR, then polls until the bundle arrives and decodes it', async () => {
    const calls: string[] = [];
    let polls = 0;
    const fake = (async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? 'GET'} ${url}`);
      if (init?.method === 'PUT') return new Response(null, { status: 204 });
      return ++polls < 3
        ? new Response(null, { status: 204 })
        : Response.json({ sessionId: 'ab'.repeat(16), enc: 'AAEC', ct: 'AwQF' });
    }) as typeof fetch;
    const relay = chipRelay('http://x', fake, 0);
    await relay.open(QR);
    const sealed = await relay.receive(QR);
    expect(calls[0]).toBe(`PUT http://x/chip-link/${'ab'.repeat(16)}`);
    expect([...sealed.enc]).toEqual([0, 1, 2]);
    expect([...sealed.ct]).toEqual([3, 4, 5]);
    expect(polls).toBe(3);
  });
  it('gives up when the session is gone', async () => {
    const relay = chipRelay('http://x', (async () => new Response(null, { status: 404 })) as typeof fetch, 0);
    await expect(relay.receive(QR)).rejects.toThrow('CHIP_RELAY_GONE');
  });
  it('refuses a malformed QR', async () => {
    await expect(chipRelay('http://x', fetch, 0).open('nope')).rejects.toThrow('QR_INVALID');
  });
});
