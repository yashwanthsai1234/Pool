// OD-31 in the web app: the feed options built from the seeded observer key (a test-only key pair).
import { ApiAuth } from '@legx/contracts/api';
import { describe, expect, it, vi } from 'vitest';
import { observerFeed } from '../src/lib/observer.ts';

const KEY = JSON.stringify({
  keyId: 'observer-test',
  ed25519Pkcs8: '302e020100300506032b6570042204201d018c7cb17ec31df4dd237cbf5811ff2234f7fe550795a82916d2765a13980d',
  mlDsa65Pkcs8:
    '3034020100300b0609608648016503040312042280205020f2be422a5c1b239d8862a176e1c5115baa21d9d96172c8086b7fd31d59b6',
});

describe('observerFeed', () => {
  it('is absent without a key, with a malformed key, and in the production profile', () => {
    expect(observerFeed({})).toBeUndefined();
    expect(observerFeed({ VITE_LEGX_OBSERVER: 'nope' })).toBeUndefined();
    expect(observerFeed({ VITE_LEGX_OBSERVER: JSON.stringify({ keyId: 'a' }) })).toBeUndefined();
    expect(observerFeed({ VITE_LEGX_OBSERVER: KEY, VITE_LEGX_PROFILE: 'production' })).toBeUndefined();
  });

  it('signs GET /ws under the pair key ids with the index from the public XRPL node, then from the newest ledger push', async () => {
    const health = vi.fn(async () => Response.json({ result: { ledger_index: 900, validated: true } }));
    const feed = observerFeed(
      { VITE_LEGX_OBSERVER: KEY, VITE_LEGX_XRPL_RPC: 'https://s.altnet.rippletest.net:51234' },
      health as never,
    );
    const first = ApiAuth.parse(JSON.parse((await feed?.auth()) ?? ''));
    expect(first.ledgerIndex).toBe(900);
    expect(first.signatures.map((s) => s.keyid)).toEqual(['observer-test#ed25519', 'observer-test#ml-dsa-65']);
    feed?.onLedger({ index: 905, hash: 'AB'.repeat(32), close_time: 1 } as never);
    const second = ApiAuth.parse(JSON.parse((await feed?.auth()) ?? ''));
    expect(second.ledgerIndex).toBe(905);
    expect(second.nonce).not.toBe(first.nonce);
    expect(health).toHaveBeenCalledTimes(1);
  });

  it('a node answer without a ledger index, or no node, signs nothing', async () => {
    const rpc = { VITE_LEGX_OBSERVER: KEY, VITE_LEGX_XRPL_RPC: 'https://node.example' };
    await expect(observerFeed(rpc, (async () => Response.json({ result: {} })) as never)?.auth()).rejects.toThrow();
    await expect(observerFeed({ VITE_LEGX_OBSERVER: KEY })?.auth()).rejects.toThrow();
  });
});
