// P4.9-05: over key creation, signing (relay, API request) and the binding, no seed or expanded secret key leaves the
// device: spies (calling through) on fetch, WebSocket, postMessage, MessagePort, console and the submitted record.
// The public keys and the signatures do go out.
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiRequestSigner } from '../../src/pq/apiRequest.ts';
import { pqBindingSession } from '../../src/pq/binding.ts';
import { pqKeys } from '../../src/pq/keys.ts';
import { containsSecret, rawRows } from '../helpers.ts';
import { bindingWorld, captureSeeds } from './support.ts';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('P4.9-05 spy test', () => {
  it('no seed or secret key in any outbound channel, console or stored row', async () => {
    const seeds = captureSeeds();
    const spies = [
      vi.spyOn(window, 'fetch'),
      vi.spyOn(WebSocket.prototype, 'send'),
      vi.spyOn(window, 'postMessage'),
      vi.spyOn(MessagePort.prototype, 'postMessage'),
      ...(['log', 'info', 'warn', 'error', 'debug'] as const).map((k) => vi.spyOn(console, k)),
    ];
    // Request bodies are read back from the Request objects fetch received.
    const sent = async () => {
      const calls: unknown[] = spies.flatMap((sp) => sp.mock.calls);
      for (const [input, init] of spies[0]?.mock.calls ?? []) calls.push(String(init?.body ?? ''), String(input));
      return calls;
    };

    const w = await bindingWorld();
    const s = pqBindingSession({ slot: 'A', seal: w.seal, pinned: w.pinned, offer: w.offer });
    await s.signWith(w.phone);
    const second = await s.signWith(w.second);
    // The binding and an API request go out through fetch, as the app would send them.
    const record = await s.finish(w.crossSign, async (b) => {
      await fetch('/api/v1/pq-binding', { method: 'POST', body: JSON.stringify(b) });
    });
    const signer = await pqKeys({ role: 'alice', dbName: w.phoneDb }).hybridSigner(w.id, 'p');
    const auth = await apiRequestSigner(
      signer.signRaw,
      async () => 7,
    )({ method: 'GET', path: '/', body: new Uint8Array() });
    await fetch('/api/v1/x', { headers: { 'x-legx-auth': JSON.stringify(auth) } });

    // The vault seeds among every 32-byte random draw: those whose public key is a vault key.
    const hex = (b: Uint8Array) => b.join();
    const mlPubs = new Set([w.pinned[0].mlDsa65, w.pinned[1].mlDsa65].map(hex));
    const xwPubs = new Set(w.xwingPubs.map(hex));
    const secrets = seeds.copies.flatMap((seed) => {
      const k = ml_dsa65.keygen(seed);
      if (mlPubs.has(hex(k.publicKey))) return [seed, k.secretKey];
      return xwPubs.has(hex(ml_kem768_x25519.getPublicKey(seed))) ? [seed] : [];
    });
    expect(secrets).toHaveLength(6); // two devices: ML-DSA seed and expanded key, X-Wing seed
    const out = await sent();
    expect(containsSecret(out, secrets)).toBe(false);
    expect(containsSecret(record, secrets)).toBe(false);
    for (const db of [w.phoneDb, w.secondDb]) expect(containsSecret(await rawRows(db), secrets)).toBe(false);
    // What does go out: the signatures (base64 in the record and in the header).
    expect(out.join('\n')).toContain(record.holder_sigs[1].sig);
    expect(record.holder_sigs[1].key_id).toBe(second.keyId);
    expect(JSON.stringify(spies[0]?.mock.calls)).toContain(auth.signatures[1].sig);
  });
});
