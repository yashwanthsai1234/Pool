// I-W-10: the lawyer console's hybrid signer is a frame op. The frame signs DSSE evidence statements of one deal (the
// event and the attestation payload types) under `legx/dsse/v1`, and nothing else: no API request, no relay message, no
// other deal's statement, no free text. Both halves come back together and verify under the registered pair.
import { ATTEST_PAYLOAD_TYPE, PAYLOAD_TYPE, pae } from '@legx/core/evidence';
import { mldsaVerify } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';
import { vaultFrameHost } from '../src/frame-host.ts';
import { connectVault, serveVault } from '../src/protocol.ts';
import { createVault } from '../src/vault.ts';
import { dealId, freshDb } from './helpers.ts';

const enc = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));
const event = (id: string) => enc({ subject: [{ name: `deal:${id}` }], predicate: { deal_id: id, kind: 'ops.bound' } });
const attest = (id: string) => enc({ deal_id: id, side: 'A' });

async function frame() {
  const id = dealId();
  const dbName = freshDb();
  const { port1, port2 } = new MessageChannel();
  serveVault(
    port2,
    createVault({ role: 'lawyerA', dbName, deals: () => Promise.reject(new Error('no seal')) }),
    vaultFrameHost({ role: 'lawyerA', dbName }),
  );
  const app = connectVault(port1);
  const pub = await app.enroll(id, 'pair-9');
  return { id, app, pub };
}

describe('signHybrid in the vault frame', () => {
  it.each([
    ['an event', PAYLOAD_TYPE, event],
    ['an attestation', ATTEST_PAYLOAD_TYPE, attest],
  ])('signs %s of this deal with both halves under the DSSE context', async (_n, type, body) => {
    const f = await frame();
    const msg = pae(type, body(f.id));
    const sig = await f.app.signHybrid(f.id, msg);
    expect(sig.keyIds).toEqual({ ed25519: 'pair-9#ed25519', mlDsa65: 'pair-9#ml-dsa-65' });
    expect(ed25519.verify(sig.ed25519, msg, f.pub.ed25519, { zip215: false })).toBe(true);
    expect(mldsaVerify('ml-dsa-65', f.pub.mlDsa65, msg, sig.mlDsa65, 'legx/dsse/v1' as never)).toBe(true);
    const keys = await f.app.signerKeys(f.id);
    expect(keys.keyIds).toEqual(sig.keyIds);
    expect(keys.ed25519).toEqual(f.pub.ed25519);
    expect(keys.mlDsa65).toEqual(f.pub.mlDsa65);
  });

  it.each([
    ['free text', () => new TextEncoder().encode('pay me')],
    ['another payload type', (id: string) => pae('application/x-evil', event(id))],
    ['an event of another deal', () => pae(PAYLOAD_TYPE, event(dealId()))],
    ['an attestation of another deal', () => pae(ATTEST_PAYLOAD_TYPE, attest(dealId()))],
    ['a body that is not JSON', () => pae(PAYLOAD_TYPE, new TextEncoder().encode('not json'))],
    ['a body shorter than its length', (id: string) => pae(PAYLOAD_TYPE, event(id)).slice(0, -1)],
    ['trailing bytes after the body', (id: string) => new Uint8Array([...pae(PAYLOAD_TYPE, event(id)), 0])],
    ['an API request message', () => new TextEncoder().encode('legx/api-request/v1GET/ws')],
  ])('refuses %s', async (_n, make) => {
    const f = await frame();
    await expect(f.app.signHybrid(f.id, make(f.id))).rejects.toMatchObject({ code: 'MESSAGE_REFUSED' });
  });

  it('refuses a deal with no enrollment key', async () => {
    const f = await frame();
    const other = dealId();
    await expect(f.app.signHybrid(other, pae(PAYLOAD_TYPE, event(other)))).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});
