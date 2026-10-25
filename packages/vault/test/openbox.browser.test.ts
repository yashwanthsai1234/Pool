// OD-32: the client's own lawyer opens the `zk-salt` and `zk-disclosure` boxes sealed to its vault X-Wing key. The frame
// opens them (the key never leaves) and hands the page the plaintext, which a lawyer console is entitled to hold; only the
// lawyer of that side, and only for the box kind and side it names.
import { sealDisclosure, sealSalt } from '@legx/core/zkIdentity';
import { describe, expect, it } from 'vitest';
import { vaultFrameHost } from '../src/frame-host.ts';
import { connectVault, serveVault } from '../src/protocol.ts';
import type { PartyRole } from '../src/rules.ts';
import { createVault } from '../src/vault.ts';
import { dealId, freshDb } from './helpers.ts';

async function frame(role: PartyRole) {
  const id = dealId();
  const dbName = freshDb();
  const { port1, port2 } = new MessageChannel();
  serveVault(
    port2,
    createVault({ role, dbName, deals: () => Promise.reject(new Error('no seal')) }),
    vaultFrameHost({ role, dbName }),
  );
  const app = connectVault(port1);
  return { id, app, pub: await app.enroll(id, 'pair-L') };
}

const facts = { firstname: 'Ada', lastname: 'Lovelace', birthdate: '1815-12-10', nationality: 'GBR' };

describe('openBox in the vault frame', () => {
  it('opens the salt and the disclosure sealed to the lawyer of that side', async () => {
    const f = await frame('lawyerA');
    const salt = crypto.getRandomValues(new Uint8Array(32));
    expect(await f.app.openBox(f.id, 'zk-salt', 'A', await sealSalt(salt, f.pub.xwing, f.id, 'A'))).toEqual(salt);
    const box = await sealDisclosure(facts, f.pub.xwing, f.id, 'A');
    const plain = await f.app.openBox(f.id, 'zk-disclosure', 'A', box);
    expect(JSON.parse(new TextDecoder().decode(plain))).toEqual(facts);
  });

  it('refuses the other side, a client role, another kind, and a box for another deal', async () => {
    const f = await frame('lawyerA');
    const box = await sealSalt(new Uint8Array(32), f.pub.xwing, f.id, 'A');
    await expect(f.app.openBox(f.id, 'zk-salt', 'B', box)).rejects.toMatchObject({ code: 'ROLE_REFUSED' });
    await expect(f.app.openBox(f.id, 'zk-disclosure', 'A', box)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
    const other = await sealSalt(new Uint8Array(32), f.pub.xwing, dealId(), 'A');
    await expect(f.app.openBox(f.id, 'zk-salt', 'A', other)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
    const client = await frame('alice');
    const mine = await sealSalt(new Uint8Array(32), client.pub.xwing, client.id, 'A');
    await expect(client.app.openBox(client.id, 'zk-salt', 'A', mine)).rejects.toMatchObject({ code: 'ROLE_REFUSED' });
  });

  it('lawyer B opens only side B', async () => {
    const f = await frame('lawyerB');
    const box = await sealSalt(new Uint8Array(32).fill(3), f.pub.xwing, f.id, 'B');
    expect(await f.app.openBox(f.id, 'zk-salt', 'B', box)).toEqual(new Uint8Array(32).fill(3));
    await expect(f.app.openBox(f.id, 'zk-salt', 'A', box)).rejects.toMatchObject({ code: 'ROLE_REFUSED' });
  });
});
