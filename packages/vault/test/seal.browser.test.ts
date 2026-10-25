// OD-36 (a): a production vault frame never trusts a seal it is handed. The seal is pinned in the frame's own metadata at join time;
// the page then hands over the public deal data, and the frame recomputes `dealSeal` and uses the data only if it equals the pin.
// The seal covers every payout, key and contract field the allow-list reads, so a lying page cannot change them.
import { bytesToHex, dealSeal } from '@legx/core/dealcore';
import { describe, expect, it } from 'vitest';
import { makeWorld } from '../../core/test/helpers/gate.ts';
import { vaultFrameHost } from '../src/frame-host.ts';
import { connectVault, serveVault } from '../src/protocol.ts';
import { createVault } from '../src/vault.ts';
import { dealId, freshDb } from './helpers.ts';

async function frame() {
  const w = await makeWorld();
  const data = w.input.deal.data;
  const id = dealId();
  const dbName = freshDb();
  const host = vaultFrameHost({ role: 'lawyerA', dbName });
  const vault = createVault({ role: 'lawyerA', dbName, deals: host.sealedDeal });
  const { port1, port2 } = new MessageChannel();
  serveVault(port2, vault, host);
  return { id, data, app: connectVault(port1), host, seal: bytesToHex(dealSeal(data)) };
}

describe('the frame verifies the seal itself', () => {
  it('has no deal until a seal is pinned and data matching it is loaded', async () => {
    const f = await frame();
    await expect(f.host.sealedDeal(f.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(f.app.loadDeal(f.id, f.data, '25000000')).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await f.app.pinSeal(f.id, f.seal);
    await f.app.loadDeal(f.id, f.data, '25000000');
    const d = await f.host.sealedDeal(f.id);
    expect(bytesToHex(d.dealSeal as Uint8Array)).toBe(f.seal);
    expect(d.walletAddress).toBe(f.data.walletAddress);
    expect(d.exitAmountDrops).toBe('25000000');
    expect(d.payoutB.account).toBe(f.data.payoutB.split(':')[0]);
  });

  it('refuses data whose seal is not the pinned one (any single field changed)', async () => {
    const f = await frame();
    await f.app.pinSeal(f.id, f.seal);
    for (const changed of [
      { ...f.data, payoutB: f.data.payoutA },
      { ...f.data, walletAddress: f.data.lawyerOpsA },
      { ...f.data, contractRoot: '77'.repeat(32) },
    ])
      await expect(f.app.loadDeal(f.id, changed, '25000000')).rejects.toMatchObject({ code: 'MESSAGE_REFUSED' });
    await expect(f.host.sealedDeal(f.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('the pin is set once: a second, different seal is refused', async () => {
    const f = await frame();
    await f.app.pinSeal(f.id, f.seal);
    await f.app.pinSeal(f.id, f.seal);
    await expect(f.app.pinSeal(f.id, '00'.repeat(32))).rejects.toMatchObject({ code: 'INPUT_INVALID' });
  });

  it('refuses malformed data without throwing out of the frame', async () => {
    const f = await frame();
    await f.app.pinSeal(f.id, f.seal);
    await expect(f.app.loadDeal(f.id, { ...f.data, quorum: 3 } as never, '1')).rejects.toBeDefined();
  });
});
