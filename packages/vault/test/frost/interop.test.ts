// A/B against task 3.9 (Node): the browser wire format must give the same signed bytes as the coordinator's schema for
// every kind and pass its strict decoder, and the browser holder must run a DKG, a signature, a refresh and a repair
// with 3.9's own holder (the recovery agent's code) in the same session.
import {
  bytesToSign as coordBytesToSign,
  decodeSigned as coordDecode,
  signedBytes,
} from '@legx/coordinator/frost/schema';
import { type KeyShare, slotPubkey, verifyEd25519Strict } from '@legx/core/frost';
import { testSignCheck, testSignMessage } from '@legx/core/frostDkg';
import { xwingShareCipher as agentCipher } from '@legx/recovery-agent/cipher';
import { FrostHolder as AgentHolder } from '@legx/recovery-agent/holder';
import { equalBytes } from '@noble/curves/utils.js';
import { describe, expect, it } from 'vitest';
import { xwingShareCipher } from '../../src/frost/cipher.ts';
import { FrostHolder } from '../../src/frost/holder.ts';
import { keyDirectory } from '../../src/frost/pinning.ts';
import { bytesToSign, type RelayMessage } from '../../src/frost/wire.ts';
import { clientSlot, type MemoryRelay, type Party } from './world.ts';

const DEAL = '0192f3a0-0000-7000-8000-000000000002';

function browserHolder(w: ReturnType<typeof clientSlot>, p: Party, index: number) {
  return new FrostHolder({
    index,
    keys: p.keys,
    dealId: DEAL,
    slot: 'A',
    holders: w.holders,
    relay: w.relay,
    cipher: xwingShareCipher,
    pinned: keyDirectory(w.holders),
    timeoutMs: 20_000,
  });
}

function agentHolder(w: ReturnType<typeof clientSlot>, relay: MemoryRelay) {
  return new AgentHolder({
    index: 3,
    keys: { keyId: w.agent.info.keyId, edSecret: w.agent.edSecret, pqSecret: w.agent.pqSecret },
    dealId: DEAL,
    slot: 'A',
    holders: w.holders.map((h) => ({ ...h })),
    relay: relay as never,
    cipher: agentCipher,
    pinned: keyDirectory(w.holders),
    timeoutMs: 20_000,
  });
}

describe('wire and holder interop with task 3.9', () => {
  it('a DKG, a 1+3 signature, a refresh and a repair with the agent running 3.9 code', {
    timeout: 120_000,
  }, async () => {
    const w = clientSlot();
    const phone = browserHolder(w, w.phone, 1);
    const second = browserHolder(w, w.second, 2);
    const agent = agentHolder(w, w.relay);
    const dkg = await w.relay.openSession({ purpose: 'dkg', holders: w.holders });
    const [p, s, a] = await Promise.all([phone.dkg(dkg), second.dkg(dkg), agent.dkg(dkg)]);
    expect(equalBytes(p.key.public.commitments[0] as Uint8Array, a.key.public.commitments[0] as Uint8Array)).toBe(true);

    // every message the browser sent passes 3.9's strict decoder and has the same signed bytes
    for (const signed of w.relay.log) {
      const d = coordDecode(signed);
      const json = JSON.parse(new TextDecoder().decode(d.payload)) as RelayMessage;
      expect(equalBytes(signedBytes(d), bytesToSign(json, d.payload))).toBe(true);
      expect(equalBytes(coordBytesToSign(d.message, d.payload), bytesToSign(json, d.payload))).toBe(true);
    }

    // a 1+3 test signature: browser aggregator, 3.9 follower
    const pub = p.key.public;
    const pair = [1, 3] as const;
    const msg = testSignMessage(p.ctx, pub, pair);
    const sid = await w.relay.openSession({
      purpose: 'sign',
      holders: w.holders,
      pair: [w.phone.info.identifier, w.agent.info.identifier],
    });
    const [sig] = await Promise.all([
      phone.sign(sid, { msg, kind: 'tagged', share: p.key.secret, pub, check: testSignCheck(p.ctx, pub, 1), pair }),
      agent.sign(sid, { msg, kind: 'tagged', share: a.key.secret, pub, check: testSignCheck(p.ctx, pub, 3), pair }),
    ]);
    expect(verifyEd25519Strict(sig, msg, slotPubkey(pub))).toBe(true);

    // refresh with all three, deletion statements from both implementations
    const rid = await w.relay.openSession({ purpose: 'refresh', holders: w.holders });
    const o = { pub, participants: [1, 2, 3], epoch: 1 };
    const [rp, rs, ra] = await Promise.all([
      phone.refresh(rid, { ...o, share: p.key.secret }),
      second.refresh(rid, { ...o, share: s.key.secret }),
      agent.refresh(rid, { ...o, share: a.key.secret }),
    ]);
    await Promise.all([
      phone.signDeletion(rid, rp.ctx, rp.pub, 1),
      second.signDeletion(rid, rs.ctx, rs.pub, 1),
      agent.signDeletion(rid, ra.ctx, ra.pub, 1),
    ]);
    expect((await phone.refreshStatus(rid, rp.ctx, rp.pub)).status).toBe('COMPLETE');
    expect((await agent.refreshStatus(rid, ra.ctx, ra.pub)).status).toBe('COMPLETE');

    // repair share 1 from the second device (browser) and the agent (3.9)
    const xid = await w.relay.openSession({ purpose: 'repair', holders: w.holders });
    const helpers = [2, 3];
    const [repaired] = await Promise.all([
      phone.repairReceive(xid, { pub: rp.pub, helpers }),
      second.repairHelp(xid, { share: rs.share, pub: rp.pub, helpers, newIndex: 1 }),
      agent.repairHelp(xid, { share: ra.share, pub: rp.pub, helpers, newIndex: 1 }),
    ]);
    expect(equalBytes((repaired as KeyShare).signingShare, rp.share.signingShare)).toBe(true);
  });
});
